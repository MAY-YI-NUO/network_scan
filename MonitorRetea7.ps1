# =====================================================================
# MONITORIZARE RETEA - VERSIUNE AVANSATA CU IDS
# Network Monitor + Intrusion Detection System
# Compatible: Windows PowerShell 5.1+
# =====================================================================

$ErrorActionPreference = "Continue"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ---- ACCOUNTABILITY / SESSION ----
$currentUser    = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$currentComputer = $env:COMPUTERNAME
$sessionId      = [guid]::NewGuid().ToString()
$sessionIdShort = $sessionId.Substring(0, 8)   # short form for log lines
$scriptStartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# ---- CONFIGURARE ----
$intervalSecunde   = 300
$subnet            = "192.168.0.0/24"
$logDir            = "C:\NetworkMonitor"
$scanMode          = "balanced"  # fast | balanced | aggressive

# Validate subnet format before proceeding
if ($subnet -notmatch '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$') {
    Write-Host "ERROR: Invalid subnet format! Expected format: xxx.xxx.xxx.xxx/xx" -ForegroundColor Red
    exit 1
}

# Nmap with timeout - FIXED: Proper path quoting
$nmapExe = "C:\Program Files (x86)\Nmap\nmap.exe"
if (-not (Test-Path $nmapExe)) { $nmapExe = "C:\Program Files\Nmap\nmap.exe" }
if (-not (Test-Path $nmapExe)) {
    Write-Host "ERROR: Nmap not found!" -ForegroundColor Red
    exit 1
}
# Wrap path in quotes for safety
$nmapExeQuoted = "`"$nmapExe`""

# PicoKMS ports
$picokmsPorts = @(3390, 3391, 3392, 3393)

# Critical ports monitored by IDS
$criticalPorts = @(
    @{Port=22;   Name="SSH"},
    @{Port=3389; Name="RDP"},
    @{Port=5900; Name="VNC"},
    @{Port=445;  Name="SMB"},
    @{Port=139;  Name="NetBIOS"},
    @{Port=135;  Name="RPC"}
)

# Excluded devices (printers, Xerox, etc.) - not flagged by IDS
$excludedMACs = @()
$excludedMACsNormalized = $excludedMACs | ForEach-Object { $_.Replace("-","").Replace(":","").ToUpper() }

# ---- IDS CONFIGURATION ----
$maxReconnectsInWindow  = 3    # how many reconnects in window before alert
$reconnectWindowSeconds = 300  # window in seconds (5 min)
$maxIPsPerMAC           = 2    # how many IPs a MAC can have before flagging
$threatThresholds       = @{ Low=3; Medium=6; High=10 }

# Alert rate limiting (prevent flooding)
$alertRateLimitSeconds = 60  # minimum seconds between same alert type for same IP
$lastAlertTime = @{}   # Track last alert per IP:alertType

# Hostnames that look like penetration testing tools
$suspiciousPatterns = @("kali","metasploit","parrot","pentbox","nessus","openvas","backtrack","hacker","pwn")

# DNS Cache with TTL (5 minutes)
$dnsCache = @{}
$dnsCacheTTL = 300  # seconds

# MAC Cache with TTL (10 minutes)
$macCacheWithTTL = @{}
$macCacheTTL = 600  # seconds

# File lock mutex - FIXED: Removed Global\ prefix to avoid admin requirements
$fileLock = New-Object System.Threading.Mutex($false, "NetworkMonitorFileLock")

# ---- LOG FILES ----
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

$logFile          = "$logDir\host_status.log"
$csvFile          = "$logDir\host_status.csv"
$statsFile        = "$logDir\host_statistics.csv"
$statusFile       = "$logDir\last_status.txt"
$alertFile        = "$logDir\alerts.log"
$criticalPortsLog = "$logDir\critical_ports.log"
$errorLog         = "$logDir\errors.log"
$ipChangeLog      = "$logDir\ip_changes.log"
$macCacheFile     = "$logDir\mac_cache.csv"
$threatLogFile    = "$logDir\threats.log"
$intrusionLogFile = "$logDir\intrusion.log"
$knownDevicesFile = "$logDir\known_devices.csv"
$executionAuditFile = "$logDir\execution_audit.csv"   # NEVER rotated / deleted

# ---- LOG ROTATION CONFIG ----
$logRotationMaxBytes = 1MB          # rotate when file exceeds this size
# Files subject to rotation (execution_audit.csv is intentionally excluded)
$rotatableFiles = @($logFile, $alertFile, $criticalPortsLog, $errorLog,
                    $ipChangeLog, $threatLogFile, $intrusionLogFile)

# Initialize CSV headers if files don't exist (with file locking)
function Safe-InitializeFile {
    param([string]$Path, [string]$Header)
    if (-not (Test-Path $Path)) {
        $lockAcquired = $fileLock.WaitOne(5000)
        try {
            if ($lockAcquired) {
                Add-Content -Path $Path -Value $Header -Encoding UTF8
            } else {
                Write-Host "WARNING: Could not acquire lock for $Path" -ForegroundColor Yellow
            }
        } finally {
            if ($lockAcquired) { $fileLock.ReleaseMutex() }
        }
    }
}

# FIXED: Changed -Value to -Header parameter
Safe-InitializeFile -Path $csvFile -Header "Timestamp,EventType,IPAddress,Hostname,AdditionalInfo"
Safe-InitializeFile -Path $statsFile -Header "IPAddress,Hostname,TotalConnects,TotalDisconnects,FirstSeen,LastSeen,CurrentStatus,MACAddress,LastKnownHostname,AvgSessionMin"
Safe-InitializeFile -Path $macCacheFile -Header "IPAddress,MACAddress,LastSeen,Hostname"
Safe-InitializeFile -Path $knownDevicesFile -Header "MACAddress,Hostname,FirstSeen,TrustedStatus"
Safe-InitializeFile -Path $executionAuditFile -Header "Timestamp,Username,Computer,SessionID,ScriptPath"

# Write execution audit row — one row per script run, never deleted
$auditRow = "$scriptStartTime,$currentUser,$currentComputer,$sessionId,$($MyInvocation.MyCommand.Path)"
$lockAcquired = $fileLock.WaitOne(5000)
try {
    if ($lockAcquired) { Add-Content -Path $executionAuditFile -Value $auditRow -Encoding UTF8 }
} finally {
    if ($lockAcquired) { $fileLock.ReleaseMutex() }
}

# ---- IN-MEMORY DATA STRUCTURES ----
$stats            = @{}   # IP  -> stats hashtable
$macToHostname    = @{}   # MAC -> hostname
$macToIPHistory   = @{}   # MAC -> [IPs]
$macCache         = @{}   # IP  -> {MAC, LastSeen, Hostname}
$reconnectTracker = @{}   # IP  -> [DateTime stamps]
$threatScore      = @{}   # IP/MAC -> cumulative score
$sessionStart     = @{}   # IP  -> DateTime of last connect
$sessionDurations = @{}   # IP  -> [session minutes]
$knownDevices     = @{}   # MAC -> {Hostname, FirstSeen, TrustedStatus}
$idsAlerts        = [System.Collections.ArrayList]::new()

# ---- LOAD EXISTING DATA ----
if (Test-Path $statsFile) {
    $existingStats = Import-Csv $statsFile -ErrorAction SilentlyContinue
    foreach ($row in $existingStats) {
        $avgMin = 0
        if ($row.PSObject.Properties['AvgSessionMin'] -and $row.AvgSessionMin -ne "") {
            try { $avgMin = [double]$row.AvgSessionMin } catch { }
        }
        $stats[$row.IPAddress] = @{
            Hostname           = $row.Hostname
            TotalConnects      = [int]$row.TotalConnects
            TotalDisconnects   = [int]$row.TotalDisconnects
            FirstSeen          = $row.FirstSeen
            LastSeen           = $row.LastSeen
            CurrentStatus      = $row.CurrentStatus
            MACAddress         = $row.MACAddress
            LastKnownHostname  = $row.LastKnownHostname
            AvgSessionMin      = $avgMin
        }
        if ($row.MACAddress -ne "unknown" -and $row.MACAddress -ne "") {
            if (-not $macToHostname.ContainsKey($row.MACAddress))   { $macToHostname[$row.MACAddress]   = $row.Hostname }
            if (-not $macToIPHistory.ContainsKey($row.MACAddress))  { $macToIPHistory[$row.MACAddress]  = @() }
            $macToIPHistory[$row.MACAddress] += $row.IPAddress
            $macToIPHistory[$row.MACAddress]  = $macToIPHistory[$row.MACAddress] | Select-Object -Unique
        }
    }
}

if (Test-Path $macCacheFile) {
    $existingCache = Import-Csv $macCacheFile -ErrorAction SilentlyContinue
    foreach ($row in $existingCache) {
        $macCache[$row.IPAddress] = @{
            MACAddress = $row.MACAddress
            LastSeen   = $row.LastSeen
            Hostname   = $row.Hostname
        }
    }
}

if (Test-Path $knownDevicesFile) {
    $existingKnown = Import-Csv $knownDevicesFile -ErrorAction SilentlyContinue
    foreach ($row in $existingKnown) {
        $knownDevices[$row.MACAddress] = @{
            Hostname      = $row.Hostname
            FirstSeen     = $row.FirstSeen
            TrustedStatus = $row.TrustedStatus
        }
    }
}

# =====================================================================
# HELPER FUNCTIONS
# =====================================================================

function Get-Timestamp     { Get-Date -Format "yyyy-MM-dd HH:mm:ss" }
function Get-CsvTimestamp  { Get-Date -Format "yyyy-MM-ddTHH:mm:ss" }

function Get-NmapProfile {
    switch ($scanMode) {
        "fast"       { return "-T4 --top-ports 50 --host-timeout 30s" }
        "balanced"   { return "-T3 -sS -sV --host-timeout 60s" }
        "aggressive" { return "-T4 -A --script vuln --host-timeout 120s" }
        default      { return "-T3 --host-timeout 60s" }
    }
}

function Invoke-Nmap {
    param ([string]$Arguments)
    
    $tempOutput = "$logDir\nmap_output_temp.txt"
    
    try {
        $process = Start-Process -FilePath $nmapExe `
            -ArgumentList $Arguments `
            -NoNewWindow `
            -RedirectStandardOutput $tempOutput `
            -RedirectStandardError $errorLog `
            -Wait -PassThru
        
        if ($process.ExitCode -eq 0 -and (Test-Path $tempOutput)) {
            $output = Get-Content $tempOutput -Raw -ErrorAction SilentlyContinue
            Remove-Item $tempOutput -Force -ErrorAction SilentlyContinue
            return $output
        }
        return $null
    } catch {
        Safe-WriteToFile -Path $errorLog -Content "$(Get-Timestamp) | Nmap execution failed: $_"
        return $null
    }
}

function Discover-Hosts {
    Write-Host "[*] Discovering live hosts..." -ForegroundColor Cyan
    
    $output = Invoke-Nmap "-sn $subnet"
    
    if (-not $output) { return @() }
    
    $hosts = @()
    foreach ($line in ($output -split "`n")) {
        if ($line -match "Nmap scan report for (?:.*\()?(\d+\.\d+\.\d+\.\d+)\)?") {
            $hosts += $matches[1]
        } elseif ($line -match "Nmap scan report for (\d+\.\d+\.\d+\.\d+)") {
            $hosts += $matches[1]
        }
    }
    
    return $hosts | Select-Object -Unique
}

function Scan-Services {
    param([string[]]$hosts)
    
    if ($hosts.Count -eq 0) { return $null }
    
    Write-Host "[*] Scanning services on $($hosts.Count) hosts..." -ForegroundColor Cyan
    
    $profile = Get-NmapProfile
    $targets = $hosts -join " "
    return Invoke-Nmap "$profile $targets"
}

function Detect-OS {
    param([string[]]$hosts)
    
    if ($hosts.Count -eq 0) { return $null }
    
    Write-Host "[*] Detecting OS on $($hosts.Count) hosts..." -ForegroundColor Cyan
    
    $targets = $hosts -join " "
    return Invoke-Nmap "-O --host-timeout 90s $targets"
}

function Run-NSEScripts {
    param([string[]]$hosts)
    
    if ($hosts.Count -eq 0) { return $null }
    
    Write-Host "[*] Running NSE vulnerability scripts..." -ForegroundColor Yellow
    
    $targets = $hosts -join " "
    return Invoke-Nmap "--script vuln,safe,default -T4 --host-timeout 180s $targets"
}

function Analyze-Ports {
    param([string]$nmapOutput)
    
    if (-not $nmapOutput) { return }
    
    foreach ($line in ($nmapOutput -split "`n")) {
        if ($line -match "(\d+)/tcp\s+open\s+(\S+)") {
            $port = [int]$matches[1]
            $service = $matches[2]
            
            # Check critical ports
            foreach ($criticalPort in $criticalPorts) {
                if ($criticalPort.Port -eq $port) {
                    $msg = "$(Get-Timestamp) | CRITICAL PORT DETECTED: $port ($service)"
                    Safe-WriteToFile -Path $criticalPortsLog -Content $msg
                    Write-Host $msg -ForegroundColor Red
                    break
                }
            }
            
            # Check weak services
            if ($service -match "telnet|ftp|rpc|vnc") {
                $msg = "$(Get-Timestamp) | WEAK SERVICE DETECTED: $service on port $port"
                Safe-WriteToFile -Path $intrusionLogFile -Content $msg
                Write-Host $msg -ForegroundColor Yellow
            }
        }
    }
}

function Get-HostnameWithCache {
    param([string]$ip)
    
    # Check cache first
    $now = Get-Date
    if ($dnsCache.ContainsKey($ip)) {
        $cacheEntry = $dnsCache[$ip]
        if (($now - $cacheEntry.Timestamp).TotalSeconds -lt $dnsCacheTTL) {
            return $cacheEntry.Hostname
        } else {
            $dnsCache.Remove($ip)
        }
    }
    
    # Cache miss or expired - perform lookup
    try {
        $h = [System.Net.Dns]::GetHostEntry($ip).HostName
        if ($h -eq $ip) { 
            $hostname = "unknown"
        } else {
            $hostname = ($h -split '\.')[0]
        }
        
        $dnsCache[$ip] = @{
            Hostname = $hostname
            Timestamp = $now
        }
        return $hostname
    } catch { 
        return "unknown" 
    }
}

function Get-MacAddressWithCache {
    param([string]$ip)
    
    # Check cache first
    $now = Get-Date
    if ($macCacheWithTTL.ContainsKey($ip)) {
        $cacheEntry = $macCacheWithTTL[$ip]
        if (($now - $cacheEntry.Timestamp).TotalSeconds -lt $macCacheTTL) {
            return $cacheEntry.MACAddress
        } else {
            $macCacheWithTTL.Remove($ip)
        }
    }
    
    # Cache miss or expired - perform lookup
    try {
        $pingProcess = Start-Process -FilePath "ping" -ArgumentList "-n 1 -w 500 $ip" -NoNewWindow -Wait -PassThru
        if ($pingProcess.ExitCode -eq 0) {
            $arpOut = & arp -a 2>$null
            foreach ($line in ($arpOut -split "`r?`n")) {
                if ($line -match "^\s+$([regex]::Escape($ip))\s+([0-9a-fA-F-]{17})") {
                    $mac = $matches[1].ToUpper()
                    $macCacheWithTTL[$ip] = @{
                        MACAddress = $mac
                        Timestamp = $now
                    }
                    return $mac
                }
            }
        }
        return "unknown"
    } catch { 
        return "unknown" 
    }
}

function Is-ExcludedDevice {
    param([string]$mac)
    if ($mac -eq "unknown") { return $false }
    $n = $mac.Replace("-","").Replace(":","").ToUpper()
    return $excludedMACsNormalized -contains $n
}

function Get-ThreatColor {
    param([int]$score)
    if ($score -ge $threatThresholds.High)   { return "Red" }
    if ($score -ge $threatThresholds.Medium) { return "Yellow" }
    if ($score -gt 0)                        { return "DarkYellow" }
    return "Green"
}

function Get-ThreatLabel {
    param([int]$score)
    if ($score -ge $threatThresholds.High)   { return "HIGH  " }
    if ($score -ge $threatThresholds.Medium) { return "MEDIUM" }
    if ($score -gt 0)                        { return "LOW   " }
    return "CLEAN "
}

function Get-UptimePct {
    param([string]$ip)
    if (-not $stats.ContainsKey($ip)) { return 0 }
    $s     = $stats[$ip]
    $total = $s.TotalConnects + $s.TotalDisconnects
    if ($total -eq 0) { return 0 }
    return [math]::Round(($s.TotalConnects / $total) * 100, 0)
}

function Is-AlertRateLimited {
    param([string]$ip, [string]$alertType)
    $key = "$ip`:$alertType"
    $now = Get-Date
    
    if ($lastAlertTime.ContainsKey($key)) {
        $timeDiff = ($now - $lastAlertTime[$key]).TotalSeconds
        if ($timeDiff -lt $alertRateLimitSeconds) {
            return $true
        }
    }
    
    $lastAlertTime[$key] = $now
    return $false
}

# =====================================================================
# LOG ROTATION
# =====================================================================

function Invoke-LogRotation {
    param([string]$Path)

    # Only rotate files in the approved list; never rotate CSVs or the audit file
    if ($rotatableFiles -notcontains $Path) { return }
    if (-not (Test-Path $Path))             { return }

    try {
        $size = (Get-Item $Path).Length
        if ($size -lt $logRotationMaxBytes)  { return }

        # Rename the old file: append timestamp so nothing is lost
        $stamp   = Get-Date -Format "yyyyMMdd_HHmmss"
        $dir     = [System.IO.Path]::GetDirectoryName($Path)
        $base    = [System.IO.Path]::GetFileNameWithoutExtension($Path)
        $ext     = [System.IO.Path]::GetExtension($Path)
        $archive = Join-Path $dir "${base}_${stamp}${ext}"

        Rename-Item -Path $Path -NewName $archive -Force -ErrorAction Stop

        # Write a short header so the new file explains itself
        $header = "# Log rotated at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Previous file: $archive | User: $currentUser | Session: $sessionId"
        Add-Content -Path $Path -Value $header -Encoding UTF8

        Write-Host "  [LOG ROTATION] $([System.IO.Path]::GetFileName($Path)) rotated -> $([System.IO.Path]::GetFileName($archive))" -ForegroundColor DarkGray
    } catch {
        # Rotation failure is non-fatal — just keep writing to the existing file
        Write-Host "  [WARN] Log rotation failed for $Path : $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# =====================================================================
# ALERT / LOGGING with File Locking
# =====================================================================

function Safe-WriteToFile {
    param([string]$Path, [string]$Content)
    
    $lockAcquired = $fileLock.WaitOne(5000)
    if (-not $lockAcquired) {
        Write-Host "WARNING: Could not acquire lock for $Path after 5 seconds" -ForegroundColor Yellow
        return $false
    }
    
    try {
        Invoke-LogRotation -Path $Path   # rotate before writing if over size limit
        Add-Content -Path $Path -Value $Content -Encoding UTF8
        return $true
    } catch {
        Write-Host "ERROR writing to $Path : $($_.Exception.Message)" -ForegroundColor Red
        return $false
    } finally {
        $fileLock.ReleaseMutex()
    }
}

function Save-Alert {
    param([string]$Subject, [string]$Body)
    
    $alertKey = $Subject -replace '[^a-zA-Z0-9]', ''
    if (Is-AlertRateLimited -ip "global" -alertType $alertKey) {
        return
    }
    
    $ts  = Get-Timestamp
    $sep = "=" * 80
    $content = @"
$sep
[$ts] $Subject
User: $currentUser | Computer: $currentComputer | Session: $sessionId
$sep
$Body

"@
    
    Safe-WriteToFile -Path $alertFile -Content $content
    Write-Host "  [ALERT] $Subject" -ForegroundColor Cyan
}

# =====================================================================
# IDS FUNCTIONS
# =====================================================================

function Add-ThreatScore {
    param([string]$key, [int]$points, [string]$reason)
    if (-not $threatScore.ContainsKey($key)) { $threatScore[$key] = 0 }
    $threatScore[$key] += $points
    Safe-WriteToFile -Path $threatLogFile -Content "$(Get-Timestamp) | SID:$sessionIdShort | User:$currentUser | +$points | $key | $reason"
}

function Add-IDSAlert {
    param([string]$severity, [string]$ip, [string]$msg)
    
    $alertKey = "$ip`:$msg".Substring(0, [Math]::Min(100, "$ip`:$msg".Length))
    if (Is-AlertRateLimited -ip $ip -alertType $alertKey) {
        return
    }
    
    $ts    = Get-Timestamp
    $entry = @{ Time=$ts; Severity=$severity; IP=$ip; Message=$msg }
    $null  = $idsAlerts.Add($entry)
    while ($idsAlerts.Count -gt 100) { $idsAlerts.RemoveAt(0) }
    
    Safe-WriteToFile -Path $intrusionLogFile -Content "$ts | SID:$sessionIdShort | User:$currentUser | $severity | $ip | $msg"
    Save-Alert  -Subject "[$severity] IDS: $msg" -Body "Timestamp: $ts`nIP: $ip`nSeverity: $severity`nDetails: $msg"
}

function Register-KnownDevice {
    param([string]$mac, [string]$hostname)
    if ($mac -eq "unknown" -or $mac -eq "") { return }
    if (-not $knownDevices.ContainsKey($mac)) {
        $ts = Get-Timestamp
        $knownDevices[$mac] = @{ Hostname=$hostname; FirstSeen=$ts; TrustedStatus="new" }
        Safe-WriteToFile -Path $knownDevicesFile -Content "$mac,$hostname,$ts,new"
    }
}

function Test-UnknownDevice {
    param([string]$ip, [string]$mac, [string]$hostname)
    if ($mac -eq "unknown" -or (Is-ExcludedDevice -mac $mac)) { return }
    if (-not $knownDevices.ContainsKey($mac)) {
        Register-KnownDevice -mac $mac -hostname $hostname
        Add-IDSAlert   -severity "MEDIUM" -ip $ip -msg "NEW UNKNOWN DEVICE: $ip | MAC: $mac | Host: $hostname"
        Add-ThreatScore -key $mac -points 5 -reason "First time seen on network"
        Write-Host "  [IDS] New device: $ip ($hostname) MAC: $mac" -ForegroundColor Magenta
    }
}

function Test-RapidReconnect {
    param([string]$ip)
    $now = Get-Date
    if (-not $reconnectTracker.ContainsKey($ip)) { $reconnectTracker[$ip] = [System.Collections.ArrayList]::new() }
    $reconnectTracker[$ip].Add($now) | Out-Null
    
    $reconnectTracker[$ip] = [System.Collections.ArrayList]::new(@($reconnectTracker[$ip] | Where-Object {
        ($now - $_).TotalSeconds -le $reconnectWindowSeconds
    }))
    
    $count = $reconnectTracker[$ip].Count
    if ($count -ge $maxReconnectsInWindow) {
        Add-IDSAlert    -severity "HIGH" -ip $ip -msg "RAPID RECONNECT: $ip reconnected $count x in ${reconnectWindowSeconds}s - possible scan/instability"
        Add-ThreatScore -key $ip -points 8 -reason "Rapid reconnection (${count}x)"
        Write-Host "  [IDS] Rapid reconnect: $ip ($count times)" -ForegroundColor Red
    }
}

function Test-MacRoaming {
    param([string]$ip, [string]$mac)
    if ($mac -eq "unknown" -or (Is-ExcludedDevice -mac $mac)) { return }
    if ($macToIPHistory.ContainsKey($mac)) {
        $allIPs = @($macToIPHistory[$mac] | Select-Object -Unique)
        if ($allIPs.Count -gt $maxIPsPerMAC -and ($allIPs -notcontains $ip)) {
            $ipList = $allIPs -join ", "
            Add-IDSAlert    -severity "HIGH" -ip $ip -msg "MAC ROAMING/SPOOFING: MAC $mac seen on $($allIPs.Count + 1) IPs: $ipList + $ip"
            Add-ThreatScore -key $mac -points 10 -reason "Multiple IPs for same MAC ($($allIPs.Count + 1) IPs)"
            Write-Host "  [IDS] MAC roaming: $mac on multiple IPs" -ForegroundColor Red
        }
    }
}

function Test-SuspiciousHostname {
    param([string]$ip, [string]$hostname)
    if ($hostname -eq "unknown") { return }
    foreach ($pattern in $suspiciousPatterns) {
        if ($hostname -like "*$pattern*") {
            Add-IDSAlert    -severity "HIGH" -ip $ip -msg "SUSPICIOUS HOSTNAME: '$hostname' on $ip matches pentest pattern '$pattern'"
            Add-ThreatScore -key $ip -points 15 -reason "Suspicious hostname: $hostname"
            Write-Host "  [IDS] Suspicious hostname: $hostname ($ip)" -ForegroundColor Red
            break
        }
    }
}

function Invoke-IDSCheck {
    param([string]$ip, [string]$mac, [string]$hostname, [string]$eventType)
    if ($eventType -eq "CONNECT") {
        Test-UnknownDevice   -ip $ip -mac $mac -hostname $hostname
        Test-RapidReconnect  -ip $ip
        Test-MacRoaming      -ip $ip -mac $mac
        Test-SuspiciousHostname -ip $ip -hostname $hostname
    }
}

function Detect-IPChange {
    param([string]$ip, [string]$mac, [string]$hostname)
    if ($mac -eq "unknown" -or (Is-ExcludedDevice -mac $mac)) { return $false }
    if ($macToIPHistory.ContainsKey($mac)) {
        $prevIPs = $macToIPHistory[$mac]
        if ($prevIPs -notcontains $ip) {
            $ts     = Get-Timestamp
            $oldIPs = $prevIPs -join ", "
            $msg    = "$ts | IP CHANGE! MAC: $mac | Host: $hostname | OLD: $oldIPs | NEW: $ip"
            Safe-WriteToFile -Path $ipChangeLog -Content $msg
            Safe-WriteToFile -Path $csvFile -Content "$(Get-CsvTimestamp),IP_CHANGE,$ip,$hostname,OldIPs=$oldIPs"
            Write-Host $msg -ForegroundColor Magenta
            Save-Alert -Subject "IP CHANGE - $hostname" -Body "Timestamp: $ts`nHostname: $hostname`nMAC: $mac`nNEW IP: $ip`nOLD IPs: $oldIPs"
            Add-ThreatScore -key $mac -points 3 -reason "IP address change (was $oldIPs, now $ip)"
            return $true
        }
    }
    if (-not $macToIPHistory.ContainsKey($mac)) { $macToIPHistory[$mac] = @() }
    if ($macToIPHistory[$mac] -notcontains $ip) { $macToIPHistory[$mac] += $ip }
    if ($hostname -ne "unknown") { $macToHostname[$mac] = $hostname }
    return $false
}

# =====================================================================
# STATISTICS
# =====================================================================

function Update-Statistics {
    param([string]$ip, [string]$hostname, [string]$eventType, [string]$macAddress)
    $ts = Get-Timestamp
    if (-not $stats.ContainsKey($ip)) {
        $stats[$ip] = @{
            Hostname          = $hostname
            TotalConnects     = 0
            TotalDisconnects  = 0
            FirstSeen         = $ts
            LastSeen          = $ts
            CurrentStatus     = "unknown"
            MACAddress        = $macAddress
            LastKnownHostname = $hostname
            AvgSessionMin     = 0
        }
    }
    if ($eventType -eq "CONNECT") {
        $stats[$ip].TotalConnects++
        $stats[$ip].CurrentStatus = "online"
        $sessionStart[$ip] = Get-Date
        if ($hostname -ne "unknown" -and $stats[$ip].LastKnownHostname -ne $hostname) {
            Safe-WriteToFile -Path $ipChangeLog -Content "$(Get-Timestamp) | HOSTNAME CHANGE $ip | OLD: $($stats[$ip].LastKnownHostname) | NEW: $hostname"
            $stats[$ip].LastKnownHostname = $hostname
        }
    } elseif ($eventType -eq "DISCONNECT") {
        $stats[$ip].TotalDisconnects++
        $stats[$ip].CurrentStatus = "offline"
        if ($sessionStart.ContainsKey($ip)) {
            $duration = [math]::Round(((Get-Date) - $sessionStart[$ip]).TotalMinutes, 1)
            if (-not $sessionDurations.ContainsKey($ip)) { $sessionDurations[$ip] = @() }
            $sessionDurations[$ip] += $duration
            $avg = [math]::Round(($sessionDurations[$ip] | Measure-Object -Average).Average, 1)
            $stats[$ip].AvgSessionMin = $avg
            $sessionStart.Remove($ip)
        }
    }
    $stats[$ip].LastSeen = $ts
    if ($hostname   -ne "unknown") { $stats[$ip].Hostname   = $hostname   }
    if ($macAddress -ne "unknown") {
        $stats[$ip].MACAddress        = $macAddress
        $stats[$ip].LastKnownHostname = $hostname
        $macCache[$ip] = @{ MACAddress=$macAddress; LastSeen=$ts; Hostname=$hostname }
    }
}

function Save-Statistics {
    # FIXED: Using Set-Content instead of Add-Content to prevent accumulation
    $lines = @("IPAddress,Hostname,TotalConnects,TotalDisconnects,FirstSeen,LastSeen,CurrentStatus,MACAddress,LastKnownHostname,AvgSessionMin")
    foreach ($ip in ($stats.Keys | Sort-Object)) {
        $s = $stats[$ip]
        $lines += "$ip,$($s.Hostname),$($s.TotalConnects),$($s.TotalDisconnects),$($s.FirstSeen),$($s.LastSeen),$($s.CurrentStatus),$($s.MACAddress),$($s.LastKnownHostname),$($s.AvgSessionMin)"
    }
    $content = $lines -join "`r`n"
    Set-Content -Path $statsFile -Value $content -Encoding UTF8

    $cLines = @("IPAddress,MACAddress,LastSeen,Hostname")
    foreach ($ip in ($macCache.Keys | Sort-Object)) {
        $c = $macCache[$ip]
        $cLines += "$ip,$($c.MACAddress),$($c.LastSeen),$($c.Hostname)"
    }
    $cContent = $cLines -join "`r`n"
    Set-Content -Path $macCacheFile -Value $cContent -Encoding UTF8
}

# =====================================================================
# VISUALIZATION HELPERS
# =====================================================================

function Write-BarChart {
    param(
        [string]$Label,
        [int]   $Value,
        [int]   $MaxValue,
        [int]   $BarWidth = 28,
        [string]$Color    = "Cyan",
        [int]   $LabelWidth = 22
    )
    if ($MaxValue -lt 1) { $MaxValue = 1 }
    $filled = [math]::Round(($Value / $MaxValue) * $BarWidth)
    $empty  = $BarWidth - $filled
    $bar    = ([string][char]9608) * $filled + ([string][char]9617) * $empty
    $fmt    = "{0,-$LabelWidth} {1} {2,5}"
    Write-Host ($fmt -f $Label, $bar, $Value) -ForegroundColor $Color
}

# =====================================================================
# SCAN FUNCTIONS with Timeouts
# =====================================================================

function Scan-Network {
    return Discover-Hosts
}

function Scan-PicoKMS {
    $ts = Get-Timestamp
    foreach ($port in $picokmsPorts) {
        try {
            $result = & $nmapExe -p $port --open --host-timeout 30s $subnet 2>$null
            if ($result -match "open") {
                $openIPs = @()
                foreach ($line in ($result -split "`r?`n")) {
                    if ($line -match "Nmap scan report for (?:.*\()?(\d+\.\d+\.\d+\.\d+)\)?") { $openIPs += $matches[1] }
                }
                if ($openIPs.Count -gt 0) {
                    $logMsg = "$ts | WARNING: PicoKMS PORT $port OPEN on $($openIPs -join ', ')"
                    Safe-WriteToFile -Path $criticalPortsLog -Content $logMsg
                    Write-Host $logMsg -ForegroundColor Red
                    Save-Alert  -Subject "PicoKMS DETECTED!" -Body "Timestamp: $ts`nPort: $port`nAffected IPs: $($openIPs -join ', ')"
                    foreach ($ip in $openIPs) { Add-ThreatScore -key $ip -points 20 -reason "PicoKMS port $port open" }
                }
            }
        } catch {
            Safe-WriteToFile -Path $errorLog -Content "$(Get-Timestamp) | PicoKMS error port $port - $($_.Exception.Message)"
        }
    }
}

function Scan-CriticalPorts {
    param([string]$ip, [string]$hostname, [string]$mac)
    if (Is-ExcludedDevice -mac $mac) { return }
    $openPorts = @()
    foreach ($portInfo in $criticalPorts) {
        try {
            # FIXED: Added null check for TcpTestSucceeded
            $result = Test-NetConnection -ComputerName $ip -Port $portInfo.Port `
                      -WarningAction SilentlyContinue -ErrorAction SilentlyContinue `
                      -TimeoutSeconds 3
            if ($result -and $result.TcpTestSucceeded -eq $true) { 
                $openPorts += "$($portInfo.Port)/$($portInfo.Name)" 
            }
        } catch { }
    }
    if ($openPorts.Count -gt 0) {
        $ts   = Get-Timestamp
        $macD = if ($mac -eq "unknown") { "n/a" } else { $mac }
        $msg  = "$ts | CRITICAL PORTS on $ip ($hostname) MAC: $macD | $($openPorts -join ', ')"
        Safe-WriteToFile -Path $criticalPortsLog -Content $msg
        Write-Host $msg -ForegroundColor Yellow
        Save-Alert -Subject "Critical Ports Open on $ip" -Body "Timestamp: $ts`nHost: $ip ($hostname)`nMAC: $macD`nOpen Ports: $($openPorts -join ', ')"
        $isNew = (-not $knownDevices.ContainsKey($mac)) -or ($knownDevices.ContainsKey($mac) -and $knownDevices[$mac].TrustedStatus -eq "new")
        if ($isNew) {
            Add-IDSAlert    -severity "MEDIUM" -ip $ip -msg "NEW/UNTRUSTED device $ip has critical ports open: $($openPorts -join ',')"
            Add-ThreatScore -key $ip -points 7 -reason "New device with open critical ports"
        }
    }
}

# =====================================================================
# LOG FUNCTIONS (connect / disconnect / initial)
# =====================================================================

function Write-ConnectLog {
    param([string]$ip)
    $hostname   = Get-HostnameWithCache   $ip
    $mac        = Get-MacAddressWithCache $ip
    $ts         = Get-Timestamp
    $isExcluded = Is-ExcludedDevice -mac $mac
    $ipChanged  = Detect-IPChange   -ip $ip -mac $mac -hostname $hostname
    Update-Statistics -ip $ip -hostname $hostname -eventType "CONNECT" -macAddress $mac
    if (-not $isExcluded) { Invoke-IDSCheck -ip $ip -mac $mac -hostname $hostname -eventType "CONNECT" }

    $macD = if ($mac -eq "unknown") { "n/a" } else { $mac }
    Safe-WriteToFile -Path $logFile -Content "$ts | CONNECT | $ip | $hostname | MAC: $macD | SID:$sessionIdShort | User:$currentUser"
    Safe-WriteToFile -Path $csvFile -Content "$(Get-CsvTimestamp),CONNECT,$ip,$hostname,$macD"

    if      ($isExcluded) { Write-Host "$ts | CONNECT    | $ip | $hostname | MAC: $macD [EXCL]"      -ForegroundColor DarkGray  }
    elseif  ($ipChanged)  { Write-Host "$ts | CONNECT    | $ip | $hostname | MAC: $macD [IP CHANGE]" -ForegroundColor Magenta    }
    else                  { Write-Host "$ts | CONNECT    | $ip | $hostname | MAC: $macD"             -ForegroundColor Green      }

    if (-not $isExcluded) {
        $note = if ($ipChanged) { "`nWARNING: Device changed IP address!" } else { "" }
        Save-Alert -Subject "Host Connected: $ip ($hostname)" `
                   -Body "HOST CONNECTED!`n`nTimestamp: $ts`nIP: $ip`nHostname: $hostname`nMAC: $macD`nTotal connects: $($stats[$ip].TotalConnects)$note"
        Scan-CriticalPorts -ip $ip -hostname $hostname -mac $mac
    }
}

function Write-DisconnectLog {
    param([string]$ip)
    $hostname = if ($stats.ContainsKey($ip) -and $stats[$ip].Hostname -ne "unknown") { $stats[$ip].Hostname } else { Get-HostnameWithCache $ip }
    $mac      = if ($stats.ContainsKey($ip) -and $stats[$ip].MACAddress -ne "unknown") { $stats[$ip].MACAddress } else { Get-MacAddressWithCache $ip }
    $ts         = Get-Timestamp
    $isExcluded = Is-ExcludedDevice -mac $mac
    Update-Statistics -ip $ip -hostname $hostname -eventType "DISCONNECT" -macAddress $mac

    Safe-WriteToFile -Path $logFile -Content "$ts | DISCONNECT | $ip | $hostname | SID:$sessionIdShort | User:$currentUser"
    Safe-WriteToFile -Path $csvFile -Content "$(Get-CsvTimestamp),DISCONNECT,$ip,$hostname,"

    if ($isExcluded) { Write-Host "$ts | DISCONNECT | $ip | $hostname [EXCL]" -ForegroundColor DarkGray }
    else             { Write-Host "$ts | DISCONNECT | $ip | $hostname"         -ForegroundColor Red     }

    if (-not $isExcluded) {
        Save-Alert -Subject "Host Disconnected: $ip ($hostname)" `
                   -Body "HOST DISCONNECTED!`n`nTimestamp: $ts`nIP: $ip`nHostname: $hostname`nTotal disconnects: $($stats[$ip].TotalDisconnects)"
    }
    
    if ($reconnectTracker.ContainsKey($ip)) {
        $reconnectTracker.Remove($ip)
    }
}

function Write-InitialLog {
    param([string]$ip)
    $hostname   = Get-HostnameWithCache   $ip
    $mac        = Get-MacAddressWithCache $ip
    $ts         = Get-Timestamp
    $isExcluded = Is-ExcludedDevice -mac $mac
    Detect-IPChange   -ip $ip -mac $mac -hostname $hostname | Out-Null
    Update-Statistics -ip $ip -hostname $hostname -eventType "CONNECT" -macAddress $mac
    if (-not $isExcluded) { Register-KnownDevice -mac $mac -hostname $hostname }

    $macD = if ($mac -eq "unknown") { "n/a" } else { $mac }
    Safe-WriteToFile -Path $logFile -Content "$ts | INITIAL | $ip | $hostname | MAC: $macD | SID:$sessionIdShort | User:$currentUser"
    Safe-WriteToFile -Path $csvFile -Content "$(Get-CsvTimestamp),INITIAL,$ip,$hostname,$macD"

    if ($isExcluded) { Write-Host "$ts | INITIAL    | $ip | $hostname | MAC: $macD [EXCL]" -ForegroundColor DarkGray }
    else             { Write-Host "$ts | INITIAL    | $ip | $hostname | MAC: $macD"        -ForegroundColor Cyan     }
}

# =====================================================================
# INITIAL SCAN
# =====================================================================

function InitialFastScan {
    Write-Host "  Starting initial scan of $subnet ..." -ForegroundColor Yellow
    $t0          = Get-Date
    $activeHosts = Scan-Network
    $dur         = [math]::Round(((Get-Date) - $t0).TotalSeconds, 0)
    Write-Host "  Scan completed in ${dur}s | Active hosts: $($activeHosts.Count)" -ForegroundColor Green
    Write-Host ""
    $activeHosts | Out-File -FilePath $statusFile -Encoding UTF8
    foreach ($ip in $activeHosts) { Write-InitialLog $ip }
    Write-Host ""
    Write-Host "  Checking critical ports on active hosts..." -ForegroundColor Yellow
    foreach ($ip in $activeHosts) {
        $h = Get-HostnameWithCache   $ip
        $m = Get-MacAddressWithCache $ip
        Scan-CriticalPorts -ip $ip -hostname $h -mac $m
    }
    return $activeHosts
}

# =====================================================================
# ADVANCED SCAN CYCLE (with Nmap pipeline)
# =====================================================================

function Start-AdvancedScanCycle {
    Write-Host "`n===== NEW SCAN CYCLE =====" -ForegroundColor Green
    
    $hosts = Discover-Hosts
    
    if ($hosts.Count -eq 0) {
        Write-Host "  No hosts found." -ForegroundColor Yellow
        return
    }
    
    Write-Host "  Found $($hosts.Count) active hosts" -ForegroundColor Green
    
    $serviceData = Scan-Services -hosts $hosts
    if ($serviceData) {
        Safe-WriteToFile -Path $logFile -Content "`n=== SERVICE SCAN $(Get-Timestamp) ===`n$serviceData"
        Analyze-Ports -nmapOutput $serviceData
    }
    
    $osData = Detect-OS -hosts $hosts
    if ($osData) {
        Safe-WriteToFile -Path $logFile -Content "`n=== OS DETECTION $(Get-Timestamp) ===`n$osData"
    }
    
    $vulnData = Run-NSEScripts -hosts $hosts
    if ($vulnData) {
        Safe-WriteToFile -Path $threatLogFile -Content "`n=== VULNERABILITY SCAN $(Get-Timestamp) ===`n$vulnData"
        
        # Check for vulnerabilities in output
        if ($vulnData -match "VULNERABLE|CVE-") {
            $msg = "Potential vulnerabilities detected in scan"
            Add-IDSAlert -severity "HIGH" -ip "network" -msg $msg
            Write-Host "  [IDS] Vulnerabilities detected!" -ForegroundColor Red
        }
    }
}

# =====================================================================
# MAIN MONITORING LOOP (UPGRADED)
# =====================================================================

function Start-Monitoring {
    Clear-Host
    Write-Host ""
    Write-Host ("=" * 66) -ForegroundColor Red
    Write-Host "   NETWORK MONITOR + IDS  -  ACTIVE MONITORING" -ForegroundColor Red
    Write-Host ("=" * 66) -ForegroundColor Red
    Write-Host "  Subnet   : $subnet" -ForegroundColor Green
    Write-Host "  Interval : $intervalSecunde sec" -ForegroundColor Green
    Write-Host "  Scan Mode: $scanMode" -ForegroundColor Green
    Write-Host "  Log dir  : $logDir" -ForegroundColor Green
    Write-Host "  IDS log  : $intrusionLogFile" -ForegroundColor Cyan
    Write-Host "  User     : $currentUser" -ForegroundColor DarkYellow
    Write-Host "  Computer : $currentComputer" -ForegroundColor DarkYellow
    Write-Host "  Session  : $sessionId" -ForegroundColor DarkYellow
    Write-Host ("=" * 66) -ForegroundColor Red
    Write-Host ""

    $currentHosts = InitialFastScan

    Write-Host ""
    Write-Host "  Monitoring active. Press CTRL+C to stop." -ForegroundColor Green
    Write-Host ""

    $scanCounter = 0
    while ($true) {
        try {
            $scanCounter++
            
            # FIXED: Check if status file exists before reading
            $previousHosts = @()
            if (Test-Path $statusFile) { 
                $previousHosts = Get-Content $statusFile -ErrorAction SilentlyContinue 
            }
            $currentHosts  = Scan-Network

            foreach ($ip in $currentHosts) {
                if ($previousHosts -notcontains $ip) { Write-ConnectLog $ip }
            }
            foreach ($ip in $previousHosts) {
                if ($currentHosts -notcontains $ip) { Write-DisconnectLog $ip }
            }

            $currentHosts | Out-File -FilePath $statusFile -Encoding UTF8

            $threatHigh = ($threatScore.Values | Where-Object { $_ -ge $threatThresholds.High }).Count
            Write-Host "$(Get-Timestamp) | Scan #$scanCounter | Online: $($currentHosts.Count) | IDS events: $($idsAlerts.Count) | Threats(HIGH): $threatHigh" -ForegroundColor DarkGray

            Scan-PicoKMS
            
            # Run advanced Nmap pipeline every 3rd scan (to reduce load)
            if ($scanCounter % 3 -eq 0) {
                Start-AdvancedScanCycle
            }
            
            Save-Statistics
            
        } catch {
            Safe-WriteToFile -Path $errorLog -Content "$(Get-Timestamp) | Scan cycle error: $_"
            Write-Host "  ERROR in scan cycle: $_" -ForegroundColor Red
        }
        
        Start-Sleep -Seconds $intervalSecunde
    }
}

# =====================================================================
# DISPLAY FUNCTIONS
# =====================================================================

function Show-Statistics {
    Clear-Host
    Write-Host ""
    Write-Host ("=" * 105) -ForegroundColor Cyan
    Write-Host "                      HOST STATISTICS" -ForegroundColor Cyan
    Write-Host ("=" * 105) -ForegroundColor Cyan
    Write-Host ("{0,-16} {1,-22} {2,5} {3,5} {4,7} {5,9}  {6,-19} {7,-8} {8}" -f `
        "IP Address","Hostname","Conn","Disc","Up%","AvgSesM","MAC Address","Status","Threat") -ForegroundColor Yellow
    Write-Host ("-" * 105) -ForegroundColor DarkGray

    foreach ($ip in ($stats.Keys | Sort-Object)) {
        $s       = $stats[$ip]
        $threat  = if ($threatScore.ContainsKey($ip)) { $threatScore[$ip] } else { 0 }
        $color   = if ($s.CurrentStatus -eq "online") { "Green" } else { "DarkGray" }
        if ($threat -ge $threatThresholds.High)   { $color = "Red"    }
        elseif ($threat -ge $threatThresholds.Medium) { $color = "Yellow" }
        $macD    = if ($s.MACAddress -eq "unknown") { "n/a" } else { $s.MACAddress }
        $pct     = Get-UptimePct $ip
        $avgS    = if ($s.AvgSessionMin -gt 0) { $s.AvgSessionMin } else { "-" }
        $tLabel  = Get-ThreatLabel -score $threat
        Write-Host ("{0,-16} {1,-22} {2,5} {3,5} {4,7} {5,9}  {6,-19} {7,-8} {8}" -f `
            $ip, $s.Hostname, $s.TotalConnects, $s.TotalDisconnects, "$pct%", $avgS, $macD, $s.CurrentStatus, $tLabel) -ForegroundColor $color
    }

    Write-Host ("=" * 105) -ForegroundColor Cyan
    $on  = ($stats.Values | Where-Object { $_.CurrentStatus -eq "online"  }).Count
    $off = ($stats.Values | Where-Object { $_.CurrentStatus -eq "offline" }).Count
    Write-Host ("  Total: $($stats.Count)  |  Online: $on  |  Offline: $off  |  IDS alerts this session: $($idsAlerts.Count)") -ForegroundColor White
    Write-Host ""
}

# FIXED: Corrected the Hakut typo
function Show-NetworkGraph {
    Clear-Host
    Write-Host ""
    Write-Host ("=" * 68) -ForegroundColor Cyan
    Write-Host "            NETWORK ACTIVITY GRAPH" -ForegroundColor Cyan
    Write-Host ("=" * 68) -ForegroundColor Cyan

    if ($stats.Count -eq 0) {
        Write-Host "  No data available yet." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "  CONNECTIONS PER HOST (top 15):" -ForegroundColor Yellow
    Write-Host ("  {0,-22} {1,-30} {2}" -f "IP / Hostname","","Count") -ForegroundColor DarkGray
    Write-Host ""

    $sorted     = $stats.GetEnumerator() | Sort-Object { $_.Value.TotalConnects } -Descending | Select-Object -First 15
    $maxConn    = ($sorted | ForEach-Object { $_.Value.TotalConnects } | Measure-Object -Maximum).Maximum
    if ($maxConn -lt 1) { $maxConn = 1 }

    foreach ($e in $sorted) {
        $ip     = $e.Key
        $s      = $e.Value
        $label  = if ($s.Hostname -ne "unknown") { "$ip ($($s.Hostname))" } else { $ip }
        $label  = $label.Substring(0, [math]::Min($label.Length, 22))
        $color  = if ($s.CurrentStatus -eq "online") { "Green" } else { "DarkGray" }
        $threat = if ($threatScore.ContainsKey($ip)) { $threatScore[$ip] } else { 0 }
        if ($threat -ge $threatThresholds.High)   { $color = "Red"    }
        elseif ($threat -ge $threatThresholds.Medium) { $color = "Yellow" }
        Write-Host "  " -NoNewline
        Write-BarChart -Label $label -Value $s.TotalConnects -MaxValue $maxConn -Color $color
    }

    Write-Host ""
    Write-Host ("=" * 68) -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  UPTIME INDEX % (hosts with >1 event):" -ForegroundColor Yellow
    Write-Host ""

    $withEvents = $stats.GetEnumerator() | Where-Object {
        ($_.Value.TotalConnects + $_.Value.TotalDisconnects) -gt 1
    } | Sort-Object { Get-UptimePct $_.Key } -Descending | Select-Object -First 12

    foreach ($e in $withEvents) {
        $ip    = $e.Key
        $s     = $e.Value
        $pct   = Get-UptimePct $ip
        $label = if ($s.Hostname -ne "unknown") { "$ip ($($s.Hostname))" } else { $ip }
        $label = $label.Substring(0, [math]::Min($label.Length, 22))
        $color = if ($pct -ge 80) { "Green" } elseif ($pct -ge 50) { "Yellow" } else { "Red" }
        Write-Host "  " -NoNewline
        Write-BarChart -Label $label -Value $pct -MaxValue 100 -BarWidth 25 -Color $color
    }

    if ($threatScore.Count -gt 0) {
        Write-Host ""
        Write-Host ("=" * 68) -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  THREAT SCORES:" -ForegroundColor Red
        Write-Host ""
        $sortedThreats = $threatScore.GetEnumerator() | Sort-Object { $_.Value } -Descending | Select-Object -First 10
        $maxThreat     = ($sortedThreats | ForEach-Object { $_.Value } | Measure-Object -Maximum).Maximum
        if ($maxThreat -lt 1) { $maxThreat = 1 }
        foreach ($e in $sortedThreats) {
            $color = Get-ThreatColor -score $e.Value
            Write-Host "  " -NoNewline
            Write-BarChart -Label $e.Key -Value $e.Value -MaxValue $maxThreat -BarWidth 20 -Color $color
        }
    }
    Write-Host ""
}

function Show-LiveDashboard {
    $refreshSec = 30
    Write-Host "  Live Dashboard - auto-refreshes every ${refreshSec}s. Press CTRL+C to exit." -ForegroundColor Cyan
    Start-Sleep -Seconds 2
    
    try {
        while ($true) {
            Clear-Host
            $ts         = Get-Timestamp
            $onCount    = ($stats.Values | Where-Object { $_.CurrentStatus -eq "online" }).Count
            $totalKnown = $stats.Count
            $tHigh      = ($threatScore.Values | Where-Object { $_ -ge $threatThresholds.High   }).Count
            $tMed       = ($threatScore.Values | Where-Object { $_ -ge $threatThresholds.Medium -and $_ -lt $threatThresholds.High }).Count
            $newDevices = ($knownDevices.Values | Where-Object { $_.TrustedStatus -eq "new" }).Count

            Write-Host ("=" * 72) -ForegroundColor Red
            Write-Host ("  NETWORK MONITOR DASHBOARD         " + $ts) -ForegroundColor Red
            Write-Host ("=" * 72) -ForegroundColor Red
            Write-Host ""

            Write-Host ("  {0,-18} {1,-18} {2,-18} {3,-16}" -f "Online Hosts","Known Hosts","New Devices","IDS Events") -ForegroundColor DarkGray
            Write-Host ("  {0,-18} {1,-18} {2,-18} {3,-16}" -f `
                "[ $onCount / $totalKnown ]", "[ $totalKnown ]", "[ $newDevices ]", "[ $($idsAlerts.Count) ]") -ForegroundColor White
            Write-Host ""

            Write-Host "  Threat level:  " -NoNewline -ForegroundColor DarkGray
            if ($tHigh -gt 0)    { Write-Host " HIGH:$tHigh "   -NoNewline -ForegroundColor Red    }
            if ($tMed -gt 0)     { Write-Host " MEDIUM:$tMed "  -NoNewline -ForegroundColor Yellow }
            if ($tHigh + $tMed -eq 0) { Write-Host " All clear " -NoNewline -ForegroundColor Green }
            Write-Host ""
            Write-Host ""

            Write-Host ("  {0,-24} {1,-18} {2,5} {3,5} {4,7}  {5,-8} {6}" -f `
                "IP / Hostname","MAC","Conn","Disc","Up%","Status","Threat") -ForegroundColor Yellow
            Write-Host ("  " + "-" * 70) -ForegroundColor DarkGray

            $topHosts = $stats.GetEnumerator() | Sort-Object { $_.Value.TotalConnects } -Descending | Select-Object -First 18
            foreach ($e in $topHosts) {
                $ip     = $e.Key
                $s      = $e.Value
                $label  = if ($s.Hostname -ne "unknown") { "$ip/$($s.Hostname)" } else { $ip }
                $label  = $label.Substring(0, [math]::Min($label.Length, 23))
                $macD   = if ($s.MACAddress -ne "unknown") { $s.MACAddress } else { "n/a" }
                $pct    = Get-UptimePct $ip
                $stStr  = if ($s.CurrentStatus -eq "online") { "[ON] " } else { "[OFF]" }
                $threat = if ($threatScore.ContainsKey($ip)) { $threatScore[$ip] } else { 0 }
                $tLbl   = Get-ThreatLabel -score $threat
                $color  = if ($s.CurrentStatus -eq "online") { "Green" } else { "DarkGray" }
                if ($threat -ge $threatThresholds.High)   { $color = "Red"    }
                elseif ($threat -ge $threatThresholds.Medium) { $color = "Yellow" }
                Write-Host ("  {0,-24} {1,-18} {2,5} {3,5} {4,7}  {5,-8} {6}" -f `
                    $label, $macD, $s.TotalConnects, $s.TotalDisconnects, "$pct%", $stStr, $tLbl) -ForegroundColor $color
            }

            Write-Host ""
            if ($idsAlerts.Count -gt 0) {
                Write-Host ("  RECENT IDS ALERTS:") -ForegroundColor Red
                Write-Host ("  " + "-" * 70) -ForegroundColor DarkGray
                $recent = $idsAlerts | Select-Object -Last 6
                foreach ($a in $recent) {
                    $aColor = if ($a.Severity -eq "HIGH") { "Red" } elseif ($a.Severity -eq "MEDIUM") { "Yellow" } else { "DarkYellow" }
                    Write-Host ("  [{0}] {1,-8} {2}" -f $a.Time.Substring(11,8), $a.Severity, $a.Message) -ForegroundColor $aColor
                }
            } else {
                Write-Host "  IDS: No alerts this session - network looks clean." -ForegroundColor DarkGreen
            }

            Write-Host ""
            Write-Host ("=" * 72) -ForegroundColor DarkGray
            Write-Host "  Refreshing in ${refreshSec}s  |  CTRL+C to return to menu  |  Subnet: $subnet" -ForegroundColor DarkGray
            Start-Sleep -Seconds $refreshSec
        }
    } catch {
        # FIXED: Reset console color before exiting
        [console]::ResetColor()
        Write-Host ""
        Write-Host "  Dashboard closed." -ForegroundColor DarkGray
        Start-Sleep -Seconds 1
    }
}

function Show-ThreatReport {
    Clear-Host
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor Red
    Write-Host "              INTRUSION DETECTION REPORT" -ForegroundColor Red
    Write-Host ("=" * 72) -ForegroundColor Red
    Write-Host ""

    if ($threatScore.Count -eq 0 -and $idsAlerts.Count -eq 0) {
        Write-Host "  No threats detected. Network appears clean." -ForegroundColor Green
        Write-Host ""
        return
    }

    if ($threatScore.Count -gt 0) {
        Write-Host "  THREAT SCORES:" -ForegroundColor Yellow
        Write-Host ("  {0,-22} {1,-7} {2,-9} {3}" -f "IP / MAC","Score","Level","Hostname") -ForegroundColor DarkGray
        Write-Host ("  " + "-" * 70) -ForegroundColor DarkGray
        $sortedT = $threatScore.GetEnumerator() | Sort-Object { $_.Value } -Descending
        foreach ($e in $sortedT) {
            $key   = $e.Key
            $score = $e.Value
            $label = Get-ThreatLabel -score $score
            $color = Get-ThreatColor -score $score
            $info  = if ($stats.ContainsKey($key)) { $stats[$key].Hostname } else { "" }
            Write-Host ("  {0,-22} {1,-7} {2,-9} {3}" -f $key, $score, $label, $info) -ForegroundColor $color
        }
        Write-Host ""
    }

    Write-Host "  ALL IDS EVENTS THIS SESSION ($($idsAlerts.Count) total):" -ForegroundColor Yellow
    Write-Host ("  " + "-" * 70) -ForegroundColor DarkGray
    if ($idsAlerts.Count -eq 0) {
        Write-Host "  None." -ForegroundColor Green
    } else {
        foreach ($a in $idsAlerts) {
            $aColor = if ($a.Severity -eq "HIGH") { "Red" } elseif ($a.Severity -eq "MEDIUM") { "Yellow" } else { "DarkYellow" }
            Write-Host ("  [{0}] {1,-8} {2}" -f $a.Time, $a.Severity, $a.Message) -ForegroundColor $aColor
        }
    }

    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor DarkGray
    $hCount = ($threatScore.Values | Where-Object { $_ -ge $threatThresholds.High   }).Count
    $mCount = ($threatScore.Values | Where-Object { $_ -ge $threatThresholds.Medium -and $_ -lt $threatThresholds.High }).Count
    Write-Host "  Summary: HIGH=$hCount  MEDIUM=$mCount  Total IDS events=$($idsAlerts.Count)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Threat log file : $threatLogFile" -ForegroundColor DarkGray
    Write-Host "  Intrusion log   : $intrusionLogFile" -ForegroundColor DarkGray
    Write-Host ""
}

function Show-LastAlerts {
    Write-Host ""
    Write-Host ("=" * 65) -ForegroundColor Cyan
    Write-Host "                  LAST ALERTS" -ForegroundColor Cyan
    Write-Host ("=" * 65) -ForegroundColor Cyan
    if (Test-Path $alertFile) { Get-Content $alertFile -Tail 60 }
    else { Write-Host "  No alerts logged yet." -ForegroundColor Yellow }
    Write-Host ""
}

function Show-MacCache {
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "                  MAC ADDRESS CACHE" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ("{0,-16} {1,-20} {2,-25} {3}" -f "IP Address","MAC Address","Last Seen","Hostname") -ForegroundColor Yellow
    Write-Host ("-" * 80) -ForegroundColor DarkGray
    foreach ($ip in ($macCache.Keys | Sort-Object)) {
        $c = $macCache[$ip]
        Write-Host ("{0,-16} {1,-20} {2,-25} {3}" -f $ip, $c.MACAddress, $c.LastSeen, $c.Hostname) -ForegroundColor White
    }
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "  Total entries: $($macCache.Count)" -ForegroundColor Green
    Write-Host ""
}

function Show-KnownDevices {
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor Cyan
    Write-Host "               KNOWN DEVICES REGISTRY" -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor Cyan
    Write-Host ("{0,-22} {1,-22} {2,-22} {3}" -f "MAC Address","Hostname","First Seen","Trust Status") -ForegroundColor Yellow
    Write-Host ("-" * 78) -ForegroundColor DarkGray
    foreach ($mac in ($knownDevices.Keys | Sort-Object)) {
        $d     = $knownDevices[$mac]
        $color = switch ($d.TrustedStatus) {
            "trusted"  { "Green"  }
            "blocked"  { "Red"    }
            default    { "Yellow" }
        }
        Write-Host ("{0,-22} {1,-22} {2,-22} {3}" -f $mac, $d.Hostname, $d.FirstSeen, $d.TrustedStatus) -ForegroundColor $color
    }
    Write-Host ("=" * 78) -ForegroundColor Cyan
    Write-Host "  Total: $($knownDevices.Count) devices" -ForegroundColor White
    Write-Host ""
    Write-Host "  Tip: Edit '$knownDevicesFile'" -ForegroundColor DarkGray
    Write-Host "       Set TrustedStatus to 'trusted' (green) or 'blocked' (red)." -ForegroundColor DarkGray
    Write-Host "       Devices marked 'blocked' will trigger HIGH alerts when seen." -ForegroundColor DarkGray
    Write-Host ""
}

function Show-IPDetails {
    $ip = Read-Host "  Enter IP address"
    Write-Host ""
    if (-not $stats.ContainsKey($ip)) {
        Write-Host "  IP $ip not found in database." -ForegroundColor Yellow
        return
    }
    $s      = $stats[$ip]
    $threat = if ($threatScore.ContainsKey($ip)) { $threatScore[$ip] } else { 0 }
    $pct    = Get-UptimePct $ip
    $tColor = Get-ThreatColor -score $threat
    $sColor = if ($s.CurrentStatus -eq "online") { "Green" } else { "Red" }

    Write-Host ("  " + "=" * 52) -ForegroundColor Cyan
    Write-Host "  Details: $ip" -ForegroundColor Cyan
    Write-Host ("  " + "=" * 52) -ForegroundColor Cyan
    Write-Host ("  {0,-18} {1}" -f "Hostname:",$s.Hostname)
    Write-Host ("  {0,-18} {1}" -f "MAC Address:",$s.MACAddress)
    Write-Host ("  {0,-18} {1}" -f "First Seen:",$s.FirstSeen)
    Write-Host ("  {0,-18} {1}" -f "Last Seen:",$s.LastSeen)
    Write-Host ("  {0,-18} {1}" -f "Status:",$s.CurrentStatus) -ForegroundColor $sColor
    Write-Host ("  {0,-18} {1}" -f "Connects:",$s.TotalConnects)    -ForegroundColor Green
    Write-Host ("  {0,-18} {1}" -f "Disconnects:",$s.TotalDisconnects) -ForegroundColor Red
    Write-Host ("  {0,-18} {1}%" -f "Uptime Index:",$pct)
    Write-Host ("  {0,-18} {1} min" -f "Avg Session:",$s.AvgSessionMin)
    Write-Host ("  {0,-18} {1} ({2})" -f "Threat Score:",$threat,(Get-ThreatLabel -score $threat).Trim()) -ForegroundColor $tColor

    if ($s.MACAddress -ne "unknown" -and $knownDevices.ContainsKey($s.MACAddress)) {
        $kd = $knownDevices[$s.MACAddress]
        Write-Host ("  {0,-18} {1}" -f "Trust Status:",$kd.TrustedStatus) -ForegroundColor (if($kd.TrustedStatus -eq "trusted"){"Green"}elseif($kd.TrustedStatus -eq "blocked"){"Red"}else{"Yellow"})
    }

    $myAlerts = $idsAlerts | Where-Object { $_.IP -eq $ip }
    if ($myAlerts) {
        Write-Host ""
        Write-Host "  IDS Events:" -ForegroundColor Yellow
        foreach ($a in $myAlerts) {
            $ac = if ($a.Severity -eq "HIGH") { "Red" } else { "Yellow" }
            Write-Host ("    [{0}] {1}: {2}" -f $a.Time, $a.Severity, $a.Message) -ForegroundColor $ac
        }
    }
    Write-Host ""
}

# =====================================================================
# EXECUTION AUDIT DISPLAY (FIXED)
# =====================================================================

function Show-ExecutionAudit {
    Clear-Host
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "                  EXECUTION AUDIT LOG" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
    
    if (Test-Path $executionAuditFile) {
        Write-Host "  All script executions (never deleted):" -ForegroundColor Yellow
        Write-Host ""
        
        # Display as formatted table
        $auditData = Import-Csv $executionAuditFile -ErrorAction SilentlyContinue
        if ($auditData -and $auditData.Count -gt 0) {
            Write-Host ("  {0,-20} {1,-25} {2,-15} {3,-10} {4}" -f "Timestamp", "Username", "Computer", "SessionID", "ScriptPath") -ForegroundColor DarkGray
            Write-Host ("  " + "-" * 120) -ForegroundColor DarkGray
            foreach ($row in $auditData) {
                # Handle potential missing properties safely
                $ts = if ($row.Timestamp) { $row.Timestamp } else { "N/A" }
                $user = if ($row.Username) { $row.Username } else { "N/A" }
                $comp = if ($row.Computer) { $row.Computer } else { "N/A" }
                $sid = if ($row.SessionID -and $row.SessionID.Length -gt 0) { $row.SessionID.Substring(0, [Math]::Min(8, $row.SessionID.Length)) + "..." } else { "N/A" }
                $path = if ($row.ScriptPath) { $row.ScriptPath } else { "N/A" }
                
                Write-Host ("  {0,-20} {1,-25} {2,-15} {3,-10} {4}" -f $ts, $user, $comp, $sid, $path) -ForegroundColor White
            }
        } else {
            # Fallback to raw display if CSV import fails or is empty
            Write-Host "  Raw audit data:" -ForegroundColor Yellow
            Get-Content $executionAuditFile | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
        }
        
        Write-Host ""
        Write-Host "  Total executions: $(if($auditData) { $auditData.Count } else { 0 })" -ForegroundColor Green
        Write-Host "  File location: $executionAuditFile" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  This audit log is NEVER rotated or deleted." -ForegroundColor DarkYellow
    } else {
        Write-Host "  No execution audit log found." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  The audit log will be created when the script runs." -ForegroundColor DarkGray
    }
    
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
}

# =====================================================================
# MAIN MENU
# =====================================================================

function Show-Menu {
    Clear-Host
    Write-Host ""
    Write-Host ("=" * 56) -ForegroundColor Red
    Write-Host "    NETWORK MONITOR + IDS  -  ADVANCED v2.0" -ForegroundColor Red
    Write-Host ("=" * 56) -ForegroundColor Red
    Write-Host "  Subnet  : $subnet" -ForegroundColor DarkGray
    Write-Host "  Log dir : $logDir" -ForegroundColor DarkGray
    Write-Host "  Mode    : $scanMode" -ForegroundColor DarkGray
    Write-Host "  User    : $currentUser  [$currentComputer]" -ForegroundColor DarkYellow
    Write-Host "  Session : $sessionIdShort" -ForegroundColor DarkGray

    $on     = ($stats.Values | Where-Object { $_.CurrentStatus -eq "online"  }).Count
    $tHigh  = ($threatScore.Values | Where-Object { $_ -ge $threatThresholds.High }).Count
    $statusColor = if ($tHigh -gt 0) { "Red" } else { "Green" }
    Write-Host "  Online  : $on / $($stats.Count)   Threats(HIGH): $tHigh" -ForegroundColor $statusColor

    Write-Host ("=" * 56) -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [1] Start monitoring" -ForegroundColor White
    Write-Host "  [2] Host statistics table" -ForegroundColor White
    Write-Host "  [3] Network activity graph + uptime + threats" -ForegroundColor Cyan
    Write-Host "  [4] Live dashboard  (auto-refresh)" -ForegroundColor Cyan
    Write-Host "  [5] Threat / IDS report" -ForegroundColor Yellow
    Write-Host "  [6] IP details + IDS events" -ForegroundColor White
    Write-Host "  [7] Last alerts" -ForegroundColor White
    Write-Host "  [8] MAC address cache" -ForegroundColor White
    Write-Host "  [9] Known devices registry" -ForegroundColor White
    Write-Host "  [A] Execution audit log" -ForegroundColor DarkYellow
    Write-Host "  [0] Exit" -ForegroundColor DarkGray
    Write-Host ""
}

do {
    Show-Menu
    $choice = Read-Host "  Choose option"

    switch ($choice) {
        "1" { Start-Monitoring }
        "2" { Show-Statistics;   Read-Host "`n  Press Enter" }
        "3" { Show-NetworkGraph; Read-Host "`n  Press Enter" }
        "4" { Show-LiveDashboard }
        "5" { Show-ThreatReport; Read-Host "`n  Press Enter" }
        "6" { Show-IPDetails;    Read-Host "`n  Press Enter" }
        "7" { Show-LastAlerts;   Read-Host "`n  Press Enter" }
        "8" { Show-MacCache;     Read-Host "`n  Press Enter" }
        "9" { Show-KnownDevices; Read-Host "`n  Press Enter" }
        "A" { Show-ExecutionAudit; Read-Host "`n  Press Enter" }   # FIXED: Added the missing menu option
        "0" { Write-Host "  Goodbye!" -ForegroundColor Green }
        default { Write-Host "  Invalid option!" -ForegroundColor Red; Start-Sleep -Seconds 2 }
    }
} while ($choice -ne "0")