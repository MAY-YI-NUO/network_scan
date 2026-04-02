NOTE - done with AI tools for training purposes. Text generated with AI
# Network Monitor + IDS - PowerShell Network Security Tool

## Description

**Network Monitor + IDS** is a comprehensive PowerShell-based network monitoring and intrusion detection system for Windows environments. It continuously scans your network, tracks device behavior, detects suspicious activities, and provides real-time alerts for potential security threats.

Built for network administrators and security professionals, this tool transforms a standard Windows machine into a powerful network monitoring station with IDS capabilities.

## Key Features

### 🔍 Network Discovery
- Automatic host discovery using Nmap ping scans
- Service and port detection on active hosts
- OS fingerprinting and vulnerability scanning (NSE scripts)
- Support for custom subnet configurations (/24 standard)

### 🛡️ Intrusion Detection
- **New device detection** - Alerts when unknown devices join the network
- **MAC roaming/spoofing detection** - Flags devices appearing with multiple IPs
- **Rapid reconnect detection** - Identifies potential port scans or unstable devices
- **Suspicious hostname detection** - Recognizes pentesting tool patterns (Kali, Metasploit, etc.)
- **Critical port monitoring** - Tracks SSH, RDP, VNC, SMB, NetBIOS, RPC
- **PicoKMS detection** - Monitors ports 3390-3393 for unauthorized KMS servers

### 📊 Monitoring & Analytics
- Real-time connection/disconnection tracking
- Session duration statistics and uptime percentage
- Threat scoring system (Low/Medium/High)
- MAC address to IP mapping with history
- DNS caching for performance

### 📁 Logging & Reporting
- Structured CSV logging for all events
- Automatic log rotation (1MB per file)
- Persistent statistics across script restarts
- Execution audit trail (never deleted)
- Separate logs for: alerts, threats, intrusions, errors, IP changes

### 🖥️ Interactive Dashboard
- Real-time network status display
- Threat level visualization
- Connection graphs and uptime charts
- Device details with IDS event history
- MAC address cache viewer
- Known devices registry with trust status

## Configuration Options

### Network Subnet Configuration

The script monitors a single subnet at a time. Configure it for your network by modifying line 35:

```powershell
$subnet = "192.168.0.0/24"   # Change this to match YOUR network
```

#### Common Network Configurations:

| Network Type | Subnet Value | Description |
|--------------|--------------|-------------|
| **Home/Office** | `192.168.0.0/24` | Most common home router default |
| **Alternative Home** | `192.168.1.0/24` | Second most common home network |
| **Corporate** | `10.0.0.0/24` or `10.0.1.0/24` | Common enterprise networks |
| **Corporate** | `172.16.0.0/24` to `172.31.0.0/24` | Corporate class B range |
| **Small Network** | `192.168.1.0/25` | 126 hosts (255.255.255.128) |
| **Large Network** | `10.0.0.0/16` | 65,534 hosts (use with caution!) |

### Scan Mode Configuration

Adjust the `$scanMode` variable (line 36) to balance speed vs thoroughness:

```powershell
$scanMode = "balanced"  # Options: fast | balanced | aggressive
```

| Mode | Speed | Features | Use Case |
|------|-------|----------|----------|
| **fast** | 30-60 sec | -T4 --top-ports 50 | Quick checks, large networks |
| **balanced** | 2-5 min | -T3 -sS -sV | Default, good for most |
| **aggressive** | 10-30+ min | -T4 -A --script vuln | Security audits, deep analysis |

### Scan Interval Configuration

Change the monitoring frequency (line 34):

```powershell
$intervalSecunde = 300   # Seconds between scans (default: 5 minutes)
```

**Recommended intervals:**
- `60` - Active monitoring (high traffic networks)
- `300` - Standard monitoring (default)
- `600` - Light monitoring (quiet networks)
- `3600` - Hourly checks (minimal network impact)

### Log Directory Configuration

Change where logs are stored (line 37):

```powershell
$logDir = "C:\NetworkMonitor"  # Change to any writable path
```

**Examples:**
```powershell
$logDir = "D:\SecurityLogs\NetworkMonitor"
$logDir = "$env:USERPROFILE\Documents\NetworkMonitor"
$logDir = "\\server\share\NetworkMonitor"  # Network share (requires permission)
```

### IDS Thresholds

Fine-tune sensitivity (lines 67-70):

```powershell
$maxReconnectsInWindow  = 3    # Reconnects before alert (1-5)
$reconnectWindowSeconds = 300  # Time window in seconds (60-600)
$maxIPsPerMAC           = 2    # Max IPs per MAC before flagging (2-4)
$threatThresholds       = @{ Low=3; Medium=6; High=10 }  # Score thresholds
```

### Alert Rate Limiting

Prevent alert flooding (line 72):

```powershell
$alertRateLimitSeconds = 60  # Minimum seconds between same alert type
```

### Critical Ports to Monitor

Customize which ports trigger alerts (lines 47-54):

```powershell
$criticalPorts = @(
    @{Port=22;   Name="SSH"},
    @{Port=3389; Name="RDP"},
    @{Port=5900; Name="VNC"},
    @{Port=445;  Name="SMB"},
    @{Port=139;  Name="NetBIOS"},
    @{Port=135;  Name="RPC"}
    # Add your own:
    # @{Port=3306; Name="MySQL"},
    # @{Port=5432; Name="PostgreSQL"}
)
```

### Suspicious Hostname Patterns

Add or remove patterns to detect (line 75):

```powershell
$suspiciousPatterns = @("kali","metasploit","parrot","pentbox","nessus","openvas","backtrack","hacker","pwn")
# Add: @("nmap","wireshark","burp")
# Remove: delete entries you don't want
```

### Device Exclusion

Exclude trusted devices from alerts (lines 57-61):

```powershell
$excludedMACs = @(
    "AA-BB-CC-DD-EE-FF",  # Add MAC addresses to ignore
    "11-22-33-44-55-66"
)
# Empty array = no exclusions: $excludedMACs = @()
```

## Command-Line Overrides

Run the script with custom parameters:

```powershell
# Custom interval only
.\MonitorRetea7.ps1 60

# Custom subnet only (requires placeholder for interval)
.\MonitorRetea7.ps1 300 192.168.1.0/24

# Both custom
.\MonitorRetea7.ps1 120 10.0.0.0/24
```

## Requirements

- **Windows PowerShell 5.1+** or PowerShell 7+
- **Nmap** installed (`C:\Program Files\Nmap\nmap.exe`)
- **Administrator privileges** (recommended for full ARP table access)
- **Network access** to the subnet being monitored

## Log Files

All logs are stored in `$logDir` (default: `C:\NetworkMonitor`):

| File | Purpose |
|------|---------|
| `host_status.log` | Raw connection events |
| `host_status.csv` | Structured event log |
| `host_statistics.csv` | Persistent device statistics |
| `alerts.log` | All alert notifications |
| `intrusion.log` | IDS security events |
| `threats.log` | Threat score changes |
| `critical_ports.log` | Critical port findings |
| `known_devices.csv` | Device registry with trust status |
| `execution_audit.csv` | Script execution history (never rotated) |

## Trust Status System

Edit `known_devices.csv` to set device trust levels:

- **`new`** (default) - Unknown device, triggers alerts
- **`trusted`** - Known good device, reduced alerts
- **`blocked`** - Suspicious device, triggers HIGH alerts

## Example Use Cases

### 1. Small Office Network
```powershell
$subnet = "192.168.1.0/24"
$intervalSecunde = 60
$scanMode = "fast"
```

### 2. Corporate Environment
```powershell
$subnet = "10.10.0.0/16"
$intervalSecunde = 300
$scanMode = "balanced"
$maxReconnectsInWindow = 5
```

### 3. Home Lab / Security Testing
```powershell
$subnet = "192.168.100.0/24"
$intervalSecunde = 30
$scanMode = "aggressive"
$maxIPsPerMAC = 1  # Stricter MAC monitoring
```

## Menu Options

| Option | Function |
|--------|----------|
| `1` | Start active monitoring |
| `2` | View host statistics table |
| `3` | Network activity graph |
| `4` | Live auto-refresh dashboard |
| `5` | Threat/IDS report |
| `6` | IP details with events |
| `7` | Last alerts |
| `8` | MAC address cache |
| `9` | Known devices registry |
| `A` | Execution audit log |
| `0` | Exit |

## Performance Notes

- **/24 subnet** (256 IPs) - Lightweight, runs on any modern PC
- **/23 subnet** (512 IPs) - Moderate, 4-8GB RAM recommended
- **/22 subnet** (1024 IPs) - Heavy, may need performance tuning
- **/16 subnet** (65K IPs) - Not recommended for continuous monitoring

## Security Considerations

- Run with least privilege necessary (admin not strictly required)
- Log files contain network topology information
- Consider encrypting log directories for sensitive environments
- The execution audit tracks all script runs for accountability

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Nmap not found | Install Nmap or update path in script |
| No hosts found | Check subnet configuration matches your network |
| Permission errors | Run PowerShell as Administrator |
| File lock warnings | Normal on first run, resolves automatically |
| Slow scans | Reduce interval or switch to "fast" mode |

## License

Free for personal and commercial use. Use responsibly - only monitor networks you own or have permission to monitor.
