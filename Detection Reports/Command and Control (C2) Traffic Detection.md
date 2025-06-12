# Detection Use Case: Command and Control (C2) Traffic via PowerShell

## Description
Command and Control (C2) channels are established by adversaries to maintain persistence or exfiltrate data. PowerShell is a popular post-exploitation tool used to perform beaconing and connect to remote endpoints. This detection identifies frequent PowerShell activity, which may indicate beaconing behavior.

## Objective
Identify potential C2 traffic by detecting repeated execution of PowerShell (`powershell.exe`) making network connections within a short time window.

## Tools Used
- SIEM: Splunk
- Data Source: Windows Security Logs or Sysmon

## Event ID / Data Source Mapping

| Source           | Event ID | Description                         |
|------------------|----------|-------------------------------------|
| Windows Sysmon   | 3        | Network connection via process      |

## Detection Logic (SPL Query)
```spl
EventCode=3 Image="*powershell.exe"
| bin _time span=30s
| stats count by SourceIp, DestinationIp, Image
| where count > 10
```
## Sample Alert Details
```
Field         | Value
--------------|-------------------------
Timestamp     | 2025-05-17T13:00:00+05:30
Source IP     | 192.168.1.50
Destination IP| 198.51.100.23
Image         | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Count         | 14
```
## Sample Raw Event
```
EventCode: 3
Image: powershell.exe
SourceIp: 192.168.1.50
DestinationIp: 198.51.100.23
Time: 2025-05-17T13:00:05
```
## Analyst Notes
- Check for encoded PowerShell payloads or IEX (Invoke-Expression) usage in command line arguments.
- Investigate destination IP reputation using threat intelligence tools.
- Pivot on source host for lateral movement or privilege escalation.

## Detection Status
Tested and verified using a simulated beaconing script. Detection was triggered consistently after repeated external connection attempts from PowerShell.
