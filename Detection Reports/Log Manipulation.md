# Detection Use Case: Log Manipulation Attempts

## Scenario Description
Attackers may try to cover their tracks by clearing event logs using built-in tools like `wevtutil`, `auditpol`, or `Clear-EventLog`.

## Objective
Detect execution of commands used to clear logs or disable auditing.

---

## Tools Used
- **SIEM:** Splunk  
- **Log Source:** Sysmon or Security Logs with CommandLine capture

---

## Event ID / Data Source Mapping

| Source            | Event ID | Description           |
|-------------------|----------|------------------------|
| Windows Security  | 4688     | Process Creation       |

---

## Detection Logic
```
EventCode=4688
| rex field=Message "Process Command Line:\s+\"?(?<Command_Line>[^\r\n]+)"
| rex field=Message "Account Name:\s+(?<Account_Name>[^\r\n]+)"
| where like(Command_Line, "%auditpol.exe%clear%")
OR like(Command_Line, "%wevtutil%cl%")
OR like(Command_Line, "%clear-eventlog%")
| table _time, Account_Name, Command_Line, ComputerName
```
---
## Triggered Alert Details
```
Field	    Value
Timestamp   2025-05-17T14:50:00+05:30
Command	    wevtutil cl Security
User	    attacker
```
---
## Sample Events
```
EventCode=4688
CommandLine: wevtutil cl Security
User: attacker
```
---

## Recommendations
Clearing logs is a strong indicator of malicious intent. Immediate triage of the host is recommended. Cross-reference with recent system changes or privilege escalation activity.

---

## Detection Status
- **Validated Using Simulated Log Clear Command**
