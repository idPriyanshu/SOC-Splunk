# Detection Use Case: Brute Force Login Attempt Detection by an IP

## Scenario Description
Multiple failed login attempts from the same source IP over a short time frame may indicate brute-force attacks.

## Objective
Detect brute force login attempts from a single IP within a 5-minute window.

---

## Tools Used
- **SIEM:** Splunk  
- **Log Source:** Windows Security Logs  
- **Forwarder:** Winlogbeat

---

## Event ID / Data Source Mapping

| Source            | Event ID | Description           |
|-------------------|----------|------------------------|
| Windows Security  | 4625     | Failed login attempt   |

---

## Detection Logic / Query (Splunk SPL)
```
EventCode=4625
| transaction Source_Network_Address maxspan=5m
| where eventcount > 4
| stats count by Source_Network_Address
```
---

## Triggered Alert Details
```
Field	      Value
Timestamp	  2025-05-17T22:23:40+05:30
Alert Name	Brute Force Login Attempt Detection by an IP
Event ID	  4625
Source IP	  192.168.1.100
```

---

## Sample Events
```
EventCode=4625
Account_Name=admin
Failure Reason: Bad password
Source IP: 192.168.1.100
```
---

## Recommendations
Check firewall logs and correlate with user reports for possible unauthorized access. Consider blocking the source IP after repeated detection.

---

## Detection Status
- **Successfully Triggered and Validated in Test Lab**
