# Detection Use Case: Account Added to Privileged Group

## Scenario Description
An attacker may elevate privileges by adding users to critical groups such as 'Administrators'.

## Objective
Detect any addition of user accounts to the Administrators group.

---

## Tools Used
- **SIEM:** Splunk  
- **Log Source:** Windows Security Logs

---

## Event ID / Data Source Mapping

| Source            | Event ID | Description                      |
|-------------------|----------|----------------------------------|
| Windows Security  | 4728, 4732 | User added to privileged group   |

---

## Detection Logic
```
(EventCode=4728 OR EventCode=4732)
| where Group_Name="Administrators"
| table _time, Group_Name, Message
```
---

## Triggered Alert Details
```
Field	      Value
Timestamp	  2025-05-17T11:30:00+05:30
Group Name	Administrators
User Added	suspicious_user
```
---

## Sample Events
```
EventCode=4728
User: suspicious_user
Group: Administrators
```
---

## Recommendations
Check if user elevation was authorized. Review logs and permissions granted.

---

## Detection Status
- **Working as Expected**
