# Detection Use Case: User Account Created Outside Business Hours

## Scenario Description
Creation of user accounts outside standard working hours may indicate suspicious or unauthorized activity.

## Objective
Detect user account creation events (EventCode=4720) during non-business hours.

---

## Tools Used
- **SIEM:** Splunk  
- **Log Source:** Windows Security Logs

---

## Event ID / Data Source Mapping

| Source            | Event ID | Description           |
|-------------------|----------|------------------------|
| Windows Security  | 4720     | User account created   |

---

##  Detection Logic / Query (Splunk SPL)
```
EventCode=4720
| eval hour=strftime(_time, "%H")
| where hour<8 OR hour>18
| table _time, SAM_Account_Name, Account_Domain, Message
```
---


## Triggered Alert Details
```
Field	        Value
Timestamp	    2025-05-17T07:00:00+05:30
Alert Name	  Off-Hours Account Creation
Created User	test_admin
```
---

## Sample Events
```
EventCode=4720
User: test_admin
Time: 07:00 AM
```
---

## Recommendations
Confirm if the account creation was scheduled or authorized. Unscheduled creations should be investigated immediately.

---

## Detection Status
- **Confirmed Working in Simulation**
