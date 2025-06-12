# Detection Use Case: Lateral Movement after Brute Force by IP with Geolocation

## Description
This detection identifies brute-force attacks followed by successful logins from external IP addresses not on an allowlisted internal IP range. It enhances traditional brute-force detection by adding geolocation context, helping to flag potential lateral movement or account compromise originating from unusual regions.

## Objective
Detect IP addresses that generated more than 4 failed logins (Event ID 4625) followed by at least one successful login (Event ID 4624) within 5 minutes, and geolocate such IPs that are not in the internal IP allowlist.

## Tools Used
- SIEM: Splunk
- Data Sources:
  - Windows Security Event Logs
  - Lookup File: `standard_internal_ips.csv` (allowlist of internal IPs)
  - Geolocation Database: Used via `iplocation` command in Splunk

## Event ID / Data Source Mapping

| Source             | Event ID | Description                  |
|--------------------|----------|------------------------------|
| Windows Security   | 4625     | Failed login attempt         |
| Windows Security   | 4624     | Successful login             |

## Detection Logic (SPL Query)
```spl
(EventCode=4625 OR EventCode=4624)
| rename Source_Network_Address as IpAddress 
| rex field=Message "Logon Type:\s+(?<LogonType>\d+)"
| search LogonType=3
| search NOT [ | inputlookup standard_internal_ips.csv | fields IpAddress ]
| eval Failed=if(EventCode=4625, 1, 0)
| eval Success=if(EventCode=4624, 1, 0)
| stats earliest(_time) as firstSeen latest(_time) as lastSeen sum(Failed) as FailedAttempts sum(Success) as Successes by IpAddress
| where FailedAttempts > 4 AND Successes > 0 AND lastSeen - firstSeen < 300
| iplocation IpAddress
| table IpAddress, City, Country, Region, FailedAttempts, Successes
```
## Sample Alert Details
```
Field            | Value
-----------------|---------------------------
Timestamp Range  | 2025-05-17T11:21:00 - 11:25:00
IpAddress        | 203.0.113.42
City             | New York
Country          | United States
Region           | New York
FailedAttempts   | 7
Successes        | 1
```
## Sample Raw Event Snippets
- Failed Login Event (4625)
```
EventCode: 4625
Logon Type: 3
Source Network Address: 203.0.113.42
Account Name: admin
Failure Reason: Unknown user name or bad password
```
- Successful Login Event (4624)
```
EventCode: 4624
Logon Type: 3
Source Network Address: 203.0.113.42
Account Name: admin
Authentication Package: NTLM
```
## Analyst Notes
- Investigate IP reputation and geo anomalies. Is the IP from a region that usually does not access your systems?
- Review whether the account accessed sensitive shares, lateral services, or domain controllers.
- Cross-reference with VPN logs or asset inventories to verify if this IP is truly external.

## Detection Status
Tested and successfully triggered during brute-force simulation followed by a legitimate credential login from an external IP address. Geolocation was correctly resolved for suspicious IPs outside the internal IP allowlist.
