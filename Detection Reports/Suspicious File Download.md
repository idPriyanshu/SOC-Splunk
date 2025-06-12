# Detection Use Case: Suspicious File Download via PowerShell

## Scenario Description
Adversaries may use PowerShell to download and execute malicious payloads from the internet.

## Objective
Detect suspicious file downloads via PowerShell, especially with the OutFile and URI parameters.

---

## Tools Used
- **SIEM:** Splunk  
- **Log Source:** PowerShell Operational Logs

---

## Event ID / Data Source Mapping

| Source                | Event ID | Description             |
|------------------------|----------|------------------------|
| PowerShell Operational | 4103     | Command line execution |

---

## Detection Logic
```
EventCode=4103
| rex "name=\"Uri\"; value=\"(?<url>[^\"]+)\""
| rex "name=\"OutFile\"; value=\"(?<downloaded_file>[^\"]+)\""
| where isnotnull(url) AND isnotnull(downloaded_file) AND url!="" AND downloaded_file!=""
| table url, downloaded_file
```
---

## Triggered Alert Details
```
Field	          Value
Timestamp	      2025-05-17T12:00:00+05:30
URL	            http://malicious.example.com/malware.exe
Downloaded File	C:\Users\Public\malware.exe
```
---

## Sample Events
```
EventCode=4103
Uri: http://malicious.example.com/malware.exe
OutFile: C:\Users\Public\malware.exe
```
---

## Analyst Notes / Recommendations
Confirm whether this download was part of a legitimate script or malicious download attempt.

---

## Detection Status
- **Successfully Detected During Controlled Download Test**
