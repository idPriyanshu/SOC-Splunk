# Brute Force Login Attempt Detection by an IP
```
EventCode=4625
| transaction Source_Network_Address maxspan=5m
| where eventcount > 4
| stats count by Source_Network_Address
```
# Suspicious Logon Times - After-Hours Admin Activity
```
EventCode=4624
| eval hour=strftime(_time, "%H")
| search (hour < 9 OR hour > 19) 
| search Account_Name IN ("Administrator", "Admin", "Domain Admins", "Backup Operators", "SYSTEM")
| stats count by _time, Account_Name, EventCode, Logon_Type
```
# Successful Login detected after Brute forcing within 5 mins
```
(EventCode=4625 OR EventCode=4624)
| transaction Source_Network_Address maxspan=5m
| where eventcount > 4 AND mvcount(EventCode)=2
| stats count by Source_Network_Address
```
# User Account Created outside Business Hours
```
EventCode=4720
| eval hour=strftime(_time, "%H")
| where hour<8 OR hour>18
| table _time, SAM_Account_Name, Account_Domain, Message
```
# Account added to Privileged Group
```
(EventCode=4728 OR EventCode=4732)
| where Group_Name="Administrators"
| table _time, Group_Name, Message
```
# Command and Control (C2) Traffic Detection
```
EventCode=3 Image="*powershell.exe"
| bin _time span=30s
| stats count by SourceIp, DestinationIp, Image
| where count > 10
```
# Lateral Movement after Brute Force by IP with Geolocation
```
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
# Suspicious File Download
```
EventCode=4103
| rex "name=\"Uri\"; value=\"(?<url>[^\"]+)\""
| rex "name=\"OutFile\"; value=\"(?<downloaded_file>[^\"]+)\""
| where isnotnull(url) AND isnotnull(downloaded_file) AND url!="" AND downloaded_file!=""
| table url, downloaded_file
```
# Log Manipulation
```
EventCode=4688
| rex field=Message "Process Command Line:\s+\"?(?<Command_Line>[^\r\n]+)"
| rex field=Message "Account Name:\s+(?<Account_Name>[^\r\n]+)"
| where like(Command_Line, "%auditpol.exe%clear%")
    OR like(Command_Line, "%wevtutil%cl%") 
    OR like(Command_Line, "%clear-eventlog%")
| table _time, Account_Name, Command_Line, ComputerName
```
