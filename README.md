# 🛡️ SOC Detection & Response with Splunk

Welcome to my Security Operations Center (SOC) project where I demonstrate my detection engineering skills using **Splunk** and **SPL (Search Processing Language)**. This repository serves as a practical showcase of real-world attack detection logic, threat simulations, and alert response strategies.

---

## 📂 Repository Structure

- 📁 Detection-Reports/ → Detailed reports for each detection logic with context & recommendations
- 📁 SPL-Queries/ → All SPL queries used for detection, threat hunting, and investigation
---

## 🚨 What This Project Demonstrates

- ✅ **Use of SPL for real-world attack detection**
- ✅ **Knowledge of common Windows Event IDs**
- ✅ **End-to-end detection logic (from query to alert)**
- ✅ **Understanding of attacker behaviors (aligned with MITRE ATT&CK)**
- ✅ **Report writing and alert documentation for SOC analysts**


---

## 📘 Sample Topics Covered

- Brute force detection and privileged login
- Suspicious PowerShell execution
- Unauthorized after-hours admin activity
- Privilege escalation and group membership changes
- Lateral movement attempts with geolocation
- Potential command & control (C2) behavior
- Log clearing and tampering activities
- And many more...

---

## 🔧 Tools & Technologies Used

- **SIEM:** Splunk
- **Scripting:** SPL (Search Processing Language)
- **OS Logs:** Windows Event Logs (via Winlogbeat or native forwarding)
- **Environment:** Simulated Lab (Kali Linux, Windows 11, pfSense)
- **Standards Followed:** MITRE ATT&CK, Windows Logging Cheat Sheet

---

## 💡 Contributions & Extensions

You can extend this project by:
- Adding detections for Linux, cloud (AWS, Azure), or endpoint logs
- Mapping each detection to a MITRE ATT&CK Technique ID
- Integrating Splunk alerts with SOAR or automated responses
- Creating dashboards for visual correlation

---

## 🙋‍♂️ About Me

I'm passionate about cybersecurity, detection engineering, and building SOC capabilities. This project is a reflection of my hands-on experience in designing, writing, and validating detections that can help blue teams defend against real-world threats.

Feel free to fork, star ⭐, or open issues for discussion!

---
