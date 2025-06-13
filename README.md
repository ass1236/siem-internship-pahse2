# siem-internship-pahse2
🛡️ Wazuh Attack Detection Lab
Simulating Attacks & Detecting Them Using Wazuh, Sysmon, and Windows Logs

📌 Overview
This project simulates real-world attacks on a Windows endpoint and detects them using:
 ** Wazuh SIEM
 ** Sysmon logs
 ** Windows Event Logs
It helps demonstrate how custom and built-in rules can alert on suspicious behavior.

🧪 Lab Setup
Monitoring Tools: Wazuh server + Sysmon + Wuzuh agent
Target: Windows VM
Attacker: ubuntu Linux
Simulated Tools: Netcat, PowerShell, Hydra, Mimikatz, Nmap

🎯 Attack Scenarios
1- Suspicious File Download – Detect .zip/.rar/.7z from external IPs (Sysmon EID 11).

2- Malicious PowerShell – Encoded/obfuscated or Office-spawned PowerShell (EID 1, 4104).

3- Credential Dumping – Mimikatz simulation, detect sensitive memory access.

4- C2 Beaconing – Outbound traffic to fake C2 domain .

5- Privilege Escalation – New user added to Admins (EID 4728/4732).

6- RDP Access – Detect unauthorized login via RDP (EID 4624 + Logon Type 10).

7- Vulnerability Scanning – Nmap/Nessus scan (Sysmon ).

8- SMB File Copy – Lateral access via SMB shared folders (EID 5140).

9- Archive Execution – Run .exe from password-protected archive (EID 1, 11).

10- Reverse Shell – Detect PowerShell/Netcat reverse shell (EID 1, network events).

📊 Detection
1- Alerts shown in Wazuh Dashboard
2- Based on custom rules using Sysmon and Event logs

✅ Purpose
To help learners and defenders understand how real attacks look in logs and how to detect them using open-source tools. Great for SOC analysts, students, or blue teamers.


Reverse Shell – Detect PowerShell/Netcat reverse shell (EID 1, network events).
