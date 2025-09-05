# 👨‍💻 SOAR Home Lab: Wazuh, Sysmon, Shuffle & TheHive 🚀

## Table of Contents  
1. [Introduction](#introduction)  
2. [Key Features](#key-features)  
3. [Network Setup](#-network-setup)  
4. [Workflow Overview](#-workflow-overview)  
5. [Key Highlights](#-key-highlights)  
6. [Prerequisites](#-prerequisites)  
7. [Network Topology](#-network-topology)  
8. [Step 1: Environment Setup](#️-step-1-environment-setup)  
9. [Step 2: Network Configuration](#-step-2-network-configuration)  
10. [Step 3: Installation (Linked Resources)](#-step-3-installation)  
11. [Step 4: TheHive Configuration](#-step-4-thehive-configuration)  
12. [Step 5: Wazuh Configuration](#-step-5-wazuh-configuration)  
13. [Step 6: Windows 10 Telemetry Configuration](#-step-6-windows-10-telemetry-configuration)  
14. [Step 7: Rule Creation in Wazuh](#-step-7-rule-creation-in-wazuh)  
15. [Step 8: Shuffle Integration & Workflow Automation](#-step-8-shuffle-integration-and-workflow-automation)  
16. [Outcome](#-outcome)  
17. [Next Steps & Future Enhancements](#-next-steps-and-future-enhancements)  
18. [Conclusion](#-conclusion)  
19. [Let’s Connect](#-lets-connect)  


---  
## 📌Introduction
Welcome to the SOC Automation Project! 🚀

In today’s world, cyber threats are everywhere – from phishing emails to credential dumping attacks using tools like Mimikatz. Security Operations Centers (SOCs) need to act fast to detect, analyze, and respond to incidents in real time.

This project demonstrates how automation can make SOC operations faster and more efficient.

We’ve built a mini SOC homelab with:  
-> Windows 10 VM as the endpoint where we generate telemetry.  
-> Wazuh Manager to detect suspicious activity.  
-> Shuffle for automation and enrichment using VirusTotal API.  
-> TheHive for case management and investigation.  




## Key Features:  
🔍 Detect suspicious activity (Mimikatz execution)  
📤 Forward alerts from Wazuh to Shuffle  
🤖 Enrich alerts with VirusTotal threat intelligence  
📧 Notify SOC analysts via email  
📂 Create cases in TheHive for investigation  

This end-to-end automation flow helps SOC teams respond faster, reduce manual effort, and focus on what matters most – stopping attacks.


---


## 🌐 Network Setup

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

<p align="center">
  <img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/Simple%20Network%20Topology%20Diagram.png?raw=true" alt="Network Topology" height="250" />
</p>



---  


## 🔄 Workflow Overview
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

<p align="center">
  <img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/Flowchart.png?raw=true" alt="Flowchart" height="400" />
</p>

---  







## 🌟 Key Highlights  
SOC Automation Project stands out because of the following features:  

-> End-to-End SOC Workflow: Covers detection, enrichment, case creation, and analyst notification seamlessly.  
-> Distributed Setup: Uses two laptops with VMs connected via bridged network to handle heavy RAM requirements efficiently.  
-> Realistic Attack Simulation: Uses Mimikatz to simulate credential dumping(T1003), replicating real-world attack scenarios.  
-> Automation with SOAR: Automatically enriches alerts using VirusTotal and creates cases in TheHive.  
-> Immediate Notifications: Sends emails to SOC analysts for faster response.  
-> Hands-On SOC Experience: Closely mimics a real SOC environment, making it perfect for learning and practice.  

<p align="center">
  <img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/Lab%20Setup.png?raw=true" alt="Network Topology" height="250" />
</p>

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



---  



## 🌐 Network Topology  

The lab uses two laptops connected through a bridged network, allowing all systems to communicate as if they are on the same LAN.  
-> Laptop 1: Hosts Ubuntu Server 1 (Wazuh Manager) – collects logs and forwards alerts.  
-> Laptop 2: Hosts Windows 10 Workstation, Ubuntu Server 2 (TheHive), and Shuffle – generates   telemetry, enriches alerts, and creates cases.  

<p align="center">
  <img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/SOC%20home%20lab%20diagram%20%20(1).png?raw=true" alt="Network Topology" height="250" />
</p>


---  

## 🛠️ Step 1: Environment Setup  
To start the project, I set up the virtual environment across two laptops:  

-> Installed VMware Workstation (VirtualBox can also be used).  
-> Created three VMs: Windows 10 Workstation, Ubuntu Server 1 (Wazuh Manager), and Ubuntu Server 2 (TheHive).  
-> Allocated resources: Windows 10 → 5–6 GB RAM, Wazuh → 4 GB RAM, TheHive → 6–8 GB RAM.  
-> Distributed load across two laptops (Laptop 1 hosted Wazuh Manager, Laptop 2 hosted Windows 10, TheHive, and Shuffle).  
-> Installed operating systems and set Bridged Network mode so all machines could communicate.  

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntuServer_thehive_network_configuration.png?raw=true" alt="Network Topology" height="250" />
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntuServer_wazuh_network_configuration.png?raw=true" alt="Network Topology" height="250" />
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/windows10_workstation_network_configuration.png?raw=true" alt="Network Topology" height="250" />
</p>

---  

## 🌐 Step 2: Network Configuration  
After setting up the environment, I configured the network for all virtual machines to ensure proper communication:  

-> Ubuntu Server 1 (Wazuh Manager): 10.53.159.19  
-> Ubuntu Server 2 (TheHive + Shuffle): 10.53.159.152  
-> Windows 10 Workstation: 10.53.159.106  

All machines were set to Bridged Network Mode so they could communicate with each other and with the host systems seamlessly.  




---  


## 🛠️ Step 3: Installation  

For this project, the following tools were installed:  
-> Sysmon on the Windows 10 VM (for detailed telemetry)  
-> Wazuh SIEM on Ubuntu Server (for centralized log collection & monitoring)  
-> TheHive on Ubuntu Server (for alert management & case handling)  

📺 Reference Guide:  

    🔗 https://www.youtube.com/watch?v=YxpUx0czgx4&list=PLG6KGSNK4PuBWmX9NykU0wnWamjxdKhDJ&index=7&t=1258s
This video includes:  
-> Sysmon installation steps  
-> Wazuh manager, dashboard installation  
-> TheHive installation and service setup  

---  




## 🧩 Step 4: TheHive Configuration  

In this step, TheHive was fully configured by modifying its dependencies (Cassandra, Elasticsearch) and its own configuration file.  
Below are the detailed commands and configuration changes used during the setup.  
 
### 🛠️ 4.1 Cassandra Configuration  

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

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/cassandra_status.png?raw=true" alt="Network Topology" height="250" />
</p>


### 📡 4.2 Elasticsearch Configuration  
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

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/elasticsearch_status.png?raw=true" alt="Network Topology" height="250" />
</p>


### 📂 4.3 TheHive Directory Permissions  
Check directory ownership:  

    ls -la /opt/thp
If access is restricted to root, grant permissions to TheHive user:  
    chown -R thehive:thehive /opt/thp  
    
    ls -la /opt/thp
✅ Expected Result: Ownership should now belong to thehive:thehive.  


### ⚙️ 4.4 TheHive Application Configuration  
Open TheHive configuration file:  

    nano /etc/thehive/application.conf
🔧 Changes made:  
-> Ensured hostname is set to localhost  

Then start, enable, and check TheHive:  

    systemctl start thehive
    systemctl enable thehive
    systemctl status thehive
✅ Expected Result: TheHive should now be active (running).  

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/thehive_status.png?raw=true" alt="Network Topology" height="250" />
</p>

Also re-check Cassandra & Elasticsearch status to ensure everything is running:  

    systemctl status cassandra.service
    systemctl status elasticsearch.service


### 🌐 4.5 Access TheHive UI  
Open a browser and navigate to:  

    http://localhost:9000
Login with default credentials:  

    Username: admin@admin.local
    Password: secret

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_thehive/thehive_login.png?raw=true" height="250" />
</p>


### 🧠 4.6 JVM Options Update  
Edit JVM options to adjust memory allocation:  

    nano /etc/elasticsearch/jvm.options.d/jvm.options
    -Dlog4j2.formatMsgNoLookups=true
    -Xms2g
    -Xmx2g
✅ At this stage, TheHive, Cassandra, and Elasticsearch should all be running and accessible, completing the configuration process.  



---  

## 🖥️ Step 5: Wazuh Configuration  
In this step, Wazuh was configured and the Windows 10 workstation was added as an agent so that its telemetry could be collected and analyzed.  

### 🌐 5.1 Access Wazuh Dashboard  
1.Open a browser and navigate to the Wazuh Dashboard using the Ubuntu server IP address:  

    https://10.53.159.19
2.Log in using the indexer username and API password (retrieved later from the server).  
3.You should see Total Agents = 0, indicating no agents are yet connected.  

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_wazuh/wazuh.png?raw=true" height="250" />
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_wazuh/wazuh_no_agent_connected.png?raw=true" height="250" />
</p>


### 📂 5.2 Retrieve Wazuh Installation Details  
On the Wazuh Ubuntu Server:  

    sudo su
    ls
You should see:  

    snap    wazuh-install-files.tar    wazuh-install.sh
Extract the files:  

    tar -xvf wazuh-install-files.tar
    cd wazuh-install-files
    ls
    cat wazuh-password.txt
From wazuh-password.txt, retrieve the API user password for Wazuh.  
This password is used to log into the dashboard and manage agents.  


### ➕ 5.3 Add a New Agent in Wazuh  
1.Go to Wazuh Dashboard → Add Agent  
2.Select Windows as the operating system  
3.Enter:  

    Server Address: 10.53.159.19
    Agent Name: e.g., Win10-Workstation
4.Copy the installation command provided on the page.  
📌 Dummy Command Example:  

        Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.x.x.msi /q WAZUH_MANAGER="10.53.159.19" WAZUH_REGISTRATION_SERVER="10.53.159.19" WAZUH_AGENT_NAME="Win10-Workstation"




### 💻 5.4 Install Wazuh Agent on Windows Workstation  
On the Windows 10 VM:  
1.Open PowerShell as Administrator  
2.Paste the installation command you copied earlier (or dummy one above).  
3.After installation, start the Wazuh agent service:  

    net start wazuhsvc
4.Verify the agent is running:  
-> Open services.msc  
-> Locate Wazuh Agent  
-> Ensure status = Running  

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/windows10/Services.png?raw=true" height="250" />
</p>

### 📊 5.5 Verify Connection on Wazuh Dashboard  
Go back to the Wazuh dashboard and refresh the page.  
You should now see:  
-> Total Agents = 1  
-> Active Agents = 1  
-> Your Windows 10 VM listed as an active agent.  

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_wazuh/wazuh_agent_connected.png?raw=true" height="250" />
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_wazuh/mimikatz_search_in_wazuh_archives.png?raw=true" height="250" />
</p>

✅ Result: Windows 10 telemetry is now being forwarded to Wazuh, and you can view logs/events in real-time from the workstation.  

---  

## 🔍 Step 6: Windows 10 Telemetry Configuration  
In this step, we configure Windows 10 telemetry to send Sysmon and event logs to the Wazuh Manager for analysis.  

### 1️⃣ Editing ossec.conf File 📄  
-> Navigate to:  

    C:\Program Files (x86)\ossec-agent
-> Locate the ossec.conf file.  
-> 🛠️ Open Notepad as Administrator and edit ossec.conf.  
✅ In the <client> tag, verify the <server> address points to the Wazuh Manager’s IP:  

    <server>
      <address>10.53.159.19</address>
    </server>
<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/windows10/ossec_conf1.png?raw=true" height="250" />
</p>

### 2️⃣ Configuring Log Collection 📝  
-> Locate <localfile> tags and remove defaults:  

    <localfile>
      <location>Application</location>
    </localfile>
    
    <localfile>
      <location>Security</location>
    </localfile>
🆕 Replace with Sysmon Operational Log:  

    <localfile>
      <location>Microsoft-Windows-Sysmon/Operational</location>
      <log_format>eventchannel</log_format>
    </localfile>

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/windows10/ossec_conf2.png?raw=true" height="250" />
</p>

### 3️⃣ Creating Backup 💾  
-> Before editing, create a backup:  

    copy "C:\Program Files (x86)\ossec-agent\ossec.conf" "C:\Program Files (x86)\ossec-agent\ossec-backup.conf"
-> 🛡️ This allows you to restore the original config if needed.  

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/windows10/ossec.png?raw=true" height="250" />
</p>

### 4️⃣ Restarting Wazuh Agent 🔄  
-> Open Services → find Wazuh Agent → click Restart.  
✅ This applies the new configuration.  

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/windows10/Services.png?raw=true" height="250" />
</p>


### 5️⃣ Preparing Windows 10 for Testing 🖱️  
-> Open Windows Security → Virus & Threat Protection.  
🛑 Temporarily disable Real-Time Protection so Mimikatz is not blocked.  
-> In Chrome → Settings → Privacy & Security, select No Protection (just for downloading).  
-> ⬇️ Download Mimikatz from GentilKiwi/Mimikatz GitHub  
-> 📂 Extract the ZIP file.  

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/windows10/WindowsSecurity.png?raw=true" height="250" />
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/windows10/Mimikatz_download.png?raw=true" height="250" />
</p>

### 6️⃣ Running Mimikatz ⚡  
-> Open PowerShell as Administrator and run:  

    cd C:\Users\<User>\Downloads\mimikatz_trunk\x64
    .\mimikatz.exe
-> ✅ You should now see the Mimikatz console.  

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/windows10/WindowsSecurity.png?raw=true" height="250" />
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/windows10/Mimikatz_download.png?raw=true" height="250" />
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/windows10/Mimikatz.png?raw=true" height="250" />
</p>

### 7️⃣ Enabling Full Logging on Wazuh Manager 🖥️  
Run these commands on Ubuntu server:  

    # Create backup
    cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec-backup.conf
    
    # Edit configuration
    nano /var/ossec/etc/ossec.conf
Change inside <global>:  

    <logall>yes</logall>
    <logall_json>yes</logall_json>

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_wazuh/webhook_integration_with_shuffle.png?raw=true" height="250" />
</p>
    
💾 Save → restart Wazuh:  

    systemctl restart wazuh-manager.service


### 8️⃣ Configuring Filebeat for Archives 📊  
Edit Filebeat config:  

    nano /etc/filebeat/filebeat.yml
Change:  

    archives:
      enabled: false
to:  

    archives:
      enabled: true

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_wazuh/filebeat.png?raw=true" height="250" />
</p>
  
Restart Filebeat:  

    systemctl restart filebeat


### 9️⃣ Creating Index Pattern in Wazuh Dashboard 🖼️  
-> Go to Stack Management → Index Patterns.  
-> ➕ Create new pattern: wazuh-archives-*  
-> Select @timestamp as time field.  
-> ✅ Save and switch to this pattern.  

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_wazuh/stack_management.png?raw=true" height="250" />
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_wazuh/index_pattern.png?raw=true" height="250" />
</p>

### 🔟 Viewing Mimikatz Logs 👀  
Run Mimikatz again on Windows 10.  
On Wazuh Manager:  

    cd /var/ossec/logs/archives
    cat archives.json | grep -i mimikatz
✅ You should now see logs showing Mimikatz activity.  


### 1️⃣1️⃣ Focus on Original File Name 🔎  
Inside the logs, look for:  

    "data.win.eventdata.originalFileName": "mimikatz.exe"
💡 Tip: This field is more reliable than image because attackers may rename the executable.  

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_wazuh/original_final_name.png?raw=true" height="250" />
</p>

---  

## 📜 Step 7: Rule Creation in Wazuh  
In this step, we create a custom rule in Wazuh to detect Mimikatz execution based on Sysmon logs.  

### 1️⃣ Navigating to Rules Section 🧭  
-> Open Wazuh Dashboard.  
-> Click the dropdown button (⏬) next to “Wazuh” → Sidebar Opens.  
-> Navigate to: Management → Rules.  


### 2️⃣ Finding the Target Rule 🔍  
-> Click Manage Rules Files.  
-> Search for Sysmon Rules → locate:  

    0800-sysmon_no_id_1.xml
-> Reason for choosing Event ID 1 🧠:  
   Sysmon Event ID 1 corresponds to Process Creation Events.  
   ✅ This means every time a new process/executable starts, Sysmon generates an Event ID 1 log.  
    This makes it ideal for catching tools like Mimikatz as soon as they run.  

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_wazuh/sysmon_rules.png?raw=true" height="250" />
</p>



### 3️⃣ Creating Custom Rule File ✏️  
-> Open the rule file → Copy the <rule> block from sysmon_no_id_1.xml.  
-> Go back → Click Custom Rules → Edit local_rules.xml file.  

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_wazuh/0800-sysmon_id.png?raw=true" height="250" />
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_wazuh/custom_rules.png?raw=true" height="250" />
</p>




### 4️⃣Paste and Modifying the Rule 🛠️
Inside local_rules.xml paste the copied rule below the existing rule:
-> 🔢 Change Rule ID → must be greater than 100001.  
    Example:  

    <rule id="100002" level="15">
-> 🔝 Set Level: 15 (highest severity).  
-> 🏷️ Group Tag: Keep sysmon_event1 (since we are targeting process creation).  
-> 🎯 Field Tag: Change from parentImage to originalFileName and update pattern:  

    <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
-> 🗑️ Remove <options> tag (not required).  
-> 📝 Description Tag:  

    <description>Mimikatz usage detected</description>
-> 🧠 MITRE Technique Tag: Change to T1003 (Credential Dumping).  

    <mitre> <id>T1003</id> </mitre>

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_wazuh/local_rules.xml.png?raw=true" height="250" />
</p>

### 5️⃣ Saving and Restarting Wazuh 🔄  
-> Save changes.  
-> Click Restart on the Wazuh Dashboard to apply the rule.  

6️⃣ Testing the Rule 🧪  
-> On Windows 10 VM → Run Mimikatz again:  

    cd C:\Users\<User>\Downloads\mimikatz_trunk\x64
    .\mimikatz.exe
-> ✅ Result:  

    Wazuh Dashboard shows a new alert:
    “Mimikatz usage detected” 🔥

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_wazuh/mimikatz_usage_detected_in_dashboard.png?raw=true" height="250" />
</p>

---  


## 🔄 Step 8: Shuffle Integration and Workflow Automation   
In this step, we integrate Shuffle with Wazuh, VirusTotal, and TheHive, and configure automated workflows that send email alerts to SOC analysts when malicious activity (Mimikatz usage) is detected.  

### 8.1 – Shuffle Setup 🖥️  
-> Open Shuffle on the Ubuntu VM where Hive is installed (instead of using host machine) — this ensures proper connectivity since cloud runtime was not able to connect with Hive.  
-> Log in to Shuffle ➝ Navigate to Admin tab ➝ Select Locations.  
-> Click Add Location ➝ Name: local-env ➝ Type: on-prem ➝ Save.  
-> Click Make Default ✅.  
<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/shuffle/shuffle_admin.png?raw=true" height="250" />
</p>
-> Go back to Workflows ➝ Create a new workflow:  

    Name: SOC Automation Project
    Description: My SOC Project
    Select any use case ➝ Done.
<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/shuffle/shuffle_create_workflow.png?raw=true" height="250" />
</p>
-> A new canvas opens with the ChangeMe icon.  
<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/shuffle/shuffle_changeme.png?raw=true" height="250" />
</p>


### 8.2 – Webhook Setup 🔗  
-> Click on Triggers ➝ Drag and drop Webhook onto the canvas.  
-> It auto-connects to ChangeMe.  
-> Configure:  

    Name: Wazuh.alerts
    Copy the Webhook URI.
-> Save ✅.  
<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/shuffle/shuffle_webhook_added.png?raw=true" height="250" />
</p>

### 8.3 – Connect Wazuh to Shuffle 🛜  
On Ubuntu server:  

    sudo nano /var/ossec/etc/ossec.conf
-> Under <global> tag, add:  

    <integration>
      <name>custom-integration</name>
      <hook_url>PASTE_WEBHOOK_URL_HERE</hook_url>
      <rule_id>100002</rule_id>
      <alert_format>json</alert_format>
    </integration>

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_wazuh/webhook_integration_with_shuffle.png?raw=true" height="250" />
</p>

-> Save & restart:  

    sudo systemctl restart wazuh-manager.service
    sudo systemctl status wazuh-manager.service
-> Confirm Wazuh manager is running.  

### 8.4 – Triggering the Workflow 🚀  
-> On Windows 10 VM ➝ Run Mimikatz to generate alerts.  
-> On Shuffle ➝ Click Webhook Start ➝ Click Run (person icon).  
-> Confirm Wazuh logs are reaching Shuffle ➝ Expand execution arguments to inspect raw logs.  

### 8.5 – Parse SHA-256 Hash (Regex) 🔍  
Reason for Parsing Hash:  
We parse the hash to isolate only the SHA-256 value from the alert data. If we send unparsed data to VirusTotal, it may contain extra fields (like sha1= or md5=), causing incorrect or failed enrichment. Regex ensures we send a clean, valid hash to VirusTotal.  
-> Change ChangeMe action ➝ Select Regex Capture Group.  
-> Input: Input.data: $exec.text.win.evendata.hashes  
Regex:  

    sha256=([0-9a-fA-F]{64})
-> Rename action to sha256_regex.  
-> Save & rerun workflow ➝ Confirm parsed hashes in execution output ✅.  
<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/shuffle/shuffle_virustotal_config.png?raw=true" height="250" />
</p>


### 8.6 – VirusTotal Integration 🧪  
-> In Shuffle ➝ Apps ➝ Search & drag VirusTotal ➝ Connect sha256_regex ➝ Configure:  

    Action: Get a hash report
    Authentication:
    -> Name: auth_virustotal
    -> API Key: (paste from VirusTotal account)
    -> API URL: https://www.virustotal.com
    Hash Parameter: Select runtime argument ➝ groups ➝ list.
-> Save & rerun ➝ Verify VirusTotal status = Success.  

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/shuffle/shuffle_authenticate_virustotal.png?raw=true" height="250" />
</p>

-> Inspect output ➝ Confirm field last_analysis_stats.malicious returns a value like 67.  


### 8.7 – Configure TheHive 🐝  
In thehive I created a new organization and under the new Organization I created 2 users.  
Why I created 2 users?  
We created two users (one analyst, one service account) to follow principle of least privilege:  
-> Analyst User: For human interaction with Hive UI and case management.  
-> Service Account (Shuffle): For API integration and automation — given only necessary permissions.  

Steps:  
-> Log into Hive ➝ Create new Organization (SOCProject).  
<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_thehive/thehive_organization.png?raw=true" height="250" />
</p>

    Add:
    User 1:
    Type: Normal
    Login: soc@test.com
    Role: Analyst
    
    User 2 (Service):
    Type: Service
    Login: shuffle@test.com
    Role: Analyst
    Generate API key ➝ Copy & store securely.

<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_thehive/thehive_soc_project_organization.png?raw=true" height="250" />
</p>

-> Logout ➝ Test login with Analyst user to confirm.  
<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_thehive/thehive_login_with_user.png?raw=true" height="250" />
</p>

In Shuffle:  
-> Authenticate Hive ➝ Paste API key + Hive IP ➝ Submit.  
<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_thehive/thehive_login_with_user.png?raw=true" height="250" />
</p>
-> Find Actions: Create Alert.  
-> Configure parameters:  

    Description:
    Mimikatz detected on host ➕ runtime arg (host) ➕ from user ➕ runtime arg (user)
    Source: Wazuh
    SourceRef: "rule:100002"
    Severity: 2
    Status: new
    Tags: ["T1003"]
    Summary: Mimikatz activity detected on host <hostname>
    Process ID & Command line: Select from runtime args.
    TLP: 2
    Type: internal
-> Save & rerun ➝ Confirm Hive alert is generated ✅.  
<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_thehive/thehive_alert.png?raw=true" height="250" />
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/ubuntu_thehive/thehive_alert_details.png?raw=true" height="250" />
</p>

### 8.8 – Email Notification Setup 📧  
-> In Shuffle ➝ Apps ➝ Search for Email ➝ Drag & connect VirusTotal to the Email.  
<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/shuffle/shuffle_email.png?raw=true" height="250" />
</p>
-> Configure:  

    Recipient: Analyst mail address
    Subject: Mimikatz Detected
    Body: Include runtime arguments for:
    Time : Runtime Argument(utcTime)
    Host : Runtime Argument(computer)
    Title : Runtime Argument(title)
    Severity : Runtime Argument(severity)
-> Save & rerun ➝ Check your inbox ➝ Confirm alert email received ✅.  
<p align="center">
<img src="https://github.com/Pranav-Kale/SOAR-Automation-Home-Lab/blob/main/Screenshots/analyst_received_email.png?raw=true" height="250" />
</p>

---  

## 🎯 Outcome  
After completing all steps, we successfully:  
-> ✅ Detected Mimikatz Execution: Our custom Sysmon rule (ID 100002) flagged Mimikatz execution in real-time.  
-> 📢 Alert Generated in Wazuh: The alert was automatically triggered in Wazuh with severity 2 (Medium) and proper tagging T1003 (Credential Dumping).  
-> 🗂️ Case Created in TheHive: TheHive automatically created a case with detailed description, process ID, host, and command line arguments for analyst review.  
-> 📧 Email Notification: SOC Analyst received a live email with all relevant details including time, host, and command line.  
-> 🤖 Automated Workflow: Full end-to-end SOAR workflow was validated from detection → alerting → case creation → email notification.  

---

## 🚀 Next Step and Future Enhancements  
🔜 Short Term Plans:  
-> 🛡️ Add more detection rules for other ATT&CK techniques (e.g., keylogging, lateral movement). 
-> 🌐 Integrate Threat Intelligence feeds into TheHive for enrichment and context.  
-> 📊 Configure dashboards to visualize alerts over time and severity trends.  
🌟 Long Term Enhancements:  
-> 🔒 Enable automatic response actions like isolating compromised hosts or disabling accounts.  
-> 🤖 Implement AI/ML models to prioritize alerts and detect anomalies faster.  
-> 🔗 Add integrations with SIEMs (Splunk, ELK) and EDR tools for unified monitoring.  
-> 📁 Maintain rule baselines and version control (GitHub repo) for better team collaboration.  

---

## 🏁 Conclusion  
This project successfully demonstrated end-to-end SOC automation using Wazuh + Sysmon + TheHive + Shuffle.  
With this setup:  
-> ⏱️ We can now detect attacks like Mimikatz in near real-time.  
-> 🧑‍💻 Automatically create incidents and notify analysts.  
-> 📈 Build a scalable workflow that grows with new detection rules and playbooks.  
✨ Impact: This solution significantly reduces MTTD (Mean Time to Detect) and MTTR (Mean Time to Respond), allowing analysts to focus on real threats rather than repetitive tasks.  

---  

## 📌 Let’s Connect  
💼 [LinkedIn](https://www.linkedin.com/in/pranavkale1124/)  
🖥️ [GitHub](https://github.com/Pranav-Kale)  
