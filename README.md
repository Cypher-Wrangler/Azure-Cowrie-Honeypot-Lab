## Azure-Cowrie-Honeypot-Lab
Deploying a Cowrie SSH honeypot on Microsoft Azure to capture real-world attacker behavior, analyze telemetry, and generate threat intelligence aligned with MITRE ATT&CK.

# Overview
This project demonstrates:
- Azure VM provisioning
- Secure baseline hardening
- Cowrie SSH honeypot and deployment
- Log analysis
- Basic threat hunting
- MITRE ATT&CK mapping

# ⛏️Tools used
- Cloud Provider: Microsoft Azure
- OS: Ubuntu
- Containerization: Docker
- Honeypot: Cowrie
- Network Filtering: Azure NSG
- Log Analysis: Cowrie logs

# ☑️Architecture
``` mermaid
flowchart TD
    A[Internet] -->|Port 2222 Open| B[Azure Public IP]
    B --> C[Azure Network Security Group]
    C -->|22 Restricted| D[Ubuntu 22.04 VM]
    C -->|2222 Open| D
    D --> E[Docker Engine]
    E --> F[Cowrie Honeypot]
    F --> G[Log Files<br/>cowrie.log + cowrie.json]
```
# Deployment
NB: Initial deployment was performed via Azure Portal UI for rapid prototyping
</> Markdown
1. Install ubuntu vm on Azure
2. Deployed Cowrie on docker:
- To isolate honeypot environment
- Prevent host compromise

# Configuring Azure resource collection
</> Markdown
1.Configured Azure NSG:
<img width="1684" height="1249" alt="Screenshot 2026-02-16 104000" src="https://github.com/user-attachments/assets/3c1bb588-b392-4096-bb8b-724a3f5cb3cd" />
- Opened Port 2222 for honeypot deception
- Allowed SSH (Port 22) from only one source IP
Security principle applied: Minimize attack surface while exposing controlled deception services.

2. Log Analytic Workplace Configuration:
To store security logs:
- VM telemetry
- Custom logs (cowrie.log)
- Performance metrics
<img width="3052" height="642" alt="image" src="https://github.com/user-attachments/assets/d65ac39c-968a-48df-a5c8-ac2e7fd7f160" />
The following resource was connected:
- Azure VM hosting Cowrie Honeypot
- Azure Monitor Agent installed (Linux)
- Data Collection Rule as shown later on.

Tables used:
<img width="3077" height="1079" alt="image" src="https://github.com/user-attachments/assets/9c881bf1-c184-450e-87f6-030f6e563f07" />
- Syslog for linux authentication logs
- Hearbeat for VM health monitoring
- Perf for CPU & mmemory monitoring
- CowrieText_CL for Honeypot attack telemetry


3. Data Collection Endpoint:
 - To grab data from linux machine
 - Azure moonitor Agent installed
 - Connected to Log Analytics Workspace
 - Syslog enabled
 - Custom log ingestion configured (Cowrie.log)
<img width="2972" height="369" alt="Screenshot 2026-02-24 155858" src="https://github.com/user-attachments/assets/a77a8f08-488a-48bc-9b5a-98f084c1080e" />

4. Azure Data Collection Rules:
The Data Collection Rule was configured via Azure Portal to collect telemetry from the Endpoint hosting the Cowrie honeypot
Define what logs are collected:
  - From which resource
  - Where the logs are sent (Log Analytic workplace)
  - What table they land in ( CowrieText_CL)
  <img width="3305" height="834" alt="image" src="https://github.com/user-attachments/assets/e65e5d00-dc44-4055-84a9-0a1e4d7baf0b" />

##  Threat Hunting -  Parsing Cowrie "New Connection" Events
**Objective:** Extract and Structure Cowrie SSH connection telemetry from 'CowrieText_CL' to be used for hunting.
** Why it matters.** Raw text logs are hard to analyze at scale. This query converts lpgs into normalized fields (SrcIP) to support SOC workflows.
- Simulating from attacker machine,Logging in with privilege access(root):
<img width="1091" height="410" alt="image" src="https://github.com/user-attachments/assets/b4e528a7-7dfd-41a7-8e2b-a0cd3b9cdb6b" />
### KQL Query (Log Analytics)
```kql
CowrieText_CL
| where RawData has "New connection:"
| extend 
    Message   = extract(@"\]\s+(.*)$", 1, RawData),
    Timestamp = extract(@"^(\d{4}-\d{2}-\d{2}T[^Z]+Z)", 1, RawData),
    SrcIP = extract(@"New connection: (\d+\.\d+\.\d+\.\d+):\d+", 1, RawData),
    SrcPort = extract(@"New connection: \d+\.\d+\.\d+\.\d+:(\d+)", 1, RawData),
    DstIP = extract(@"\((\d+\.\d+\.\d+\.\d+):", 1, RawData),
    DstPort = extract(@"\(\d+\.\d+\.\d+\.\d+:(\d+)", 1, RawData),
    SessionID = extract(@"\[session: ([a-f0-9]+)\]", 1, RawData)
| project-away RawData
```
Output fields produced:
- Timestamp - event timestamp extracted from log line
- SrcIP, SrcPort - attacker source IP/port
- DstIP, DstPort - destination (honeyport container IP/port)
- SessionID - Cowrie session identifier (key for correlation)
- Message - cleaned message text
<img width="2757" height="873" alt="image" src="https://github.com/user-attachments/assets/ba183eb0-46eb-4e91-9f14-4dafe69ba349" />

5.


6. 
7. 
8.
9. - 
- 
>
