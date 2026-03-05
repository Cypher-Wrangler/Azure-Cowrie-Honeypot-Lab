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
** Why it matters:** Raw text logs are hard to analyze at scale. This query converts logs into normalized fields (SrcIP) to support SOC workflows.
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
#### Output fields produced:
- Timestamp - event timestamp extracted from log line
- SrcIP, SrcPort - attacker source IP/port
- DstIP, DstPort - destination (honeyport container IP/port)
- SessionID - Cowrie session identifier (key for correlation)
- Message - cleaned message text
<img width="2757" height="873" alt="image" src="https://github.com/user-attachments/assets/ba183eb0-46eb-4e91-9f14-4dafe69ba349" />

## Threat Hunting - Detecting Cowrie "Successful SSH Login"
**Objective:**Extract and Stucture Cowrie Successfull SSH Login telemetry from 'CowrieText_CL' to be used for hunting and trigger a near real-time Azure Monitor alert 

#### KQL Query (Log Analytics)

```kql
CowrieText_CL
| where RawData has "login attempt" and RawData has "succeeded"
| extend
    EventID = "cowrie.login.success",
    Timestamp = extract(@"^(\d{4}-\d{2}-\d{2}T[^Z]+Z)", 1, RawData),
    SrcIP = extract(@"\b(\d{1,3}(\.\d{1,3}){3})\b", 1, RawData),
    Username  = extract(@"login attempt \[b'([^']+)'", 1, RawData),
    Password  = extract(@"login attempt \[b'[^']*'/b'([^']*)'", 1, RawData),
    SessionID = extract(@"\[session:\s*([a-f0-9]+)\]", 1, RawData),
    Message = extract(@"\]\s+(.*)$", 1, RawData),
    Status = iif(RawData has "succeeded", "success", "failure")
| project TimeGenerated, EventID, SrcIP, Username, SessionID, Message, Password, Status
| sort by TimeGenerated desc
```
#### Output fields produced:
- Timestamp - event timestamp extracted from log line
- SrcIP - attacker source IP
- Status - login success 
- Message - cleaned message text
<img width="2762" height="762" alt="image" src="https://github.com/user-attachments/assets/fc5b21d3-bf21-4c67-a79c-d0bfb4f7e243" />

### Create Azure Alert Rule
## 🚨 Successful SSH Login Alert Workflow

```mermaid
flowchart LR

    Attacker[Internet Source IP] --> Honeypot[Cowrie SSH Honeypot]

    Honeypot --> Logs[Local Log Files]
    Logs --> AMA[Azure Monitor Agent]
    AMA --> LAW[Log Analytics Workspace]

    LAW --> KQL[Successful Login Detection Query]
    KQL --> Alert[Azure Monitor Alert Rule]

    Alert --> Notify[Action Group Notification]
```
### Condtion
- This means an alert will be trigged if at least 1 successful login occurs:
<img width="2207" height="1171" alt="image" src="https://github.com/user-attachments/assets/3721576f-696c-464a-b6ff-8dca70421ce5" />

### Action
- Added to an existing action group with notification set to email:
<img width="3370" height="1269" alt="image" src="https://github.com/user-attachments/assets/4ee8991b-3eae-4cbb-8566-7b8b62f641cf" />

### Alert Details
- Severity set to critical
<img width="2052" height="1266" alt="image" src="https://github.com/user-attachments/assets/0ac4a917-52bf-423e-a616-263f902ca86e" />

## SSimulating login

<img width="1111" height="202" alt="image" src="https://github.com/user-attachments/assets/84c3f8bf-3504-49e6-9b06-fa2f3ea6df24" />

## Alert trigged and Action Group nofitied via email
<img width="1618" height="714" alt="image" src="https://github.com/user-attachments/assets/4e4904ba-b291-4273-b0e7-322a15651072" />

# NB: this validates the full detection pipeline from endpoint to cloud alerting

# Threat Hunting and detections
- To simulate a real-world internet-exposed system, NSG was configured with a permissive inbound rule allowing traffic from any source to the SSH honeyport. Attackers discovering and interaction with the honeypot generates telemetry for analysis in Microsoft Sentinel:
<img width="583" height="1234" alt="Screenshot 2026-02-28 091629" src="https://github.com/user-attachments/assets/f02e51c0-f704-4114-b335-fcd4a003d96f" />

## Attack Overview
Within a short time of exposing the server, the honeypot received automated SSH connection attempts from multiple external hosts:
### Top Attacking IP

``` kql
CowrieText_CL
| where RawData has "New Connection"
| extend SrcIP = extract(@"New connection: (\d+\.\d+\.\d+\.\d+):", 1, RawData)
| summarize Attempts=count () by SrcIP
| sort by Attempts desc
```
<img width="1137" height="1118" alt="Screenshot 2026-03-05 073620" src="https://github.com/user-attachments/assets/ca572bbe-a71f-4458-b509-93801fc4eac8" />

# Step 1: investigating if the attacker successfully logged in 

```kql
CowrieText_CL
| where RawData has "139.59.230.238"
| where RawData has "login attempt"
| extend
    Username = extract(@"login attempt \[(.*?)\]", 1, RawData),
    Password  = extract(@"login attempt \[b'[^']*'/b'([^']*)'", 1, RawData),
    Result = iff(RawData has "succeeded", "Success", "Fail")
| summarize Attempts=count() by Username, Password, Result
| order by Attempts desc
```
<img width="1107" height="661" alt="image" src="https://github.com/user-attachments/assets/2e014fcf-59be-4a60-b2d9-ef9881f0f6c6" />
- From the investigation the attacker is trying common default credentials.
- This confirms: the attack is a credential brute-force attempt targeting poorly secured SSH servers.
  
# Step 2: commands executed after login
Once the login succeeded, attackers will start executing commands:
- To identify system type

``` kql
CowrieText_CL
| where RawData has "139.59.230.238"
| where RawData has "CMD:"
| extend Command = extract(@"CMD:\s+(.*)", 1, RawData)
| project TimeGenerated, Command
```
<img width="1052" height="1049" alt="image" src="https://github.com/user-attachments/assets/5a19d662-6ab5-4422-8fb2-14cdd9a0878b" />

- Follow the intelligenc: During post-compromise activity, the attacker executed the command uname -a to gather system information from the honeypot. The command was mapped to MITRE ATT$CK framework:
  
| Command | MITRE Technique | Tactic|
| -------- |---------------| -------|
|uname -a | T1082-System Information Discovery | TA0007-Discovery|

# Step 3: Assessing Post-Discovery Acivity
- further investigation shows that after executing discovery command, no additional commands such as malware downloads or system exploration were observed from the attacker session.
  
``` kql
CowrieText_CL
| where RawData has "139.59.230.238"
| where RawData has "CMD:"
| extend Command = extract(@"CMD:\s+(.*)", 1, RawData)
| summarize CommandCount=count() by Command
```
<img width="1093" height="374" alt="Screenshot 2026-03-05 201540" src="https://github.com/user-attachments/assets/3b7ab194-496c-499b-95f5-fb88d93b51b0" />

# Step 3 Further OSINT
- Further OSINT was investigated on the IP using VirusTotal to determine its reputation
<img width="1521" height="1078" alt="Screenshot 2026-03-05 202136" src="https://github.com/user-attachments/assets/4cb54d2a-1d95-4a54-b374-6489b17080f2" />

## Key findings
- 9 security vendors flagged the IP as malicious
- Associated with external SSH reconnaissance activity
- Hosted on DigitalOcean cloud infrastructure

This suggests the attack was part of automated scanning campaigns targetting exposed SSH services.

