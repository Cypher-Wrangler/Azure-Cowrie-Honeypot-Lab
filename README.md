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

# Architecture
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
