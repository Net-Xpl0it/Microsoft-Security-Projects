# Azure SOC Lab

A small SOC environment in Azure. Windows and Linux virtual machines send their logs to Microsoft Sentinel, I attack a host I own, and I investigate the result with KQL. The lab grows as I add events, queries and detections.

Individual project by Jayasurya D K.

## Goals
- Collect Windows Security Events and Linux Syslog into Microsoft Sentinel
- Simulate attacks against hosts I own and find them in the logs
- Write the KQL queries and detections that a SOC analyst would use
- Document every problem and fix, so the lab can be rebuilt by someone else

## Components
| Component | Role |
|-----------|------|
| Windows Server VM | Target host. Produces Windows Security Events |
| linux-machine (Debian) | Second host. Produces Linux Syslog |
| Log Analytics workspace | Stores the collected logs |
| Microsoft Sentinel | SIEM on top of the workspace: queries, incidents, analytics rules |
| Azure Monitor Agent (AMA) | Agent on each VM that sends logs |
| Data Collection Rules (DCR) | Define which logs the agent collects and where they go |
| Azure NAT Gateway | Gives the VMs outbound internet connectivity |
| Hydra | Attack tool used for the brute-force simulation |
| Atomic Red Team | Attack emulation framework used for the ghost account simulation |

## Where to look
- [Architecture and design](architecture/README.md)
- [Setup](setup/)
- [Events](events/)
- [KQL queries](kql/)
- [Detections](detections/)
- [Troubleshooting](troubleshooting.md)

## Events
| Event | Tool | Folder |
|-------|------|--------|
| RDP brute force | Hydra | [events/rdp-bruteforce](events/rdp-bruteforce/) |
| Ghost account | Atomic Red Team | [events/ghost-account](events/ghost-account/) |
