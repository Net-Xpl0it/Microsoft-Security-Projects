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
| Windows Server VMs (Win-1, Win-2) | Target hosts. Produce Windows Security Events |
| linux-machine (Debian) | Second host. Produces Linux Syslog |
| Log Analytics workspace | Stores the collected logs |
| Microsoft Sentinel | SIEM on top of the workspace: queries, incidents, analytics rules |
| Microsoft Defender portal | Hosts the custom detection rules (near real time and scheduled) that run on the workspace |
| Azure Monitor Agent (AMA) | Agent on each VM that sends logs |
| Data Collection Rules (DCR) | Define which logs the agent collects and where they go |
| Azure NAT Gateway | Gives the VMs outbound internet connectivity |
| Hydra | Attack tool used for the brute-force simulation |
| Atomic Red Team | Attack emulation framework used for the ghost account and fileless attack simulations |

## Where to look
- [Architecture and design](architecture/README.md)
- [Setup](setup/)
- [Events](events/)
- [KQL queries](kql/)
- [Detections](detections/README.md)
- [Troubleshooting](troubleshooting.md)

## Events
| Event | Tool | Where |
|-------|------|-------|
| RDP brute force | Hydra | [events/rdp-bruteforce](events/rdp-bruteforce/) |
| Ghost account | Atomic Red Team | [events/ghost-account](events/ghost-account/) |
| Fileless attack chain | Atomic Red Team | [detections/fileless-chain-rule.md](detections/fileless-chain-rule.md) (hunt and rule in one write-up) |
| SSH brute force | Manual SSH attempts from Win-1 | [detections/ssh-brute-force-rule.md](detections/ssh-brute-force-rule.md) (hunt and rule in one write-up) |

## Detections
| Detection | Platform | Severity |
|-----------|----------|----------|
| [RDP brute force](detections/README.md#rdp-brute-force---multiple-failed-logons) | Sentinel scheduled query rule | Medium |
| [Fileless attack chain](detections/fileless-chain-rule.md) | Defender custom detection (near real time) | High |
| [Local account created (ghost account)](detections/ghost-account-rule.md) | Defender custom detection (near real time) | Medium |
| [SSH brute force: repeated invalid-user attempts](detections/ssh-brute-force-rule.md) | Defender custom detection (scheduled, every hour) | Medium |
