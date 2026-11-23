# Troubleshooting

## Silent log-ingestion failure
Logs were not arriving in Sentinel. Cause: the VM had no managed identity. Fix: added it.

## No outbound connectivity from a VM
Fixed with an Azure NAT Gateway.

## No data from a VM that had been deallocated for days

### Symptom
Win-2 was started after several days deallocated. The `Heartbeat` and `SecurityEvent` tables showed nothing new for it, and the last events in `SecurityEvent` were from before the shutdown.

### What I checked
Each check passed, so none of them was the cause.

| Check | How | Result |
|-------|-----|--------|
| Is the workspace the right one, and does it hold old data? | `SecurityEvent \| summarize max(TimeGenerated) by Computer` | Old events present, nothing new |
| Is the VM clock correct? | `Get-Date -Format o` on the VM | Correct UTC time |
| Are the agent processes running? | `Get-Process MonAgent*` | Four `MonAgent` processes running |
| Can the VM reach Azure on port 443? | `Test-NetConnection` to the monitor control endpoint and to a public site | `TcpTestSucceeded: True` for both |
| Is the VM associated with the DCR? | `az monitor data-collection rule association list --resource <vm id>` | Associated with the Windows security DCR |
| Does the VM have a managed identity? | `az vm show ... --query identity` | `SystemAssigned` |
| Is the agent extension healthy? | `az vm extension list` | `AzureMonitorWindowsAgent` `Succeeded` |
| Does the DCR collect the right data and send it to the workspace? | `az monitor data-collection rule show` | Security log to the workspace |
| Is the workspace capping or blocking ingestion? | `az monitor log-analytics workspace show` | No daily cap, public ingestion enabled |

### What the agent log showed
The agent log contained errors about scheduled collection tasks for times three days earlier, ending "timed out before try number 0; will not retry again". This looks like the agent discarding old tasks at startup.

### Outcome
Nothing was changed. The first heartbeat appeared about 24 minutes after the agent processes started. The log pattern is consistent with the agent catching up after a long deallocation, but I did not confirm that this was the cause.

### Lesson
After starting a VM that has been off for days, wait about 25 to 30 minutes and check the `Heartbeat` table before running an attack test, or the first test may be sent late and the detection time will be wrong.

```kusto
Heartbeat
| where TimeGenerated >= ago(2h)
| summarize LastSeen = max(TimeGenerated) by Computer
```
