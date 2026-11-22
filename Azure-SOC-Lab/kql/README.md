# KQL queries

Every query here ran against the `SecurityEvent` table in the `law-soc` workspace. A hunt is a query I run by hand with a time range. A rule query has no time line, because the rule's own schedule sets the window.

| File | Type | What it does | Used in |
|------|------|--------------|---------|
| [failed-logons.kql](failed-logons.kql) | Hunt | Counts failed logons (4625) per account and computer | General check |
| [rdp-bruteforce-hunt.kql](rdp-bruteforce-hunt.kql) | Hunt | Finds bursts of 5 or more failed network logons from one IP in a minute | [events/rdp-bruteforce](../events/rdp-bruteforce/) |
| [rdp-bruteforce-rule.kql](rdp-bruteforce-rule.kql) | Rule | The same logic as the Sentinel scheduled rule | [detections](../detections/README.md) |
| [ghost-account-hunt.kql](ghost-account-hunt.kql) | Hunt | Measures how long a created and deleted account existed | [events/ghost-account](../events/ghost-account/) |
| [ghost-account-rule.kql](ghost-account-rule.kql) | Rule | Alerts on every account creation (4720) | [ghost-account-rule.md](../detections/ghost-account-rule.md) |
| [fileless-chain-hunt.kql](fileless-chain-hunt.kql) | Hunt | Finds the fileless attack commands on Win-1 in a five-minute window | [fileless-chain-rule.md](../detections/fileless-chain-rule.md) |
| [fileless-chain-rule.kql](fileless-chain-rule.kql) | Rule | Alerts on `mshta`, a PowerShell download cradle or a Run key write | [fileless-chain-rule.md](../detections/fileless-chain-rule.md) |
