# KQL Detection Rules

Six Microsoft Sentinel scheduled analytics rules from the accompanying ARM template.

## Files
- `01-encoded-powershell-t1059-001.kql` — Encoded PowerShell execution
- `02-scheduled-task-t1053-005.kql` — Scheduled task creation
- `03-registry-run-key-t1547-001.kql` — Registry Run key persistence
- `04-repeated-failed-logons-t1110.kql` — Repeated failed logons
- `05-account-discovery-t1087.kql` — Account discovery commands
- `06-security-log-cleared-t1070-001.kql` — Security log cleared
- `sentinel-lab-analytics-rules.json` — ARM deployment template
- `detection-rules-summary.csv` — Rule metadata summary

## Validation notes
These queries were extracted from the uploaded ARM template, not independently executed against a live workspace. Validate table schemas and query behavior in your own Log Analytics workspace before deployment or production use. The schedule and lookback are configured in the ARM template; the KQL files preserve the query logic as supplied.
