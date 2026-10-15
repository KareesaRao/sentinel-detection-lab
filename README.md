# sentinel-detection-lab
Detection engineering lab with Microsoft Sentinel and MITRE ATT&amp;CK


### Example investigation: encoded PowerShell execution

| Field | Detail |
|---|---|
| Incident | Lab - Encoded PowerShell execution (T1059.001) |
| Severity | High |
| Tactic / technique | Execution / T1059.001 (PowerShell) |
| Detection | Scheduled analytics rule in Microsoft Sentinel |
| Data source | Sysmon Event ID 1 (process creation) |
| Host | WIN-NQUS8CJOBGD |
| First activity | Oct 15, 2026, 2:44 PM ET (18:44 UTC) |
| Alert generated | Oct 15, 2026, 2:55 PM ET (about 12 minutes later) |
| Status | [update after classifying] |

**What happened:** I ran PowerShell with an encoded command on the lab
server to simulate T1059.001. Sysmon logged the process creation, the
Sentinel rule matched the encoded-command flag in the command line, and an
alert and incident were created.

**Why it matters:** Attackers encode PowerShell commands to hide them from
simple string matching and quick log review.

**Verdict:** Expected. This was my own attack simulation.

**What I would do in production:** decode the command, check the parent
process and the user, look for related alerts on the same host, and isolate
the host if the activity is not authorized.

### Automated response

A Logic Apps playbook (`playbook-incident-comment`) runs on Sentinel
incidents and adds a triage comment with the incident title and severity.
It uses a system-assigned managed identity with the Microsoft Sentinel
Responder role, so no credentials are stored. I ran it manually on an
incident and confirmed the comment appears in the incident's activity log.
**Tuning note:** Admin scripts and management tools also use encoded
commands, so a real deployment needs exclusions for known parent processes
and paths.

**Time to alert:** About 12 minutes in this lab. The rule runs every 5
minutes with a 10-minute lookback, and I have not yet broken down how much
of the gap came from ingestion, the schedule, or portal sync.
