# Lessons Learned

## Technical Lessons

- A SIEM search should begin with data validation rather than assuming the correct index, source or sourcetype.
- Windows Security Event IDs become more useful when they are correlated as a sequence instead of reviewed independently.
- Event ID 4720 identifies account creation, Event ID 4625 records failed authentication and Event ID 4624 records a successful logon session.
- Splunk field names can vary, so `coalesce()` helps normalize equivalent fields before analysis.
- Linux authentication messages often require `rex` field extraction from `_raw`.
- Time range, time synchronization and sorting are essential when reconstructing an incident timeline.
- Generic detections should not be permanently hardcoded to a single lab username.

## Investigation Lessons

The account-creation event provides the first pivot. The analyst can then search for the same account across failed and successful authentication events, privilege changes and later execution. The sequence demonstrates why context matters: each event may be benign alone, but the combined pattern changes the risk assessment.

For SSH monitoring, the username and source address are the most important correlation fields. A success after repeated failures deserves closer review even when the account is valid.

## Challenges Encountered

- PowerShell Operational and Sysmon channels were not initially visible for collection.
- Windows Home does not expose every enterprise management interface in the same way as Pro or Server editions.
- Expected Splunk fields may be empty when the sourcetype uses different field names.
- Authentication searches can produce high volumes of unrelated service and machine logons.
- Linux logging may use `/var/log/auth.log`, the systemd journal or both, depending on configuration.

## How the Challenges Were Addressed

- The core investigation was designed around Windows Security events that are sufficient for account and authentication monitoring.
- PowerShell and Sysmon evidence was made optional rather than falsely presented as collected.
- Searches normalize multiple possible field names.
- Case-specific searches filter to `soclabuser`, while reusable detections remain generic.
- Linux searches parse the raw SSH message so they do not rely entirely on pre-extracted fields.

## Future Improvements

- Enable PowerShell module and script-block logging.
- Add Sysmon process, network and registry telemetry.
- Create Splunk scheduled alerts with suppression and drill-down searches.
- Build a dashboard for authentication trends and account changes.
- Add Windows Defender events and basic malware-triage scenarios.
- Introduce Wazuh or Microsoft Sentinel in a separate lightweight project.
- Export sanitized sample events for repeatable detection testing.
