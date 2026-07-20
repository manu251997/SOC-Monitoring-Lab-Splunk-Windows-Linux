# Detection Engineering Notes

## Detection Design Principles

The searches in this project separate **generic detection logic** from **case-specific investigation filters**.

- A detection should normally monitor every relevant account.
- An investigation may filter to `soclabuser` to reconstruct this lab case.
- Thresholds should be tuned to the environment rather than copied blindly.
- Field normalization should occur before aggregation.
- Detection output should expose enough context for triage.

## Detection Catalogue

| File | Purpose | Suggested use |
|---|---|---|
| `windows/01-new-local-account.spl` | Monitor account creation | Low-volume alert or report |
| `windows/02-repeated-failed-logons.spl` | Identify password guessing | Threshold alert |
| `windows/03-failed-then-successful.spl` | Investigate auth sequence | Investigation search |
| `windows/04-admin-group-change.spl` | Monitor local group additions | High-value alert |
| `windows/05-powershell-activity-optional.spl` | Review PowerShell telemetry | Optional hunting search |
| `linux/01-repeated-ssh-failures.spl` | Detect repeated SSH failures | Threshold alert |
| `linux/02-failed-then-successful-ssh.spl` | Reconstruct SSH sequence | Investigation search |
| `linux/03-sudo-activity.spl` | Review privileged Linux actions | Hunting search |
| `correlation/01-windows-account-lifecycle.spl` | Correlate creation and authentication | Case timeline |
| `validation/01-windows-data-health.spl` and `validation/02-linux-data-health.spl` | Confirm data freshness and volume | Data-quality check |

## Threshold Rationale

The sample threshold uses three failures in ten minutes for the home lab so the detection can be demonstrated quickly. A production threshold should be based on normal authentication behavior, service accounts, user population, remote-access patterns and alert volume. A common tuning strategy is to begin with a higher threshold, review false positives and then refine by identity type, source and logon type.

## False Positives

Potential benign causes include:

- A user mistyping a password
- A recently changed password stored in a service or scheduled task
- Network drives reconnecting with stale credentials
- Automated vulnerability scanners or management tools
- Test accounts created by an administrator
- Expected SSH administration from a trusted source

## Escalation Conditions

Escalate when one or more of the following are present:

- The account creator is unknown or unexpected.
- The source IP is external, unusual or associated with other alerts.
- A successful login follows multiple failures.
- The account is added to a privileged group.
- The account is used outside expected hours or on multiple hosts.
- Suspicious process, PowerShell, service or network activity follows.
- Security logs are cleared or audit policy is changed.

## Recommended Alert Fields

Every alert should expose:

- Earliest and latest event time
- Host
- Account
- Event ID or outcome
- Source IP
- Logon type
- Failure count
- Group name, when relevant
- Link or drill-down query for raw events

## Limitations

- Field names depend on the Splunk source type and extraction quality.
- Local interactive logons may not have a meaningful remote source address.
- Windows Event ID 4624 is high volume and requires account/logon-type filtering.
- Linux message formats can differ by distribution and SSH configuration.
- The home lab does not include identity-provider, EDR or network telemetry.
- The searches demonstrate detection concepts and require production tuning.
