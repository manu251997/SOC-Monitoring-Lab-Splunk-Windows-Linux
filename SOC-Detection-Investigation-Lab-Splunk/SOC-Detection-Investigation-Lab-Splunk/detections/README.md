# Detection Catalogue

These SPL files contain reusable searches. Copy **one search at a time** into Splunk Search & Reporting.

## How to Use

1. Confirm that the `windows` and `linux` indexes exist.
2. Select a time range containing the lab activity.
3. Run the relevant detection file.
4. Inspect raw events when normalized fields are blank.
5. Adjust field aliases only when your source type uses different names.
6. Keep generic detections generic; use `soclabuser` only for the case-specific timeline.

## Windows

- `01-new-local-account.spl` — Event ID 4720
- `02-repeated-failed-logons.spl` — Event ID 4625 threshold
- `03-failed-then-successful.spl` — Event IDs 4625 and 4624
- `04-admin-group-change.spl` — Event ID 4732
- `05-powershell-activity-optional.spl` — Event IDs 4103 and 4104

## Linux

- `01-repeated-ssh-failures.spl`
- `02-failed-then-successful-ssh.spl`
- `03-sudo-activity.spl`

## Correlation and Validation

- `correlation/01-windows-account-lifecycle.spl`
- `validation/01-windows-data-health.spl` and `validation/02-linux-data-health.spl`

> The thresholds are intentionally low for a home-lab demonstration and must be tuned before production use.
