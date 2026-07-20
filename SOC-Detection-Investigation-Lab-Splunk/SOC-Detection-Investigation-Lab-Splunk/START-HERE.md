# Start Here — Finish the Repository by Replacing Screenshots

The repository text, investigation analysis, SPL detections, MITRE mapping and recommendations are already complete. Your only required task is to replace the ten placeholder PNG files in `screenshots/required/` with your real lab screenshots.

## Important Rule

Keep **exactly the same filenames**. Delete or overwrite each placeholder image with your real screenshot. Because the Markdown already points to these filenames, no README or document editing is required.

## Required Screenshots

| # | Filename | What the screenshot must show |
|---:|---|---|
| 1 | `01-windows-data-ingestion.png` | Splunk results proving events are arriving in `index=windows`, including host, source and sourcetype |
| 2 | `02-linux-data-ingestion.png` | Splunk results proving events are arriving in `index=linux`, including host, source and sourcetype |
| 3 | `03-windows-event-4720.png` | Windows Event Viewer showing Event ID 4720 and the test account |
| 4 | `04-splunk-event-4720.png` | Splunk result for Event ID 4720 showing account and host fields |
| 5 | `05-windows-event-4625.png` | Windows Event Viewer showing a failed logon for the test account |
| 6 | `06-windows-event-4624.png` | Windows Event Viewer showing a successful logon for the test account |
| 7 | `07-windows-authentication-timeline.png` | Splunk table showing failed logons followed by a successful logon |
| 8 | `08-kali-authentication-log.png` | Kali terminal or journal output showing failed and accepted SSH authentication |
| 9 | `09-linux-ssh-timeline.png` | Splunk table showing Linux SSH failures followed by success |
| 10 | `10-complete-incident-timeline.png` | Splunk account-lifecycle search showing creation, failures and success in chronological order |

## Queries to Use

The exact searches are stored in the `detections/` folder. Run only the relevant SPL query, select a time range that contains your simulation and capture the full result table.

Recommended validation searches:

```spl
index=windows
| stats count as events by host source sourcetype
| sort - events
```

```spl
index=linux
| stats count as events by host source sourcetype
| sort - events
```

## Screenshot Quality Checklist

- Show the Splunk query and result table together.
- Keep the event time visible.
- Keep relevant fields visible: account, host, event ID, source IP and outcome.
- Crop browser tabs, bookmarks and unrelated desktop content.
- Hide passwords, email addresses, tokens and public IP addresses.
- Do not alter event values or create fabricated evidence.
- Use PNG format and preserve the listed filenames.

## Optional Screenshots

The files in `screenshots/optional/` strengthen the project but are not needed to complete it:

- Local user added to Administrators — Event ID 4732
- PowerShell activity — Event IDs 4103/4104, when available
- A final Splunk dashboard

## Upload to GitHub

1. Create a new GitHub repository named `SOC-Detection-Investigation-Lab-Splunk`.
2. Extract the ZIP file.
3. Replace the ten images in `screenshots/required/`.
4. Open `README.md` locally to confirm the image filenames.
5. Upload the contents of the extracted root folder to GitHub.
6. Add repository topics such as `splunk`, `soc`, `cybersecurity`, `windows-event-logs`, `linux`, `siem`, `incident-response` and `mitre-attack`.
