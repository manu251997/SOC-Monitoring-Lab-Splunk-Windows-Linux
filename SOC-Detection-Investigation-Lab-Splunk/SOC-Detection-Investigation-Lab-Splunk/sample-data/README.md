# Sample Data

No raw event logs are included because endpoint logs can contain usernames, host details, IP addresses and other sensitive information.

To make the project portable without publishing raw logs:

- Detection logic is stored as SPL files.
- Evidence is represented by sanitized screenshots.
- Raw `.log`, `.evtx`, `.pcap`, `.csv` and `.json` files are excluded by `.gitignore`.

A future enhancement could add a small set of manually sanitized example events that contain no real credentials, addresses or personal data.
