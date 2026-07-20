# Safe Lab Event Generation

Use these steps only on a system you own and only after saving your work. Run Windows commands from an elevated Command Prompt or PowerShell session.

## Windows Account Creation

```powershell
net user soclabuser StrongPassword123! /add
```

After evidence collection, remove the account:

```powershell
net user soclabuser /delete
```

Do not commit the demonstration password to screenshots or real environments. Use a temporary lab-only password.

## Failed and Successful Windows Authentication

1. Sign out or switch user.
2. Select `soclabuser`.
3. Enter an incorrect password at least three times.
4. Enter the correct temporary password once.
5. Return to the administrator account and search Event IDs 4625 and 4624.

## Optional Administrator-Group Change

```powershell
net localgroup Administrators soclabuser /add
```

Remove the membership after evidence collection:

```powershell
net localgroup Administrators soclabuser /delete
```

## Linux SSH Activity

On Kali:

```bash
sudo systemctl enable --now ssh
sudo systemctl status ssh
```

From another authorized lab system, connect to Kali with SSH. Enter an incorrect password several times, then authenticate successfully.

Review evidence on Kali:

```bash
sudo grep -E "Failed password|Accepted password" /var/log/auth.log
```

or:

```bash
sudo journalctl -u ssh --no-pager
```

## Cleanup

- Remove temporary users and group memberships.
- Stop SSH if it is not otherwise needed.
- Do not expose the Kali SSH service to the public internet.
- Preserve only sanitized screenshots needed for the portfolio.
