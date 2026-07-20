# Windows Investigation — New Account Followed by Failed and Successful Logons

## Investigation Question

Was the newly created local account `soclabuser` used in repeated failed authentication attempts and then successfully authenticated on `CynicalManX52`?

## Data Sources

- Splunk index: `windows`
- Windows Security Event Log
- Event ID 4720 — user account created
- Event ID 4625 — account failed to log on
- Event ID 4624 — account successfully logged on
- Event ID 4732 — member added to a local security group, optional

## Step 1 — Confirm Account Creation

```spl
index=windows EventCode=4720
| eval created_account=coalesce(TargetUserName, Account_Name)
| eval created_by=coalesce(SubjectUserName, Caller_User_Name)
| search created_account="soclabuser"
| table _time host EventCode created_by created_account ComputerName
| sort 0 _time
```

### Evidence

![Windows Event ID 4720](../screenshots/required/03-windows-event-4720.png)

![Splunk Event ID 4720](../screenshots/required/04-splunk-event-4720.png)

### Analyst Finding

The Windows Security log records creation of the local account `soclabuser` on `CynicalManX52`. Event ID 4720 establishes the beginning of the account lifecycle and identifies the account that performed the creation when the source field is available.

## Step 2 — Review Failed Authentication

```spl
index=windows EventCode=4625
| eval user=coalesce(TargetUserName, Account_Name, user)
| eval src_ip=coalesce(IpAddress, Source_Network_Address, src_ip)
| eval logon_type=coalesce(LogonType, Logon_Type)
| search user="soclabuser"
| table _time host EventCode user src_ip logon_type FailureReason Status SubStatus
| sort 0 _time
```

![Windows Event ID 4625](../screenshots/required/05-windows-event-4625.png)

### Analyst Finding

Multiple Event ID 4625 records show unsuccessful authentication attempts involving `soclabuser`. In this lab, the activity was deliberately generated with an incorrect password. In a production environment, the analyst would determine whether the failures resulted from user error, a stale service credential or password guessing.

## Step 3 — Confirm Successful Authentication

```spl
index=windows EventCode=4624
| eval user=coalesce(TargetUserName, Account_Name, user)
| eval src_ip=coalesce(IpAddress, Source_Network_Address, src_ip)
| eval logon_type=coalesce(LogonType, Logon_Type)
| search user="soclabuser"
| table _time host EventCode user src_ip logon_type AuthenticationPackageName LogonProcessName
| sort 0 _time
```

![Windows Event ID 4624](../screenshots/required/06-windows-event-4624.png)

### Analyst Finding

A later Event ID 4624 confirms that the account successfully authenticated. The successful event is not inherently malicious; its significance comes from its position after repeated failures and shortly after local account creation.

## Step 4 — Reconstruct the Authentication Timeline

```spl
index=windows (EventCode=4625 OR EventCode=4624)
| eval user=coalesce(TargetUserName, Account_Name, user)
| search user="soclabuser"
| eval outcome=case(EventCode=4625,"Failed", EventCode=4624,"Successful")
| eval src_ip=coalesce(IpAddress, Source_Network_Address, src_ip)
| eval logon_type=coalesce(LogonType, Logon_Type)
| table _time host EventCode outcome user src_ip logon_type
| sort 0 _time
```

![Windows authentication timeline](../screenshots/required/07-windows-authentication-timeline.png)

## Triage Assessment

| Category | Assessment |
|---|---|
| Alert disposition | True positive — authorized simulation |
| Severity | Medium |
| Confidence | High when the event sequence and account fields are visible |
| Affected asset | `CynicalManX52` |
| Affected identity | `soclabuser` |
| Primary risk | Unauthorized account use or credential guessing |
| Escalation trigger | Unknown creator, remote source, privileged group membership or suspicious post-login execution |

## MITRE ATT&CK Mapping

| Observed behavior | Technique |
|---|---|
| Local account creation | T1136.001 — Create Account: Local Account |
| Repeated password failures | T1110.001 — Password Guessing |
| Successful use of the account | T1078 — Valid Accounts |
| Addition to a privileged local group, when performed | T1098.007 — Additional Local or Domain Groups |

## Analyst Recommendations

1. Confirm that the account creation was linked to an approved request.
2. Identify the user or process that created the account.
3. Review the failed-logon source, failure reason and logon type.
4. Compare the successful logon with the same account, host and source context.
5. Review local group membership and specifically check Administrators membership.
6. Search for commands, processes and network activity after the successful logon.
7. Disable the account and preserve evidence if the activity is unauthorized.
8. Apply account-lockout and password controls appropriate to the environment.
9. Create a correlation alert for account creation followed by authentication activity.
