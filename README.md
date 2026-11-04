# SOC Lab 002 - Windows Authentication Log Investigation

**Analyst:** Pranali Bhamare  
**Lab Type:** Windows Security Event Log Analysis  
**Tools:** Windows Event Viewer  
**Investigation Date:** 4 November 2026  
**Events Investigated:** 4624, 4625  
**MITRE ATT&CK Reference:** T1110 - Brute Force (considered as a potential detection category; not confirmed)

## 1. Objective

Investigate Windows authentication events to identify failed and successful logins, interpret authentication failure codes, correlate related events, and determine whether the observed activity is suspicious or benign.

## 2. Investigation Environment

- Operating System: Microsoft Windows
- Log Source: Windows Logs → Security
- Tool: Windows Event Viewer (`eventvwr.msc`)
- Account: Local Windows user account
- Investigation Scope: Authentication events recorded on 2 November 2026

## 3. Authentication Timeline

| Date and Time | Event ID | Logon Type | Observation |
|---|---|---|---|
| 02-Nov-2026 11:15:29 | 4624 | 2 | Successful interactive login to the local user account |
| 02-Nov-2026 11:15:39 | 4625 | 2 | Failed interactive login - incorrect password |
| 02-Nov-2026 11:15:40 | 4625 | 2 | Failed interactive login - incorrect password |
| 02-Nov-2026 11:15:44 | 4624 | 5 | Successful SYSTEM service logon |
| 02-Nov-2026 11:16:03 | 4624 | 5 | Successful service logon |
| 02-Nov-2026 21:57:24 | 4625 | 2 | Failed interactive login - incorrect password |

## 4. Technical Evidence

### Failed Authentication - Event ID 4625

Three failed authentication events were identified.

Common characteristics:

- Logon Type: 2 (Interactive)
- Target: Same local Windows user account
- Failure Reason: Unknown user name or bad password
- Status: `0xC000006D`
- Sub Status: `0xC000006A`
- Source Network Address: `127.0.0.1`
- Caller Process: `C:\Windows\System32\svchost.exe`
- Logon Process: `User32`
- Authentication Package: `Negotiate`

**Interpretation:** The substatus `0xC000006A` indicates incorrect-password authentication failures. The source address is the local loopback interface.

### Successful Authentication - Event ID 4624

A successful interactive login was identified at 11:15:29 AM.

Relevant evidence:

- Logon Type: 2
- Account: Same local Windows user account
- Source Address: `127.0.0.1`
- Logon Process: `User32`
- Authentication Package: `Negotiate`

Additional successful service logons (Type 5) were observed.

**Important correlation finding:** The successful interactive login occurred before the failed authentication events. Therefore, it cannot be used as evidence that the failed attempts were followed by a successful interactive login.

## 5. Analysis

Two failed authentications occurred one second apart. A third failure occurred later the same evening.

All three failures involved the same local account and shared the same failure codes and local source address.

The user recalled entering an incorrect password, which supports a benign explanation.

The available evidence does not establish a brute-force attack, password spraying, or remote unauthorized access.

The successful Type 5 service logons are not evidence of successful interactive authentication by the user.

## 6. Incident Classification

**Disposition:** Likely benign authentication failures  
**Confidence:** Moderate  
**Confirmed Compromise:** No  
**Escalation:** Not indicated by the reviewed events alone

This classification applies only to the authentication records examined. It does not establish that all activity on the workstation was benign.

## 7. Recommendations

1. Continue monitoring failed authentication events.
2. Investigate unusual increases in Event ID 4625 frequency.
3. Correlate failed logins with successful logins using timestamps, accounts, logon types, and source information.
4. Review unexpected remote interactive logins (Type 10).
5. Investigate account lockout events (4740) if observed.
6. Preserve relevant logs and redact identifying details before public sharing.

## 8. Skills Demonstrated

- Windows Event Viewer investigation
- Security log filtering
- Event ID 4624 and 4625 analysis
- Windows Logon Type interpretation
- NTSTATUS authentication failure-code interpretation
- Authentication event correlation
- False-positive assessment
- Evidence-based incident classification

## 9. Conclusion

The investigation identified three failed local interactive authentications associated with incorrect passwords.

The observed activity is consistent with ordinary authentication mistakes and the user's recollection. No evidence in the reviewed records confirms unauthorized remote access or account compromise.

The investigation demonstrates the importance of interpreting logon types, authentication error codes, event chronology, and account context before classifying security alerts.
