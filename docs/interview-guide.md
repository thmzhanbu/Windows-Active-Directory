# Interview guide

Use this guide to explain the completed local Windows lab clearly. Describe the [Active Directory roadmap](active-directory-roadmap.md) as future work until you have built and verified it. Rehearse answers in your own words and be ready to open the supporting evidence.

## 60–90 second project explanation

> I built a Windows security monitoring lab using a Windows 11 Pro ARM virtual machine on my Apple Silicon Mac. My goal was to understand how account activity appears in Windows logs and turn it into an investigation timeline.
>
> I used a disposable local account, enabled the relevant auditing, and followed a controlled sequence covering account creation, incorrect-password attempts, account lockout and a later successful sign-in. The supplied evidence summary contains six records: one creation event, three failed logons, one lockout and one successful logon.
>
> I used Event Viewer and PowerShell to filter by the test account and read named XML fields. That helped separate the test from background logons and explain why the account, logon type, timestamp and failure details matter more than an event ID alone. The lab also includes Sysmon configuration and an EVTX export-and-hash workflow.
>
> The main limitation is that this is a local-account lab. I have not demonstrated an AD domain or a centralized detection system. My next step is a compatible Windows Server lab where I can join a client, apply domain policy and correlate client logons with DC authentication records.

## What the evidence supports

| Topic | Accurate claim | Avoid claiming |
| --- | --- | --- |
| Scope | A Windows local-account security monitoring lab. | A deployed enterprise Active Directory environment. |
| Result | A supplied six-record timeline for one disposable account. | A measured detection rate, investigation speed improvement or production incident response outcome. |
| Analysis | Filtering and interpreting relevant security events. | That three failures prove malicious brute force or compromise. |
| Sysmon | Installation and Notepad process-creation evidence. | Detection of malware, complete process ancestry or proof that the supplied configuration matches the installed one. |
| Preservation | Export-and-hash tooling and supplied hash summaries. | Independent verification of private EVTX files that were not supplied for this review. |
| Updated scripts | Code improvements prepared in this repository. | That every revised command has been rerun on Windows unless a new run is documented. |

The strongest answer explains both a result and its boundary. In this package, the original EVTX files are not available for independent replay, and the public CSV was transcribed from observed output. Screenshot filenames and guest clocks do not consistently agree, so accurate real-world clock synchronization is not established.

## Questions to rehearse

### Is this an Active Directory project?

“The completed part is a local Windows security monitoring project. The test user was created with `New-LocalUser`, so it belongs to that computer. AD would add a domain controller, directory-backed accounts, domain membership and centralized policy. I documented those as the next milestones.” Local and AD accounts are distinct security principals. [Microsoft: security principals](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-principals)

### Why did you enable auditing before generating activity?

“I needed the relevant events to be recorded when the activity happened. Enabling auditing later does not create historical events. I would verify the effective policy, record the test window and generate a new controlled run if the expected evidence was missing.”

### What do the four main event IDs tell you?

“4720 records creation of a user account; 4625 records a failed logon; 4740 records an account lockout; 4624 records a successful logon session. I correlate them by the target account, timestamp and source context rather than matching event IDs alone.” [Microsoft: events to monitor](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/Appendix-L--Events-to-Monitor)

### Does 4624 prove a person signed in at the keyboard?

“No. I inspect the logon type and the target account. Type 2 is interactive, while service, network and remote interactive logons have other types. I also check the process and authentication details when they are present.” The supplied summary reports type 2 for the test account's logon records. [Microsoft: 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)

### What does the failed-password code mean?

“The supplied summary reports `0xC000006A`, which Microsoft maps to an incorrect password. For a full investigation, I would preserve both `Status` and `SubStatus` from the event XML. The public transcription uses one combined status column, so I should not infer which original field held the value.” [Microsoft: 4625 status and substatus](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)

### Why is a lockout not proof of an attack?

“An incorrect password, stale saved credentials or a misconfigured service can produce failures. In this lab, I deliberately generated them against a test account. In a real investigation I would check source systems, affected accounts, timing, authentication method and follow-on activity before deciding whether it was suspicious.”

### Why is the lockout event just before the final failed-logon event?

“The supplied record order places 4740 at `02:57:47.943Z` and the final 4625 at `02:57:47.946Z`. I preserve that order instead of rearranging it to fit a story. These are related records from a logon and lockout sequence; the three-millisecond ordering alone is not a precise internal execution trace.”

### How do you keep a timeline reliable?

"I would preserve UTC timestamps and label local-time displays, with the source computer, channel, event ID, record ID and version. Record IDs are scoped to a source log. The current summary has UTC and Singapore values, but the guest clock and screenshot filenames disagree, so I cannot prove wall-clock accuracy. A rerun should record a trusted time source before correlating machines."

### Why parse XML by field name?

“Named fields such as `TargetUserName` are easier to verify than a fixed index into an event's property array. Events have different fields and versions. I retain the original codes, avoid inventing absent values and preserve enough source information to return to the original record.”

### What does Sysmon add?

"Security logs explain the account and logon activity. Sysmon adds process context depending on configuration. My screenshots show a Notepad process-creation event and command-line details. I still need a complete event extract for parent-process analysis and a copy of the active configuration, because the installed filename differs from the supplied file. Sysmon records telemetry; it does not itself analyze whether activity is malicious." [Microsoft: Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

### Why hash the EVTX exports?

"A SHA-256 digest lets me compare a later copy against the file hashed at collection. It helps identify changes, but it does not prove the original source was trustworthy or that collection was complete. I would preserve the original file, collection details and manifest privately, then publish only reviewed lab evidence." [Microsoft: Get-FileHash](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-7.5)

### What would you check if the expected events were missing?

“First the machine and log channel, then effective audit settings, time window and exact account name. I would check for log rollover, permissions and a mismatch between the attempted action and expected event. In an AD extension, I would collect both client and DC evidence because they answer different questions.”

### How would you extend this to Active Directory?

“I would start with a supported x64 Windows Server environment, AD DS and DNS, then join a Windows client. I would prove domain membership, effective GPO and least-privilege group access before repeating the sign-in scenario. The DC can record Kerberos ticket events such as 4768 and 4769, while the accessed host records its own logon session. I would add event forwarding after proving the local sources work.” [Microsoft: 4768](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768), [4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)

### What was the most useful lesson?

“A useful result needs context and traceable evidence. A long list of events is less useful than a small timeline that explains the affected account, what happened, how I know and what I still cannot conclude.”

## Resume bullets

- Built a Windows 11 security monitoring lab to examine account creation, failed sign-ins, lockout and successful authentication using Event Viewer, PowerShell and a disposable local account.
- Documented a six-record authentication timeline, PowerShell event parsing and an EVTX export-and-hash workflow, with evidence limitations and an Active Directory extension plan.

Use these bullets only for work you can explain and demonstrate. Keep AD deployment, SIEM integration and production incident-response experience off the completed-work list until supported by actual work.

## Five-minute demonstration

1. **Scope:** open the README and explain the host, VM and local test account.
2. **Result:** show the account-specific timeline and one readable source event.
3. **Reasoning:** explain logon type, target identity and failure details; distinguish facts from interpretation.
4. **Code:** show where the parser selects events and reads XML fields by name; explain why the export workflow records hashes.
5. **Limit:** explain the missing raw evidence for review and show the next AD acceptance milestone.

Do not run password-failure tests during an interview unless you have a prepared disposable environment. A short walkthrough of reproducible evidence is sufficient to demonstrate understanding.
