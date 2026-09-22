# Lab guide: commands, purpose, and validation

This is the revised procedure for a future reproducible run. Historical screenshots and summaries document the earlier run; new commands and checks below are not claims that those steps have already been completed.

## 1. Establish the baseline

Use the existing Windows 11 Pro ARM64 VM with 4 vCPU, 6 GB RAM, and an 80 GB disk. Record the installed Windows, Fusion, PowerShell, and Sysmon versions rather than assuming the original setup guide's version still applies. Install Windows and VMware Tools using the supported vendor workflow for the version in use.

Take a clean VM snapshot. Verify that you can sign in to the separate lab administrator before testing account lockout. A VM snapshot is a convenient lab rollback point, not an evidence archive or a substitute for a backup.

Run the following in the Windows VM:

```powershell
Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber, OSArchitecture
Get-CimInstance Win32_ComputerSystem |
    Select-Object Name, Domain, PartOfDomain
$PSVersionTable.PSVersion
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status
Get-NetIPConfiguration
Get-TimeZone | Select-Object Id, DisplayName
Get-Date -Format o
(Get-Date).ToUniversalTime().ToString('o')
w32tm.exe /query /status
```

**Why:** establish the machine, operating system, domain membership, connectivity, and time source before interpreting its logs. For this standalone project, confirm and record `PartOfDomain = False`; that result was not included in the supplied screenshots. Time-zone selection only controls presentation and does not prove that the clock is synchronized. If Windows Time reports an error, document it and resolve the clock discrepancy before a new capture.

```powershell
Get-MpComputerStatus |
    Select-Object AntivirusEnabled, RealTimeProtectionEnabled
Get-NetFirewallProfile | Select-Object Name, Enabled
New-Item -ItemType Directory -Path C:\Lab\Evidence -Force | Out-Null
```

**Why:** verify baseline endpoint protection and prepare a working folder. Keep Defender and the firewall enabled. VMware NAT permits outbound access; it is not proof of complete isolation. Use a host-only/private network for future multi-machine tests where appropriate.

## 2. Enable audit coverage before generating events

Copy or clone the repository into the Windows VM, open PowerShell as Administrator, and run from its root:

```powershell
.\scripts\Enable-LabAuditing.ps1
```

**Why:** events can only be analyzed if the necessary auditing is enabled when the action occurs. The script records the prior policy, enables selected subcategories, checks native command results, and records the resulting state.

| Subcategory | Purpose in this exercise |
| --- | --- |
| Logon | Capture successful and failed sign-ins, including 4624 and 4625 |
| User Account Management | Capture account creation 4720 and lockout 4740 |
| Account Lockout | Capture failed logons to an already locked account; this is not the source subcategory for 4740 |

Review local execution policy and trust the script content before running it. If a trusted downloaded file is blocked, unblock only that reviewed file with `Unblock-File -Path <script-path>`. Do not change machine-wide policy merely to run this lab.

Sources: Microsoft [Audit User Account Management](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-user-account-management) and [4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625).

## 3. Install and validate Sysmon

Download Sysmon from the [official Microsoft page](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), extract it to `C:\Tools\Sysmon`, and select the binary matching the guest OS. This ARM64 VM uses `Sysmon64a.exe`.

```powershell
# From the repository root; review Microsoft's licence before accepting it.
& C:\Tools\Sysmon\Sysmon64a.exe -accepteula -i .\config\sysmon-lab.xml
if ($LASTEXITCODE -ne 0) { throw 'Sysmon installation failed.' }

Get-CimInstance Win32_Service |
    Where-Object Name -Like 'Sysmon*' |
    Select-Object Name, State, StartMode
& C:\Tools\Sysmon\Sysmon64a.exe -c
```

**Why:** `-i` installs the service and driver with the supplied rules. The service check confirms it is running; `-c` displays the active configuration. If already installed, review the current rules before using `-c .\config\sysmon-lab.xml` to apply this lab configuration. A running service alone does not prove the intended rules are loaded.

```powershell
Start-Process notepad.exe
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
    StartTime = (Get-Date).AddMinutes(-5)
} | Select-Object -First 10 TimeCreated, Id, RecordId, Message
```

**Why:** confirm process telemetry is generated. Inspect the event's `Image`, `CommandLine`, `ParentImage`, `ProcessGuid`, and `UtcTime`; launching Notepad does not guarantee that the newest event belongs to it.

The lab config also selects DNS queries, selected TCP/UDP connections, file creation under `C:\Lab`, and common autostart registry paths. These are intended coverage areas, not all demonstrated by the existing screenshots. Sysmon network Event 3 does not capture ICMP, so `ping` is not an appropriate network-connection validation. Sysmon supplies telemetry; it does not decide whether activity is malicious. See [Microsoft's Sysmon reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

## 4. Create the disposable local account

Create a new account only if `soc-test` does not already exist. If it exists, preserve the old evidence and choose a new lab account name for the rerun.

```powershell
Get-LocalUser -Name 'soc-test' -ErrorAction SilentlyContinue

# Run once when the account is absent.
$LabPassword = Read-Host 'Temporary lab password for soc-test' -AsSecureString
New-LocalUser -Name 'soc-test' -Password $LabPassword `
    -FullName 'SOC Test User' -Description 'Disposable monitoring-lab account'

# Ensure standard-user membership; the SID avoids a localized group name.
$UsersGroup = Get-LocalGroup -SID 'S-1-5-32-545'
Add-LocalGroupMember -Group $UsersGroup -Member 'soc-test'
Get-LocalGroupMember -Group $UsersGroup
Get-LocalGroupMember -SID 'S-1-5-32-544'
Remove-Variable LabPassword
```

**Why:** a dedicated standard account separates test activity from administration. Confirm it is in Users and absent from Administrators. The password prompt does not echo the password. This creates a **local** account, not an AD domain user.

In Event Viewer, filter **Windows Logs → Security** for `4720` and confirm the target account, creator, timestamp, and record ID. [Microsoft's 4720 reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720) explains the distinction between the subject (actor) and new account (target).

## 5. Configure and test local account lockout

Run only inside the disposable standalone VM. These settings affect its local account policy, so first save the baseline and keep your administrator credentials available.

```powershell
net.exe accounts | Out-File C:\Lab\Evidence\local-account-policy-before.txt

# Set a 5-minute reset window and lockout duration together, then threshold.
net.exe accounts /lockoutwindow:5 /lockoutduration:5
if ($LASTEXITCODE -ne 0) { throw 'Lockout timing configuration failed.' }
net.exe accounts /lockoutthreshold:3
if ($LASTEXITCODE -ne 0) { throw 'Lockout threshold configuration failed.' }
net.exe accounts
```

| Setting | Correct interpretation |
| --- | --- |
| `lockoutthreshold:3` | Three failed attempts can trigger the lockout threshold |
| `lockoutwindow:5` | Reset the failed-attempt counter after five minutes without another failed attempt |
| `lockoutduration:5` | Keep the account locked for five minutes before automatic unlock |

These short settings make the exercise observable; they are not a production recommendation. The supplied original guide reversed the explanations of window and duration and used `\\` instead of valid PowerShell `#` comments. Those issues are corrected here. Microsoft documents [lockout duration](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/account-lockout-duration) and [counter reset](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/reset-account-lockout-counter-after) separately.

1. Record the test start time in UTC and save open work.
2. Switch user and explicitly select `WIN11-SOC-LAB\soc-test`.
3. Submit an incorrect lab password three times manually; never use the administrator account for this test.
4. Stop attempting sign-ins, return to `SOC`, and inspect 4625 and 4740.
5. Wait at least the configured lockout duration without retrying.
6. Sign in as `soc-test` with the correct password, run `whoami`, and record the UTC time.
7. Return to `SOC` and locate the matching 4624.

Expected evidence: the target identity, type 2 interactive logons, failure codes, a lockout record, and a later success. Actual counts may vary; explain the observed results rather than forcing a count to match the example.

## 6. Filter, parse, and interpret

Use a short time range and the account name. In Event Viewer's Security-log XML filter, this query narrows the four event IDs to the test account:

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624 or EventID=4625 or EventID=4720 or EventID=4740)]]
      and *[EventData[Data[@Name='TargetUserName']='soc-test']]
    </Select>
  </Query>
</QueryList>
```

Then run the parser soon after the exercise:

```powershell
.\scripts\Get-AuthEvents.ps1 -Hours 4 -TargetUser 'soc-test'
```

**Why:** filtering event IDs and time at the log query stage avoids reading the entire Security log. Reading XML fields by name handles field-layout differences. The revised output preserves original `Status` and `SubStatus` separately and includes a derived explanation rather than replacing the underlying evidence.

| Field | Interpretation |
| --- | --- |
| `TimeCreatedUtc`, `RecordId`, source computer/channel | Locate the record; record IDs are scoped to a log, not globally unique |
| Subject identity | Actor or context reporting the action; not necessarily the person signing in |
| Target identity/domain/SID | Account being created, authenticated, or locked out |
| Logon type | Context: 2 interactive, 3 network, 10 remote interactive |
| `Status`, `SubStatus` | Failure result and additional detail; retain both |
| Authentication package and process | Additional context; inspect rather than infer from the event ID |

The historical summary's `StatusCode` column was derived by preferring nonzero SubStatus. It is not guaranteed to be the original XML `Status`. Revised exports differ from the old screenshot and are private pending review. Microsoft documents these fields in [4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) and [4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625).

## 7. Preserve evidence and close the test

```powershell
.\scripts\Export-LabEvidence.ps1 -AnalystName 'LAB_ANALYST'
```

**Why:** export Security and Sysmon logs without clearing them, record source and collection metadata, then calculate SHA-256 for each file. A later matching hash demonstrates unchanged bytes relative to that manifest; it does not prove that the original log was truthful or independently establish chain of custody. Keep raw EVTXs and generated manifests private.

After checking the saved exports, sign out of `soc-test`, return to the administrator, and disable the disposable account:

```powershell
Disable-LocalUser -Name 'soc-test'
Get-LocalUser -Name 'soc-test' | Select-Object Name, Enabled
```

**Why:** prevent further sign-ins while retaining the identity for review. Preserve private evidence outside the snapshot being reverted, then restore the clean snapshot or restore the recorded policy values. Do not guess the prior lockout settings. Keep account removal optional until the investigation is closed.

## Acceptance criteria for the next run

- [ ] Clock source, UTC time, Windows build, domain membership, and baseline policy recorded.
- [ ] Effective audit settings and active Sysmon configuration captured.
- [ ] Account is a standard user; each required event has readable fields and a record ID.
- [ ] Parser output reconciled against the four event types in Event Viewer/XML.
- [ ] Private exports hashed, then hashes recomputed and compared.
- [ ] Reviewed public images and summaries contain only intended lab information.
- [ ] Account cleanup and policy restoration documented.

## Validate the revised parser and hashes

Run the fixture checks from the repository root before a live collection:

```powershell
.\scripts\tests\Test-AuthEventParser.ps1
```

The 25 assertions exercise the actual XML parser using clearly labelled synthetic events. They check separate failure fields, missing values, UTC precision, schema differences, and record provenance. They do not change audit settings or prove Windows integration. Keep `ConvertFrom-AuthEventXml.ps1` alongside the main parser script.

For event 4740, Microsoft's documented XML stores the caller computer in `TargetDomainName`. The revised parser retains that raw value, maps it to `CallerComputer`, and records which source field was used; it does not mistake that value for the account's domain. [Microsoft's 4740 XML](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740).

After exporting, replace the example run-folder value with the actual path printed by the exporter:

```powershell
$RunFolder = 'C:\Lab\Evidence\raw-private\export-REPLACE-WITH-ACTUAL-RUN'
Import-Csv (Join-Path $RunFolder 'evidence-hashes.csv') | ForEach-Object {
    $ActualHash = (Get-FileHash -LiteralPath (Join-Path $RunFolder $_.EvidenceFile) -Algorithm SHA256).Hash
    [pscustomobject]@{
        EvidenceFile = $_.EvidenceFile
        HashMatches = ($ActualHash -eq $_.SHA256)
    }
}
```

**Why:** a hash is useful only when compared with the matching original file or later copy. Investigate any missing file or mismatch; do not replace the recorded hash simply to make the comparison pass. [Microsoft: Get-FileHash](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-7.5).
