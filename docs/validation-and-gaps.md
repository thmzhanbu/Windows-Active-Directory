# Validation status and next improvements

## What the supplied project supports

- A configured Windows 11 Pro ARM64 lab and successful audit-policy output.
- Sysmon ARM64 installation, a running service, and a Notepad process event.
- A six-record local-account investigation covering 4720, 4625, 4740, and 4624.
- Effective test settings of three attempts, five-minute duration, and five-minute reset window; local Users-group membership is also shown.
- A PowerShell parser run and visible record IDs, UTC timestamps, and derived failure codes.
- Successful-export console output showing two private EVTX filenames, sizes, and SHA-256 values.

All 34 supplied screenshots were visually reviewed. The [image audit](screenshots.md) identifies exactly which evidence is useful and which captures should be replaced.

## Highest-value gaps

| Priority | Missing or incomplete area | Evidence to add | Why it matters |
| --- | --- | --- | --- |
| 1 | Clock accuracy | One capture showing UTC, local time, time zone, and synchronization status | Makes the timeline defensible and explains the capture-time discrepancy |
| 1 | Original lockout-policy baseline and restoration | Before/after settings and cleanup evidence | The current 3-attempt/5-minute test settings are shown, but their restoration is not |
| 1 | Complete 4625 failure detail | Readable Details/XML containing Status, SubStatus, account, logon type, record ID, and source | Separates observed raw data from parser interpretation |
| 1 | Validation of revised scripts | Run fixture tests and all three scripts inside the Windows lab; reconcile outputs with Event Viewer | Historical screenshots cannot validate code changed during this review |
| 1 | Original evidence integrity | Private original logs/manifest, full UTC collection times, and a rehash comparison | Completes the export-and-verification workflow |
| 2 | Active configuration and scope | Sysmon configuration display plus OS/build/domain-membership output without device/product identifiers | Resolves the installed `sysmon-lab-clean.xml` versus supplied `sysmon-lab.xml` filename mismatch and establishes final scope |
| 2 | Standard-user membership and cleanup | Test-account membership and disabled state after collection | Demonstrates least privilege and a complete lab lifecycle |
| 2 | A detection outcome | A small rule/query with positive and negative tests, plus false-positive discussion | Extends manual investigation into repeatable monitoring |
| 3 | Centralized logging and retention | WEF/SIEM receipt, matching host/record/time, log size and retention settings | Extends beyond analysis on a single endpoint |
| 3 | Domain administration | DC, DNS, domain join, OU/groups, GPO, and domain authentication evidence | Required before presenting an implemented Active Directory lab |

Finish priorities 1 and 2 before adding more setup screenshots. A small set of readable evidence with precise explanations is stronger than a large gallery of installation screens.

## Corrections made in this repository

- Distinguished completed local-account monitoring from the planned AD phase.
- Replaced the fragmented setup notes with a concise workflow and explicit reasons for the important commands.
- Corrected lockout-window versus lockout-duration explanations and PowerShell comment syntax.
- Corrected the mapping of event 4740 to User Account Management auditing.
- Stopped describing generated identifiable exports as automatically sanitized.
- Retained Status and SubStatus separately in revised parsing and expanded event provenance.
- Added native command exit checking and unique private export locations.
- Removed `ping.exe` as a network-connection validation example; Sysmon 3 is TCP/UDP telemetry.
- Preserved the historical event order and documented the 3 ms boundary and time discrepancy.

## Review performed and limits

The supplied text, CSV summaries, screenshots, and original code were inspected; Microsoft documentation informed the technical corrections. Repository file/link checks and configuration XML parsing are reported in the delivery review. The code revision has not been run on the Windows VM, and the raw EVTX hashes have not been recomputed because those files were not supplied.

Run the included parser fixture tests in PowerShell and then complete the lab acceptance checklist. Synthetic fixtures test parsing behavior only; they do not prove Security-log permissions, audit-policy changes, Sysmon installation, or EVTX export work on the target machine.

For the planned domain-based phase, use the [AD roadmap](active-directory-roadmap.md). Keep future work labelled as planned until its acceptance evidence exists.
