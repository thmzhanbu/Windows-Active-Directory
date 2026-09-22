# Parser checks

The XML files in `fixtures/` are **synthetic test inputs**, not collected evidence or project results. The test calls the same conversion function used by `Get-AuthEvents.ps1`.

From the repository root in PowerShell:

```powershell
.\scripts\tests\Test-AuthEventParser.ps1
```

The 25 assertions cover separate Status/SubStatus values, reordered XML fields, missing fields, TargetSid in account events, the documented 4740 caller-computer mapping, source identity, UTC conversion, and unsupported events. No Pester installation is required. The test does not change audit policy or read live logs.

**Validation status:** XML well-formedness was checked during preparation. PowerShell is unavailable in the preparation environment, so these assertions and the Windows integration workflow have not yet been run. Run this test on the lab VM and record the result before claiming runtime validation. Also verify actual policy changes, all four Security event IDs, Sysmon configuration acceptance, private CSV output, access/no-events behavior, and exported-file hash verification on Windows.
