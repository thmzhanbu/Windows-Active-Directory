#requires -Version 5.1
<#
.SYNOPSIS
Exercise the actual conversion function using synthetic event XML.
.DESCRIPTION
No administrator rights, event-log access, or policy changes are required.
These checks do not validate Get-WinEvent, auditpol, wevtutil, or Sysmon on Windows.
#>
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'ConvertFrom-AuthEventXml.ps1')

function Assert-Equal {
    param($Actual, $Expected, [string]$Message)
    if ($Actual -cne $Expected) {
        throw "FAIL: $Message. Expected '$Expected'; received '$Actual'."
    }
}
function Read-Fixture {
    param([string]$Name)
    Get-Content -LiteralPath (Join-Path (Join-Path $PSScriptRoot 'fixtures') $Name) -Raw
}

$failureXml = Read-Fixture '4625-failure.xml'
$failure = ConvertFrom-AuthEventXml -Xml $failureXml
Assert-Equal $failure.StatusCode '0xc000006d' 'Original Status survives'
Assert-Equal $failure.SubStatusCode '0xc000006a' 'Original SubStatus survives separately'
Assert-Equal $failure.SubStatusMeaning 'Incorrect password' 'Lowercase codes are decoded'
Assert-Equal $failure.TargetUser 'soc-test' 'Named fields tolerate reordered XML'
Assert-Equal $failure.TimeCreatedUtc '2026-01-01T00:00:00.1234567Z' 'UTC precision survives'
Assert-Equal $failure.RecordId 101 'Source record ID survives'
Assert-Equal $failure.Channel 'Security' 'Source channel survives'
Assert-Equal $failure.Computer 'LAB-CLIENT' 'Source computer survives'

$success = ConvertFrom-AuthEventXml -Xml (Read-Fixture '4624-success.xml')
Assert-Equal $success.EventMeaning 'Successful logon' '4624 event meaning'
Assert-Equal $success.TargetLogonId '0x12345' 'Logon ID survives for correlation'
Assert-Equal $success.StatusMeaning 'Not present' 'Missing status is not invented'
Assert-Equal $success.SourceIpAddress $null 'Missing address is not invented'

$created = ConvertFrom-AuthEventXml -Xml (Read-Fixture '4720-created.xml')
Assert-Equal $created.TargetSid 'S-1-5-21-111-222-333-1001' '4720 TargetSid schema'
Assert-Equal $created.LogonTypeMeaning 'Not present' 'Account creation is not assigned a logon type'
$locked = ConvertFrom-AuthEventXml -Xml (Read-Fixture '4740-locked.xml')
Assert-Equal $locked.CallerComputer 'LAB-CLIENT' '4740 caller computer survives'
Assert-Equal $locked.TargetSid 'S-1-5-21-111-222-333-1001' '4740 TargetSid schema'
Assert-Equal $locked.TargetDomainRaw 'LAB-CLIENT' '4740 raw field survives'
Assert-Equal $locked.TargetDomain $null '4740 caller is not mislabelled as account domain'
Assert-Equal $locked.CallerComputerSourceField 'TargetDomainName (4740 schema)' '4740 mapping records provenance'

$zero = ConvertFrom-AuthEventXml -Xml ($failureXml.Replace('0xc000006a', '0x0'))
Assert-Equal $zero.SubStatusCode '0x0' 'Zero SubStatus is retained'
Assert-Equal $zero.StatusCode '0xc000006d' 'Zero SubStatus does not erase Status'
$unknown = ConvertFrom-AuthEventXml -Xml ($failureXml.Replace('0xc000006a', '0xDEADBEEF'))
Assert-Equal $unknown.SubStatusCode '0xDEADBEEF' 'Unknown code remains available for investigation'
Assert-Equal $unknown.SubStatusMeaning 'Unmapped; review Microsoft documentation' 'Unknown code is labelled'

$offset = ConvertFrom-AuthEventXml -Xml ($failureXml.Replace('2026-01-01T00:00:00.1234567Z', '2026-01-01T08:00:00.1234567+08:00'))
Assert-Equal $offset.TimeCreatedUtc $failure.TimeCreatedUtc 'Offset timestamp normalizes to UTC'
$rejected = $false
try { ConvertFrom-AuthEventXml -Xml ($failureXml.Replace('<EventID>4625</EventID>', '<EventID>9999</EventID>')) | Out-Null }
catch { $rejected = $true }
Assert-Equal $rejected $true 'Unsupported event ID is rejected'

Write-Host 'PASS: 25 parser assertions against synthetic fixtures. No live Windows integration tests were run by this test.'
