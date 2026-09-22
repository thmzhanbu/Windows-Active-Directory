#requires -Version 5.1
#requires -RunAsAdministrator
<#
.SYNOPSIS
Enable the three audit subcategories used by this local Windows lab.
.DESCRIPTION
Changes local audit policy, saves the previous policy, and queries the result.
Does not set account lockout thresholds or domain Group Policy.
Use on the isolated lab VM after taking a VM snapshot.
#>
[CmdletBinding()]
param([string]$EvidenceDirectory = 'C:\Lab\Evidence')
$ErrorActionPreference = 'Stop'

function Invoke-AuditPol {
    param([string[]]$Arguments)
    $result = & auditpol.exe @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "auditpol failed (exit $exitCode): $($result -join ' ')"
    }
    $result
}

$runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$privateRoot = Join-Path $EvidenceDirectory 'raw-private'
New-Item -ItemType Directory -Path $privateRoot -Force | Out-Null
$runDirectory = Join-Path $privateRoot "audit-policy-$runId"
New-Item -ItemType Directory -Path $runDirectory | Out-Null
$backupPath = Join-Path $runDirectory 'audit-policy-before.csv'
$beforePath = Join-Path $runDirectory 'audit-policy-before.txt'
$afterPath = Join-Path $runDirectory 'audit-policy-after.txt'

# Stop before making changes if the prior policy could not be saved.
Invoke-AuditPol -Arguments @('/backup', "/file:$backupPath") | Out-Host
Invoke-AuditPol -Arguments @('/get', '/category:*') |
    Out-File -LiteralPath $beforePath -Encoding UTF8 -NoClobber

# GUIDs work across Windows display languages; labels below explain the intent.
# Mapping: https://learn.microsoft.com/en-us/windows/win32/secauthz/auditing-constants
$subcategories = @(
    @{ Name = 'Logon'; Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Flags = @('/success:enable', '/failure:enable') },
    @{ Name = 'Account Lockout'; Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Flags = @('/failure:enable') },
    @{ Name = 'User Account Management'; Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Flags = @('/success:enable', '/failure:enable') }
)
foreach ($subcategory in $subcategories) {
    Write-Host "Enabling: $($subcategory.Name)"
    $arguments = @('/set', "/subcategory:$($subcategory.Guid)") + $subcategory.Flags
    Invoke-AuditPol -Arguments $arguments | Out-Host
}
$after = foreach ($subcategory in $subcategories) {
    Invoke-AuditPol -Arguments @('/get', "/subcategory:$($subcategory.Guid)")
}
$after | Out-File -LiteralPath $afterPath -Encoding UTF8 -NoClobber
$after | Out-Host
Write-Host "Audit commands succeeded. Verify the settings above and generate the test events."
Write-Host "Private before/after evidence: $runDirectory"
Write-Host "Policy backup: $backupPath"
# Domain/local Group Policy can replace these settings. Recheck after policy refresh.
# For lab rollback, prefer the VM snapshot. auditpol /restore /file:<backup> restores
# the whole saved audit policy, not just the three subcategories changed here.
