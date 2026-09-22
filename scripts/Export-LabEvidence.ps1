#requires -Version 5.1
#requires -RunAsAdministrator
<#
.SYNOPSIS
Export local Security and Sysmon logs and hash the exported files.
.DESCRIPTION
Raw logs AND the manifest are private. A SHA-256 digest detects subsequent byte
changes relative to that digest; it does not prove authenticity or completeness.
Exports are sequential, so they are not one atomic snapshot of both channels.
#>
[CmdletBinding()]
param(
    [string]$EvidenceRoot = 'C:\Lab\Evidence',
    [ValidateNotNullOrEmpty()][string]$AnalystName = 'LAB_ANALYST'
)
$ErrorActionPreference = 'Stop'
$runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$privateRoot = Join-Path $EvidenceRoot 'raw-private'
New-Item -ItemType Directory -Path $privateRoot -Force | Out-Null
$runDirectory = Join-Path $privateRoot "export-$runId"
New-Item -ItemType Directory -Path $runDirectory | Out-Null
$manifestPath = Join-Path $runDirectory 'evidence-hashes.csv'
$channels = @(
    @{ Log = 'Security'; File = 'Security.evtx' },
    @{ Log = 'Microsoft-Windows-Sysmon/Operational'; File = 'Sysmon-Operational.evtx' }
)
$failures = @()
$hashRecords = @(
    foreach ($channel in $channels) {
        $path = Join-Path $runDirectory $channel.File
        $startedUtc = [DateTime]::UtcNow.ToString('o')
        try {
            # /ow:false refuses overwrite. Do not clear or modify the source log.
            $result = & wevtutil.exe epl $channel.Log $path /ow:false 2>&1
            $exitCode = $LASTEXITCODE
            if ($exitCode -ne 0) { throw "wevtutil exit ${exitCode}: $($result -join ' ')" }
            $completedUtc = [DateTime]::UtcNow.ToString('o')
            $file = Get-Item -LiteralPath $path
            $hash = Get-FileHash -LiteralPath $path -Algorithm SHA256
            [pscustomobject][ordered]@{
                EvidenceFile = $file.Name
                Channel = $channel.Log
                SHA256 = $hash.Hash
                SizeBytes = $file.Length
                ExportStartedUtc = $startedUtc
                ExportCompletedUtc = $completedUtc
                HashedUtc = [DateTime]::UtcNow.ToString('o')
                SourceHost = $env:COMPUTERNAME
                CollectedBy = $AnalystName
            }
        }
        catch {
            # Keep successful exports and report the incomplete collection clearly.
            $failures += "$($channel.Log): $($_.Exception.Message)"
        }
    }
)
if ($hashRecords.Count -gt 0) {
    $hashRecords | Export-Csv -LiteralPath $manifestPath -NoTypeInformation -Encoding UTF8 -NoClobber
    $hashRecords | Format-Table EvidenceFile, SizeBytes, SHA256 -AutoSize
    Write-Host "Private hash manifest: $manifestPath"
}
if ($failures.Count -gt 0) {
    $failurePath = Join-Path $runDirectory 'export-errors.txt'
    $failures | Out-File -LiteralPath $failurePath -Encoding UTF8 -NoClobber
    throw "Collection incomplete: $($hashRecords.Count) of $($channels.Count) channels exported and hashed. See $failurePath. Retained files: $runDirectory"
}
Write-Host "Exported and hashed $($hashRecords.Count) logs: $runDirectory"
Write-Host 'Keep this entire directory private; the folder name does not enforce access permissions.'
