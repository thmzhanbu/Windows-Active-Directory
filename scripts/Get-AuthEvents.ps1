#requires -Version 5.1
<#
.SYNOPSIS
Build a private CSV timeline from four Windows Security event IDs.
.DESCRIPTION
Reads the local Security log. This is a parser, not a sanitizer or detection engine.
Output contains account names, hostnames, SIDs, addresses, and paths. Review a COPY
before publication. Run in an elevated Windows PowerShell session in the lab.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 720)][int]$Hours = 24,
    [string]$OutputDirectory = 'C:\Lab\Evidence\analysis-private',
    [AllowEmptyString()][string]$TargetUser = 'soc-test'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ConvertFrom-AuthEventXml.ps1')
$startTime = (Get-Date).AddHours(-$Hours)
$endTime = Get-Date

try {
    $events = @(Get-WinEvent -FilterHashtable @{
        LogName = 'Security'; Id = @(4624, 4625, 4720, 4740)
        StartTime = $startTime; EndTime = $endTime
    } -ErrorAction Stop)
}
catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
        Write-Warning "No matching Security events in the last $Hours hours. No CSV created."
        return
    }
    if ($_.Exception -is [System.UnauthorizedAccessException] -or
        $_.CategoryInfo.Category -eq 'PermissionDenied') {
        throw 'Access to Security was denied. Open Windows PowerShell as Administrator in the lab.'
    }
    throw # Preserve the actual error; a missing channel is not an empty result.
}

$records = @(
    foreach ($event in $events) {
        $record = ConvertFrom-AuthEventXml -Xml $event.ToXml()
        if ($TargetUser -eq '' -or $record.TargetUser -ieq $TargetUser) {
            $record
        }
    }
)
if ($records.Count -eq 0) {
    Write-Warning "Security events exist, but none match TargetUser '$TargetUser'. No CSV created."
    return
}
$records = @($records | Sort-Object TimeCreatedUtc, RecordId)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$outputPath = Join-Path $OutputDirectory "auth-events-$runId.csv"
$records | Export-Csv -LiteralPath $outputPath -NoTypeInformation -Encoding UTF8 -NoClobber
$records | Format-Table TimeCreatedUtc, EventId, TargetUser, LogonTypeCode, StatusCode, SubStatusCode -AutoSize
Write-Host "Events exported: $($records.Count)"
Write-Host "Private CSV (not sanitized): $outputPath"
Write-Host "Query window: $($startTime.ToUniversalTime().ToString('o')) to $($endTime.ToUniversalTime().ToString('o'))"
