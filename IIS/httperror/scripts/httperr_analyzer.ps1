<#
.SYNOPSIS
  httperr_analyzer.ps1 - HTTP.SYS error log analyzer (v2 PS edition).
#>
[CmdletBinding()]
param(
    [string] $Context,
    [string] $Log
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Import-Module (Join-Path $root '_shared\Contract.psm1') -Force

$SKILL = 'httperror'
$HTTPERR_DIR = 'C:\Windows\System32\LogFiles\HTTPERR'

$REASON_HINTS = @{
    'Timer_ConnectionIdle'            = 'Idle connection closed by HTTP.SYS'
    'Timer_HeaderWait'                = 'Client did not send headers in time'
    'Timer_MinBytesPerSecond'         = 'Slow client / network throttling'
    'Timer_EntityBody'                = 'Request body never finished'
    'Timer_AppPool'                   = 'App pool failed to dequeue request in time'
    'Connection_Abandoned_By_AppPool' = 'App pool crashed/recycled'
    'Connection_Dropped'              = 'Lower-level connection drop'
    'URL_Length'                      = 'Request URL exceeded configured limit'
    'BadRequest'                      = 'Malformed HTTP request'
    'Forbidden'                       = 'HTTP.SYS rejected the URL'
}

function Get-LatestHttperr {
    if (-not (Test-Path -LiteralPath $HTTPERR_DIR)) { return $null }
    $f = Get-ChildItem -LiteralPath $HTTPERR_DIR -Filter 'httperr*.log' |
         Sort-Object Name | Select-Object -Last 1
    return $f.FullName
}

function Parse-HttperrLine {
    param([string] $Line)
    if ([string]::IsNullOrWhiteSpace($Line)) { return $null }
    if ($Line.StartsWith('#')) { return $null }
    $p = $Line -split '\s+'
    if ($p.Count -lt 5) { return $null }
    return @{
        timestamp = "$($p[0]) $($p[1])"
        client_ip = $p[2]
        reason    = $p[-1]
    }
}

$ctx = Read-SkillContext -Argument $Context
$range = Get-SkillTimeRange -Context $ctx
$start = $range[0]; $end = $range[1]

$logFile = if ($Log) { $Log } else { Get-LatestHttperr }
if (-not $logFile -or -not (Test-Path -LiteralPath $logFile)) {
    Write-SkillResult (New-SkillResult -Skill $SKILL -Ok $true `
        -Findings @((New-SkillFinding -Summary "No HTTPERR log present under $HTTPERR_DIR" -Severity 'info' `
                       -Evidence @{ searched_path = $HTTPERR_DIR })) `
        -Confidence 'low' `
        -Recommendations @("Run on the IIS host, or pass -Log <path> to a sample file.") `
        -Raw @{ log_file = $null })
    exit 0
}

$rows = New-Object System.Collections.Generic.List[hashtable]
foreach ($line in [System.IO.File]::ReadLines($logFile)) {
    $r = Parse-HttperrLine $line; if (-not $r) { continue }
    try {
        $ts = [datetime]::ParseExact($r.timestamp, 'yyyy-MM-dd HH:mm:ss', $null)
        if (-not (Test-InTimeWindow -Timestamp $ts -Start $start -End $end -ToleranceMinutes 2)) { continue }
    } catch { }   # keep unparseable rows
    $rows.Add($r)
}

$reasonGroups = $rows | Group-Object { $_.reason } | Sort-Object Count -Descending
$ipGroups     = $rows | Group-Object { $_.client_ip } | Sort-Object Count -Descending
$topIp = if ($ipGroups) { @{ ip = $ipGroups[0].Name; count = $ipGroups[0].Count } } else { $null }
$ddos  = $topIp -and $rows.Count -gt 0 -and ($topIp.count / $rows.Count) -gt 0.30

$findings = New-Object System.Collections.Generic.List[object]
foreach ($g in ($reasonGroups | Select-Object -First 5)) {
    $hint = if ($REASON_HINTS.ContainsKey($g.Name)) { $REASON_HINTS[$g.Name] } else { 'see HTTP.SYS docs' }
    $findings.Add((New-SkillFinding -Summary "$($g.Name): $($g.Count) hits — $hint" -Severity 'warning' `
                    -Evidence @{ reason = $g.Name; count = $g.Count }))
}
if ($ddos) {
    $findings.Add((New-SkillFinding -Summary "Single client IP $($topIp.ip) dominates ($($topIp.count) requests)" `
                    -Severity 'critical' -Evidence $topIp))
}
if ($findings.Count -eq 0) {
    $findings.Add((New-SkillFinding -Summary 'No HTTPERR entries in the requested window.' -Severity 'info'))
}

$rootCause = if ($reasonGroups) { "HTTP.SYS reason: $($reasonGroups[0].Name)" } else { $null }

Write-SkillResult (New-SkillResult -Skill $SKILL -Ok $true -Findings $findings `
    -RootCause $rootCause `
    -Confidence (if ($reasonGroups) {'medium'} else {'low'}) `
    -Recommendations @('Cross-check Application event log around the same window (event_log skill)') `
    -Raw @{
        log_file       = $logFile
        rows_in_window = $rows.Count
        top_reasons    = @($reasonGroups | Select-Object -First 5 | ForEach-Object { ,@($_.Name, $_.Count) })
        top_client_ip  = $topIp
        ddos_suspected = [bool]$ddos
    })
exit 0
