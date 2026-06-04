<#
.SYNOPSIS
  event_log_analyzer.ps1 - Windows Event Log correlator (v2 PS edition).
#>
[CmdletBinding()]
param(
    [string]   $Context,
    [string[]] $Logs = @('Application','System'),
    [double]   $ToleranceMinutes = 2.0
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Import-Module (Join-Path $root '_shared\Contract.psm1') -Force

$SKILL = 'event_log'

$EVENT_ID_MAP = @{
    1000 = @{ name = '.NET application crash';                   severity='critical' }
    1001 = @{ name = 'Application pool recycle';                  severity='warning'  }
    1026 = @{ name = '.NET runtime error';                        severity='critical' }
    2004 = @{ name = 'Resource exhaustion (perfmon alert)';       severity='critical' }
     219 = @{ name = 'Driver / disk warning';                     severity='warning'  }
    7000 = @{ name = 'Service failed to start';                   severity='critical' }
    7009 = @{ name = 'Service start timeout';                     severity='warning'  }
    7034 = @{ name = 'Service terminated unexpectedly';           severity='critical' }
    5719 = @{ name = 'Domain controller unreachable';             severity='warning'  }
}

$ROOT_CAUSE_HINTS = @{
    '5xx_error'    = @(1000,1001,1026,7034)
    'high_latency' = @(2004,219)
    'auth_error'   = @()
}

$ctx = Read-SkillContext -Argument $Context
$range = Get-SkillTimeRange -Context $ctx
$start = $range[0]; $end = $range[1]
if (-not $start -or -not $end) {
    $end = (Get-Date)
    $start = $end.AddHours(-1)
}

$events = New-Object System.Collections.Generic.List[object]
foreach ($logName in $Logs) {
    try {
        $filter = @{
            LogName   = $logName
            StartTime = $start
            EndTime   = $end
            Level     = 1,2,3
        }
        $events.AddRange(@(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue))
    } catch { }
}

$correlated = New-Object System.Collections.Generic.List[hashtable]
foreach ($ev in $events) {
    if (-not (Test-InTimeWindow -Timestamp $ev.TimeCreated -Start $start -End $end -ToleranceMinutes $ToleranceMinutes)) { continue }
    $eid = [int]$ev.Id
    $meta = if ($EVENT_ID_MAP.ContainsKey($eid)) { $EVENT_ID_MAP[$eid] } else { @{ name='Unmapped event'; severity='info' } }
    $diffMin = ($ev.TimeCreated - $start).TotalMinutes
    $correlated.Add(@{
        event_id                  = $eid
        name                      = $meta.name
        severity                  = $meta.severity
        time                      = $ev.TimeCreated.ToString('o')
        provider                  = $ev.ProviderName
        message                   = ($ev.Message -replace "`r`n",' ').Substring(0, [Math]::Min(400, $ev.Message.Length))
        correlation               = if ([Math]::Abs($diffMin) -le 1) {'strong'} else {'weak'}
        minutes_from_window_start = [Math]::Round($diffMin, 2)
    })
}
$correlated = @($correlated | Sort-Object { [Math]::Abs($_.minutes_from_window_start) })

# Root cause inference
$rootCause = $null; $confidence = 'low'
if ($correlated.Count -gt 0) {
    $hintIds = $ROOT_CAUSE_HINTS[($ctx['problem_type'])]
    if (-not $hintIds) { $hintIds = @() }
    $matches = @($correlated | Where-Object { $hintIds -contains $_.event_id })
    if ($matches.Count -gt 0) {
        $rootCause = "$($matches[0].name) (event $($matches[0].event_id)) at $($matches[0].time)"
        $confidence = 'high'
    } else {
        $crit = @($correlated | Where-Object { $_.severity -eq 'critical' }) | Select-Object -First 1
        if ($crit) { $rootCause = "$($crit.name) at $($crit.time)"; $confidence = 'medium' }
        else       { $rootCause = "$($correlated[0].name) at $($correlated[0].time)" }
    }
}

$findings = @()
foreach ($c in ($correlated | Select-Object -First 10)) {
    $findings += New-SkillFinding `
        -Summary "$($c.name) (event $($c.event_id)) at $($c.time)" `
        -Severity $c.severity `
        -Evidence @{ provider = $c.provider; correlation = $c.correlation; delta_min = $c.minutes_from_window_start }
}
if ($findings.Count -eq 0) {
    $findings = @(New-SkillFinding -Summary 'No correlated events in the requested window' -Severity 'info')
}

Write-SkillResult (New-SkillResult -Skill $SKILL -Ok $true -Findings $findings `
    -RootCause $rootCause -Confidence $confidence `
    -Recommendations @(
        if ($correlated.Count) { 'Inspect the listed events; cross-check with app_crash skill if event 1000/1026 is present.' }
        else                   { 'No system-level events explain the IIS symptom in this window.' }
    ) `
    -Raw @{
        queried_logs            = $Logs
        window                  = @{ start = $start.ToString('o'); end = $end.ToString('o') }
        total_events_returned   = $events.Count
        correlated              = @($correlated)
    })
exit 0
