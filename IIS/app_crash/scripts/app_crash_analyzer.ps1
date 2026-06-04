<#
.SYNOPSIS
  app_crash_analyzer.ps1 - .NET / IIS worker process crash diagnosis (v2 PS edition).
#>
[CmdletBinding()]
param([string] $Context)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Import-Module (Join-Path $root '_shared\Contract.psm1') -Force

$SKILL = 'app_crash'
$PROVIDERS = @('.NET Runtime','Application Error','IIS-W3SVC-WP','ASP.NET 4.0.30319.0')

$FAMILY_TOKENS = @(
    @('outofmemory',       'memory_exhaustion'),
    @('stackoverflow',     'stack_overflow'),
    @('nullreference',     'null_reference'),
    @('argumentnull',      'invalid_argument'),
    @('argumentexception', 'invalid_argument'),
    @('timeout',           'operation_timeout'),
    @('sqlexception',      'database_error'),
    @('invalidoperation',  'invalid_operation'),
    @('filenotfound',      'io_error'),
    @('ioexception',       'io_error'),
    @('threadabort',       'thread_aborted')
)

$REMEDIATION = @{
    memory_exhaustion = @{ cause='Worker process exhausted available memory';   immediate='Recycle the application pool';      actions=@('Profile for leaks','Raise app pool memory limit','Tune GC / cache eviction') }
    stack_overflow    = @{ cause='Unbounded recursion';                          immediate='Patch and redeploy; recycle pool';  actions=@('Audit recursive functions','Add depth limit') }
    null_reference    = @{ cause='Null dereference in application code';         immediate='Patch and redeploy';                actions=@('Add null guards','Improve input validation') }
    operation_timeout = @{ cause='An external operation exceeded its timeout';   immediate='Increase timeout temporarily';      actions=@('Check downstream latency','Tune executionTimeout / connection timeouts') }
    database_error    = @{ cause='Database call failed';                         immediate='Confirm DB service is up';          actions=@('Verify connection string','Check DB availability','Review long-running queries') }
}
$REM_DEFAULT = @{ cause='Unclassified application exception'; immediate='Recycle the application pool'; actions=@('Inspect full stack trace','Recycle the app pool') }

function Get-CrashFamily {
    param([string] $Message)
    $m = ($Message ?? '').ToLowerInvariant()
    foreach ($pair in $FAMILY_TOKENS) {
        if ($m.Contains($pair[0])) { return $pair[1] }
    }
    return 'unclassified'
}

$ctx = Read-SkillContext -Argument $Context
$range = Get-SkillTimeRange -Context $ctx
$start = $range[0]; $end = $range[1]
if (-not $start -or -not $end) {
    $end = (Get-Date); $start = $end.AddHours(-1)
}

$events = @()
try {
    $filter = @{
        LogName      = 'Application'
        ProviderName = $PROVIDERS
        StartTime    = $start
        EndTime      = $end
    }
    $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue)
} catch { }

if ($events.Count -eq 0) {
    Write-SkillResult (New-SkillResult -Skill $SKILL -Ok $true `
        -Findings @((New-SkillFinding -Summary "No crash events from $($PROVIDERS -join ', ') in window." -Severity 'info')) `
        -Confidence 'low' `
        -Recommendations @('No app crash explains this symptom; consider resource_monitor.') `
        -Raw @{
            window    = @{ start=$start.ToString('o'); end=$end.ToString('o') }
            providers = $PROVIDERS
        })
    exit 0
}

$families = @{}
foreach ($e in $events) {
    $f = Get-CrashFamily $e.Message
    if (-not $families.ContainsKey($f)) { $families[$f] = 0 }
    $families[$f]++
}
$topFamily = ($families.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Key
$rem = if ($REMEDIATION.ContainsKey($topFamily)) { $REMEDIATION[$topFamily] } else { $REM_DEFAULT }

$samples = @()
foreach ($e in ($events | Select-Object -First 5)) {
    $msg = ($e.Message ?? '')
    $samples += @{
        time      = $e.TimeCreated.ToString('o')
        provider  = $e.ProviderName
        id        = [int]$e.Id
        family    = (Get-CrashFamily $e.Message)
        snippet   = $msg.Substring(0, [Math]::Min(300, $msg.Length))
    }
}

$findings = $families.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
    $sev = if ($_.Key -in 'memory_exhaustion','stack_overflow') {'critical'} else {'warning'}
    New-SkillFinding -Summary "$($_.Value) crash event(s) classified as $($_.Key)" -Severity $sev `
        -Evidence @{ family=$_.Key; count=$_.Value }
}

Write-SkillResult (New-SkillResult -Skill $SKILL -Ok $true -Findings $findings `
    -RootCause $rem.cause `
    -Confidence (if ($topFamily -ne 'unclassified') {'high'} else {'medium'}) `
    -Recommendations (@("Immediate: $($rem.immediate)") + $rem.actions) `
    -Raw @{
        total_events        = $events.Count
        family_distribution = $families
        top_family          = $topFamily
        samples             = $samples
    })
exit 0
