<#
.SYNOPSIS
  Shared PowerShell contract for IIS skill collection (mirrors _shared/contract.py).

.DESCRIPTION
  Exposes:
    - Get-SkillRegistry          : load _shared/registry.json
    - Resolve-SkillEntry         : absolute path of a skill's entry script
    - Read-SkillContext          : parse arg as JSON string, @file, or stdin/{}
    - New-SkillResult            : build a contract envelope
    - Write-SkillResult          : emit envelope as JSON to stdout
    - ConvertTo-SkillTime        : ISO-8601 -> [datetime]
    - Get-SkillTimeRange         : (start, end) from context.time_range
    - Test-InTimeWindow          : window membership with tolerance
    - New-SkillFinding           : build a finding hashtable

  Python 3.10+/PowerShell 5.1+ compatible. No external modules.
#>

$script:RootPath = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

function Get-SkillRegistry {
    [CmdletBinding()] param()
    $registryFile = Join-Path $script:RootPath '_shared/registry.json'
    Get-Content -LiteralPath $registryFile -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Resolve-SkillEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $SkillId,
        [ValidateSet('python','pwsh')] [string] $Runtime = 'pwsh'
    )
    $reg = Get-SkillRegistry
    if (-not $reg.skills.$SkillId) { throw "Unknown skill: $SkillId" }
    $rel = $reg.skills.$SkillId.entry.$Runtime
    if (-not $rel) { throw "Skill $SkillId has no $Runtime entry" }
    return (Join-Path $script:RootPath $rel)
}

function Read-SkillContext {
    [CmdletBinding()]
    param([string] $Argument)
    if ([string]::IsNullOrWhiteSpace($Argument)) {
        # Try stdin if it's piped
        if (-not [Console]::IsInputRedirected) { return @{} }
        $raw = [Console]::In.ReadToEnd()
        if ([string]::IsNullOrWhiteSpace($raw)) { return @{} }
        return ($raw | ConvertFrom-Json -AsHashtable -ErrorAction Stop)
    }
    if ($Argument.StartsWith('@')) {
        $p = $Argument.Substring(1)
        return (Get-Content -LiteralPath $p -Raw -Encoding UTF8 |
                ConvertFrom-Json -AsHashtable -ErrorAction Stop)
    }
    try {
        return ($Argument | ConvertFrom-Json -AsHashtable -ErrorAction Stop)
    } catch {
        if (Test-Path -LiteralPath $Argument) {
            return (Get-Content -LiteralPath $Argument -Raw -Encoding UTF8 |
                    ConvertFrom-Json -AsHashtable -ErrorAction Stop)
        }
        throw
    }
}

function New-SkillFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Summary,
        [ValidateSet('critical','warning','info')] [string] $Severity = 'info',
        [hashtable] $Evidence = @{}
    )
    [ordered]@{
        summary  = $Summary
        severity = $Severity
        evidence = $Evidence
    }
}

function New-SkillSolution {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Title,
        [string[]] $Steps = @(),
        [string] $ProblemRef = $null,
        [ValidateSet('critical','warning','info')] [string] $Severity = 'info',
        [string[]] $References = @()
    )
    [ordered]@{
        title       = $Title
        steps       = @($Steps)
        problem_ref = $ProblemRef
        severity    = $Severity
        references  = @($References)
    }
}

function New-SkillNextStep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Action,
        [string] $Why = $null,
        [string] $Skill = $null
    )
    [ordered]@{
        action = $Action
        why    = $Why
        skill  = $Skill
    }
}

function New-SkillLogRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $LogKind,
        [Parameter(Mandatory)] [string] $Why,
        [string] $HowToCollect = $null,
        [string] $Skill = $null
    )
    [ordered]@{
        log_kind        = $LogKind
        why             = $Why
        how_to_collect  = $HowToCollect
        skill           = $Skill
    }
}

function _Get-FlattenedRecommendations {
    param($Solutions, $NextSteps, $LogReqs)
    $out = @()
    foreach ($s in @($Solutions)) {
        if (-not $s) { continue }
        $tag  = if ($s.problem_ref) { "[fix:$($s.problem_ref)]" } else { '[fix]' }
        $head = "$tag $($s.title)"
        if ($s.steps -and $s.steps.Count -gt 0) { $head += " — $($s.steps[0])" }
        $out += $head
    }
    foreach ($n in @($NextSteps)) {
        if (-not $n) { continue }
        $tag = if ($n.skill) { "[next:$($n.skill)]" } else { '[next]' }
        $out += "$tag $($n.action)"
    }
    foreach ($l in @($LogReqs)) {
        if (-not $l) { continue }
        $out += "[logs:$($l.log_kind)] $($l.why)"
    }
    return $out
}

function New-SkillResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Skill,
        [bool]   $Ok = $true,
        [object[]] $Findings = @(),
        [string] $RootCause = $null,
        [ValidateSet('high','medium','low')] [string] $Confidence = 'low',
        [string[]] $Recommendations = @(),
        [object[]] $Solutions = @(),
        [object[]] $NextSteps = @(),
        [object[]] $AdditionalLogsNeeded = @(),
        [hashtable] $Raw = @{},
        [string] $ErrorMessage = $null
    )
    if ((-not $Recommendations -or $Recommendations.Count -eq 0) -and `
        (($Solutions -and $Solutions.Count -gt 0) -or `
         ($NextSteps -and $NextSteps.Count -gt 0) -or `
         ($AdditionalLogsNeeded -and $AdditionalLogsNeeded.Count -gt 0))) {
        $Recommendations = _Get-FlattenedRecommendations -Solutions $Solutions `
                                                          -NextSteps $NextSteps `
                                                          -LogReqs $AdditionalLogsNeeded
    }
    [ordered]@{
        skill                  = $Skill
        ok                     = $Ok
        findings               = @($Findings)
        root_cause             = $RootCause
        confidence             = $Confidence
        recommendations        = @($Recommendations)
        solutions              = @($Solutions)
        next_steps             = @($NextSteps)
        additional_logs_needed = @($AdditionalLogsNeeded)
        raw                    = $Raw
        error            = $ErrorMessage
        generated_at     = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function Write-SkillResult {
    [CmdletBinding()] param([Parameter(Mandatory)][object] $Result)
    # -Depth 12 is plenty for our envelopes; -Compress keeps it stdout-friendly when piped
    $Result | ConvertTo-Json -Depth 12 | Write-Output
}

function ConvertTo-SkillTime {
    [CmdletBinding()] param([Parameter(Mandatory)] [string] $Value)
    [datetime]::Parse($Value.Trim().Replace('Z','+00:00'))
}

function Get-SkillTimeRange {
    [CmdletBinding()] param([Parameter(Mandatory)] [hashtable] $Context)
    $tr = $Context['time_range']
    $start = $null; $end = $null
    if ($tr) {
        if ($tr['start']) { $start = ConvertTo-SkillTime $tr['start'] }
        if ($tr['end'])   { $end   = ConvertTo-SkillTime $tr['end'] }
    }
    return ,@($start, $end)
}

function Test-InTimeWindow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [datetime] $Timestamp,
        [Nullable[datetime]] $Start = $null,
        [Nullable[datetime]] $End   = $null,
        [double] $ToleranceMinutes  = 0
    )
    $tol = [timespan]::FromMinutes($ToleranceMinutes)
    if ($Start -and $Timestamp -lt $Start - $tol) { return $false }
    if ($End   -and $Timestamp -gt $End   + $tol) { return $false }
    return $true
}

Export-ModuleMember -Function `
    Get-SkillRegistry, Resolve-SkillEntry, Read-SkillContext,
    New-SkillFinding, New-SkillSolution, New-SkillNextStep, New-SkillLogRequest,
    New-SkillResult, Write-SkillResult,
    ConvertTo-SkillTime, Get-SkillTimeRange, Test-InTimeWindow
