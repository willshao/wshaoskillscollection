<#
.SYNOPSIS
  security_audit_analyzer.ps1 - Auth/permission diagnosis (real implementation, v2 PS).
.DESCRIPTION
  Queries the Windows Security log for failed logons (4625), object-access
  denials (4656/4663), and privilege use (4672) inside context.time_range,
  then summarizes top failing principals, target objects, and source IPs.
  Cross-checks the source IPs against context.extra.suspicious_ips.

  Requires elevation AND audit policy enabled
  (auditpol /set /subcategory:"Logon" /failure:enable, etc.).
#>
[CmdletBinding()]
param([string] $Context)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Import-Module (Join-Path $root '_shared\Contract.psm1') -Force

$SKILL = 'security_audit'
$EVENT_IDS = 4625, 4656, 4663, 4672

$EVENT_NAMES = @{
    4625 = 'Failed logon'
    4656 = 'Object handle requested'
    4663 = 'Object access attempt'
    4672 = 'Special privileges assigned'
}

# Common failure-reason sub-codes shipped in 4625 events
$LOGON_FAILURE_REASONS = @{
    '0xC0000064' = 'Unknown user name'
    '0xC000006A' = 'Bad password'
    '0xC000006D' = 'Bad user name or password'
    '0xC0000071' = 'Password expired'
    '0xC0000072' = 'Account disabled'
    '0xC000006F' = 'Outside permitted hours'
    '0xC0000193' = 'Account expired'
    '0xC0000234' = 'Account locked out'
    '0xC0000133' = 'Time difference between client/server'
}

function Extract-Field {
    param([string] $Message, [string] $Label)
    $m = [regex]::Match($Message, [regex]::Escape($Label) + '\s*:\s*([^\r\n\t]+)')
    if ($m.Success) { return $m.Groups[1].Value.Trim() }
    return $null
}

$ctx   = Read-SkillContext -Argument $Context
$range = Get-SkillTimeRange -Context $ctx
$start = $range[0]; $end = $range[1]
if (-not $start -or -not $end) {
    $end = (Get-Date); $start = $end.AddHours(-1)
}

# Read suspicious-ip hint, if any (from iis_logs problem evidence)
$suspIps = @()
if ($ctx.ContainsKey('extra') -and $ctx.extra -and $ctx.extra.ContainsKey('suspicious_ips')) {
    $suspIps = @($ctx.extra.suspicious_ips)
}

$events = @()
$elevated = $true
try {
    $filter = @{
        LogName   = 'Security'
        Id        = $EVENT_IDS
        StartTime = $start
        EndTime   = $end
    }
    $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop)
} catch [System.UnauthorizedAccessException] {
    $elevated = $false
} catch {
    # Most common: "No events were found that match the specified selection criteria."
    $events = @()
}

if (-not $elevated) {
    Write-SkillResult (New-SkillResult -Skill $SKILL -Ok $true `
        -Findings @((New-SkillFinding -Summary 'Security log requires an elevated session.' -Severity 'warning')) `
        -Confidence 'low' `
        -Recommendations @('Re-run pwsh as Administrator and retry this skill.') `
        -Raw @{ window = @{ start=$start.ToString('o'); end=$end.ToString('o') } })
    exit 0
}

if ($events.Count -eq 0) {
    Write-SkillResult (New-SkillResult -Skill $SKILL -Ok $true `
        -Findings @((New-SkillFinding -Summary 'No relevant security events in window.' -Severity 'info')) `
        -Confidence 'low' `
        -Recommendations @('No auth/permission anomalies were recorded; check whether audit policy is enabled.') `
        -Raw @{
            window      = @{ start=$start.ToString('o'); end=$end.ToString('o') }
            event_ids   = $EVENT_IDS
        })
    exit 0
}

$byId         = @{}
$byPrincipal  = @{}
$byTarget     = @{}
$bySrcIp      = @{}
$failureRsn   = @{}
$samples      = New-Object System.Collections.Generic.List[hashtable]

foreach ($e in $events) {
    $eid = [int]$e.Id
    $byId[$eid] = ($byId[$eid] + 1)
    $msg = $e.Message ?? ''

    $user = Extract-Field $msg 'Account Name'
    $obj  = Extract-Field $msg 'Object Name'
    $src  = Extract-Field $msg 'Source Network Address'
    $rsn  = Extract-Field $msg 'Status'

    if ($user) { $byPrincipal[$user]  = ($byPrincipal[$user]  + 1) }
    if ($obj)  { $byTarget[$obj]      = ($byTarget[$obj]      + 1) }
    if ($src -and $src -ne '-') {
        $bySrcIp[$src] = ($bySrcIp[$src] + 1)
    }
    if ($eid -eq 4625 -and $rsn) {
        $reasonText = if ($LOGON_FAILURE_REASONS.ContainsKey($rsn)) { $LOGON_FAILURE_REASONS[$rsn] } else { $rsn }
        $failureRsn[$reasonText] = ($failureRsn[$reasonText] + 1)
    }

    if ($samples.Count -lt 5) {
        $samples.Add(@{
            id        = $eid
            name      = $EVENT_NAMES[$eid]
            time      = $e.TimeCreated.ToString('o')
            user      = $user
            target    = $obj
            source_ip = $src
            reason    = $rsn
        })
    }
}

# Build findings
$findings = @()
foreach ($eid in ($byId.Keys | Sort-Object)) {
    $sev = if ($eid -eq 4625) {'warning'} else {'info'}
    $findings += New-SkillFinding `
        -Summary "Event $eid ($($EVENT_NAMES[$eid])): $($byId[$eid]) occurrences" `
        -Severity $sev -Evidence @{ event_id=$eid; count=$byId[$eid] }
}

$topPrincipals = $byPrincipal.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5
foreach ($p in $topPrincipals) {
    if ($p.Value -ge 5) {
        $findings += New-SkillFinding -Summary "Principal '$($p.Key)' generated $($p.Value) security events" `
            -Severity 'warning' -Evidence @{ principal=$p.Key; count=$p.Value }
    }
}

# Cross-check suspicious IPs from iis_logs context
$ipMatches = @()
foreach ($ip in $suspIps) {
    if ($bySrcIp.ContainsKey($ip)) { $ipMatches += @{ ip=$ip; count=$bySrcIp[$ip] } }
}
foreach ($m in $ipMatches) {
    $findings += New-SkillFinding -Summary "Source IP $($m.ip) flagged by iis_logs also appears in security events ($($m.count)x)" `
        -Severity 'critical' -Evidence $m
}

# Root cause inference (priority: locked-out / bad-pw bursts > IP correlation > generic)
$rootCause = $null; $confidence = 'low'
if ($ipMatches.Count -gt 0) {
    $rootCause = "Source IP $($ipMatches[0].ip) cross-referenced from iis_logs"
    $confidence = 'high'
} elseif ($failureRsn.Count -gt 0) {
    $top = $failureRsn.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1
    $rootCause = "Failed-logon reason: $($top.Key) ($($top.Value)x)"
    $confidence = 'medium'
} elseif ($topPrincipals -and $topPrincipals[0].Value -ge 5) {
    $rootCause = "Principal '$($topPrincipals[0].Key)' has unusual security activity"
    $confidence = 'medium'
}

Write-SkillResult (New-SkillResult -Skill $SKILL -Ok $true -Findings $findings `
    -RootCause $rootCause -Confidence $confidence `
    -Recommendations @(
        if ($ipMatches.Count -gt 0) { "Block source IP(s): $((($ipMatches | ForEach-Object { $_.ip }) -join ', '))" }
        if ($failureRsn.Count -gt 0) { 'Review failed-logon reasons; tighten password policy or enable account lockout if bad-password is dominant.' }
        if ($findings.Count -eq 0)   { 'No actionable findings.' }
    ) `
    -Raw @{
        window               = @{ start=$start.ToString('o'); end=$end.ToString('o') }
        event_id_distribution = $byId
        top_principals        = @($topPrincipals | ForEach-Object { @{ principal=$_.Key; count=$_.Value } })
        top_target_objects    = @($byTarget.GetEnumerator()    | Sort-Object Value -Descending | Select-Object -First 5 | ForEach-Object { @{ object=$_.Key; count=$_.Value } })
        top_source_ips        = @($bySrcIp.GetEnumerator()     | Sort-Object Value -Descending | Select-Object -First 5 | ForEach-Object { @{ ip=$_.Key; count=$_.Value } })
        failure_reasons       = $failureRsn
        suspicious_ip_matches = $ipMatches
        samples               = @($samples)
    })
exit 0
