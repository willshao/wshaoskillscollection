<#
.SYNOPSIS
  firewall_analyzer.ps1 - Windows Firewall log analyzer (real implementation, v2 PS).
.DESCRIPTION
  Parses pfirewall.log (W3C-style header), filters by context.time_range,
  aggregates DROP actions per source IP, cross-checks with the suspicious
  IPs identified by iis_logs (context.extra.suspicious_ips), and produces
  ready-to-paste New-NetFirewallRule snippets.
#>
[CmdletBinding()]
param(
    [string] $Context,
    [string] $LogPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Import-Module (Join-Path $root '_shared\Contract.psm1') -Force

$SKILL = 'firewall'
$DEFAULT_LOG = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"

function Resolve-FwLog {
    param([string] $Override)
    if ($Override) { return $Override }
    if (Test-Path -LiteralPath $DEFAULT_LOG) { return $DEFAULT_LOG }
    return $null
}

function Parse-FwLog {
    param([Parameter(Mandatory)] [string] $File)
    $fields = $null
    foreach ($line in [System.IO.File]::ReadLines($File)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line.StartsWith('#')) {
            if ($line.StartsWith('#Fields:')) {
                $fields = ($line.Substring(8)).Trim() -split '\s+'
            }
            continue
        }
        if (-not $fields) { continue }
        $parts = $line -split '\s+'
        if ($parts.Count -lt $fields.Count) { continue }
        $row = [ordered]@{}
        for ($i=0; $i -lt $fields.Count; $i++) { $row[$fields[$i]] = $parts[$i] }
        # Try to pull common fields (column names from Windows Firewall log header)
        [pscustomobject]@{
            timestamp = "$($row['date']) $($row['time'])"
            action    = $row['action']
            protocol  = $row['protocol']
            src_ip    = $row['src-ip']
            dst_ip    = $row['dst-ip']
            src_port  = $row['src-port']
            dst_port  = $row['dst-port']
        }
    }
}

$ctx   = Read-SkillContext -Argument $Context
$range = Get-SkillTimeRange -Context $ctx
$start = $range[0]; $end = $range[1]

$suspIps = @()
if ($ctx.ContainsKey('extra') -and $ctx.extra -and $ctx.extra.ContainsKey('suspicious_ips')) {
    $suspIps = @($ctx.extra.suspicious_ips)
}

$logFile = Resolve-FwLog -Override $LogPath
if (-not $logFile) {
    Write-SkillResult (New-SkillResult -Skill $SKILL -Ok $true `
        -Findings @((New-SkillFinding -Summary "Firewall log not found at $DEFAULT_LOG. Logging may be disabled." -Severity 'info' `
                       -Evidence @{ default_path = $DEFAULT_LOG })) `
        -Confidence 'low' `
        -Recommendations @(
            'Enable firewall logging: netsh advfirewall set currentprofile logging filename %systemroot%\System32\LogFiles\Firewall\pfirewall.log',
            'netsh advfirewall set currentprofile logging droppedconnections enable'
        ) `
        -Raw @{ log_file=$null })
    exit 0
}

$rows = New-Object System.Collections.Generic.List[object]
foreach ($r in (Parse-FwLog -File $logFile)) {
    if ($start -or $end) {
        try {
            $ts = [datetime]::ParseExact($r.timestamp, 'yyyy-MM-dd HH:mm:ss', $null)
            if (-not (Test-InTimeWindow -Timestamp $ts -Start $start -End $end -ToleranceMinutes 2)) { continue }
        } catch { continue }
    }
    $rows.Add($r)
}

$drops = @($rows | Where-Object { $_.action -eq 'DROP' })
$dropByIp = $drops | Group-Object src_ip | Sort-Object Count -Descending

$findings = @()
foreach ($g in ($dropByIp | Select-Object -First 5)) {
    $sev = if ($g.Count -ge 100) {'warning'} else {'info'}
    $findings += New-SkillFinding `
        -Summary "Source IP $($g.Name) had $($g.Count) DROP events" `
        -Severity $sev -Evidence @{ ip=$g.Name; drops=$g.Count }
}

$crossMatches = @()
foreach ($ip in $suspIps) {
    $hit = $dropByIp | Where-Object { $_.Name -eq $ip } | Select-Object -First 1
    if ($hit) { $crossMatches += @{ ip=$ip; drops=$hit.Count } }
}
foreach ($m in $crossMatches) {
    $findings += New-SkillFinding `
        -Summary "iis_logs-flagged IP $($m.ip) confirmed by firewall ($($m.drops) drops)" `
        -Severity 'critical' -Evidence $m
}

if ($findings.Count -eq 0) {
    $findings += New-SkillFinding -Summary 'No DROP events in window.' -Severity 'info'
}

# Build ready-to-paste block rules
$ruleSnippets = @()
foreach ($ip in (@($crossMatches | ForEach-Object { $_.ip }) +
                 @($dropByIp | Select-Object -First 1 | ForEach-Object { $_.Name })) | Where-Object { $_ } | Sort-Object -Unique) {
    $ruleSnippets += "New-NetFirewallRule -DisplayName 'Block $ip (auto-suggested)' -Direction Inbound -Action Block -RemoteAddress $ip"
}

$rootCause = $null; $confidence = 'low'
if ($crossMatches.Count -gt 0) {
    $rootCause = "Source IP $($crossMatches[0].ip) confirmed as DDoS-like by firewall drops"
    $confidence = 'high'
} elseif ($dropByIp.Count -gt 0 -and $dropByIp[0].Count -ge 100) {
    $rootCause = "Source IP $($dropByIp[0].Name) generated $($dropByIp[0].Count) DROP events"
    $confidence = 'medium'
}

Write-SkillResult (New-SkillResult -Skill $SKILL -Ok $true -Findings $findings `
    -RootCause $rootCause -Confidence $confidence `
    -Recommendations (@('Review the suggested block rules below before applying.') + $ruleSnippets) `
    -Raw @{
        log_file              = $logFile
        rows_parsed           = $rows.Count
        drop_count            = $drops.Count
        top_drop_sources      = @($dropByIp | Select-Object -First 5 | ForEach-Object { @{ ip=$_.Name; drops=$_.Count } })
        suspicious_ip_matches = $crossMatches
        suggested_rules       = $ruleSnippets
    })
exit 0
