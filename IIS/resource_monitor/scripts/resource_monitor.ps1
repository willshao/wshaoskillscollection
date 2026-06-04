<#
.SYNOPSIS
  resource_monitor.ps1 - System resource monitor (real implementation, v2 PS).
.DESCRIPTION
  Samples Windows performance counters (CPU, available memory, w3wp working
  set, physical-disk latency) for ~10 seconds and reports any threshold
  breaches. Designed to be called by the orchestrator while an IIS
  high_latency window is being investigated.
#>
[CmdletBinding()]
param(
    [string] $Context,
    [int]    $SampleSeconds = 10,
    [int]    $SampleInterval = 1
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Import-Module (Join-Path $root '_shared\Contract.psm1') -Force

$SKILL = 'resource_monitor'

# Pressure thresholds
$TH = @{
    CpuPct          = 85.0
    MemAvailableMB  = 512
    DiskSecondsP95  = 0.025   # 25 ms
    W3wpWsBytes     = 1.5GB
}

$ctx = Read-SkillContext -Argument $Context

$counters = @(
    '\Processor(_Total)\% Processor Time',
    '\Memory\Available MBytes',
    '\PhysicalDisk(_Total)\Avg. Disk sec/Read',
    '\PhysicalDisk(_Total)\Avg. Disk sec/Write',
    '\Process(w3wp*)\Working Set'
)

$maxSamples = [Math]::Max(2, [int]($SampleSeconds / $SampleInterval))
$samples = @()
try {
    $samples = @(Get-Counter -Counter $counters -SampleInterval $SampleInterval -MaxSamples $maxSamples -ErrorAction Stop)
} catch [System.UnauthorizedAccessException] {
    Write-SkillResult (New-SkillResult -Skill $SKILL -Ok $true `
        -Findings @((New-SkillFinding -Summary 'Performance counters require an elevated session.' -Severity 'warning')) `
        -Confidence 'low' `
        -Recommendations @('Re-run pwsh as Administrator.') `
        -Raw @{ counters = $counters })
    exit 0
} catch {
    Write-SkillResult (New-SkillResult -Skill $SKILL -Ok $true `
        -Findings @((New-SkillFinding -Summary "Counter sampling failed: $($_.Exception.Message)" -Severity 'warning')) `
        -Confidence 'low' `
        -Recommendations @('Verify Performance Counter service and counter availability with `lodctr /q`.') `
        -Raw @{ counters = $counters })
    exit 0
}

# Bucket counter samples by short name
$bucket = @{
    cpu     = New-Object System.Collections.Generic.List[double]
    memMB   = New-Object System.Collections.Generic.List[double]
    diskRd  = New-Object System.Collections.Generic.List[double]
    diskWr  = New-Object System.Collections.Generic.List[double]
    w3wp    = @{}   # instance -> [list[double]]
}

foreach ($s in $samples) {
    foreach ($cs in $s.CounterSamples) {
        $p = $cs.Path.ToLowerInvariant()
        switch -Regex ($p) {
            '\\processor\(_total\)\\% processor time'       { $bucket.cpu.Add($cs.CookedValue);    break }
            '\\memory\\available mbytes'                    { $bucket.memMB.Add($cs.CookedValue);  break }
            '\\physicaldisk\(_total\)\\avg\. disk sec/read' { $bucket.diskRd.Add($cs.CookedValue); break }
            '\\physicaldisk\(_total\)\\avg\. disk sec/write'{ $bucket.diskWr.Add($cs.CookedValue); break }
            '\\process\(w3wp.*\)\\working set'              {
                $inst = ($cs.InstanceName ?? 'w3wp')
                if (-not $bucket.w3wp.ContainsKey($inst)) {
                    $bucket.w3wp[$inst] = New-Object System.Collections.Generic.List[double]
                }
                $bucket.w3wp[$inst].Add($cs.CookedValue)
                break
            }
        }
    }
}

function Stat {
    param([System.Collections.Generic.List[double]] $Values)
    if (-not $Values -or $Values.Count -eq 0) { return $null }
    $sorted = @($Values | Sort-Object)
    $idx = [Math]::Min($sorted.Count - 1, [Math]::Max(0, [int]($sorted.Count * 0.95) - 1))
    return @{
        avg = ($sorted | Measure-Object -Average).Average
        max = $sorted[-1]
        p95 = $sorted[$idx]
        n   = $sorted.Count
    }
}

$cpuStat   = Stat $bucket.cpu
$memStat   = Stat $bucket.memMB
$diskRdStat= Stat $bucket.diskRd
$diskWrStat= Stat $bucket.diskWr

$w3wpStats = @{}
foreach ($k in $bucket.w3wp.Keys) { $w3wpStats[$k] = Stat $bucket.w3wp[$k] }

# Build findings + remediation hints
$findings = @()
$breaches = @()

if ($cpuStat -and $cpuStat.p95 -ge $TH.CpuPct) {
    $findings += New-SkillFinding -Summary "CPU p95 = $([Math]::Round($cpuStat.p95,1))% (threshold $($TH.CpuPct)%)" `
                    -Severity 'critical' -Evidence $cpuStat
    $breaches += 'cpu'
}
if ($memStat -and $memStat.avg -le $TH.MemAvailableMB) {
    $findings += New-SkillFinding -Summary "Available memory avg = $([Math]::Round($memStat.avg,0)) MB (threshold $($TH.MemAvailableMB) MB)" `
                    -Severity 'critical' -Evidence $memStat
    $breaches += 'memory'
}
if ($diskRdStat -and $diskRdStat.p95 -ge $TH.DiskSecondsP95) {
    $findings += New-SkillFinding -Summary "Disk read latency p95 = $([Math]::Round($diskRdStat.p95*1000,1)) ms" `
                    -Severity 'warning' -Evidence $diskRdStat
    $breaches += 'disk_read'
}
if ($diskWrStat -and $diskWrStat.p95 -ge $TH.DiskSecondsP95) {
    $findings += New-SkillFinding -Summary "Disk write latency p95 = $([Math]::Round($diskWrStat.p95*1000,1)) ms" `
                    -Severity 'warning' -Evidence $diskWrStat
    $breaches += 'disk_write'
}
foreach ($inst in $w3wpStats.Keys) {
    $st = $w3wpStats[$inst]
    if ($st -and $st.max -ge $TH.W3wpWsBytes) {
        $findings += New-SkillFinding -Summary "Worker '$inst' working set max = $([Math]::Round($st.max/1MB,0)) MB" `
                        -Severity 'warning' -Evidence (@{ instance=$inst } + $st)
        $breaches += "w3wp:$inst"
    }
}

if ($findings.Count -eq 0) {
    $findings += New-SkillFinding -Summary 'No threshold breaches during sampling window.' -Severity 'info'
}

$rootCause = $null; $confidence = 'low'
if ('cpu' -in $breaches -and 'memory' -in $breaches) {
    $rootCause = 'Combined CPU + memory pressure'; $confidence = 'high'
} elseif ($breaches.Count -gt 0) {
    $rootCause = "Resource pressure: $($breaches -join ', ')"; $confidence = 'medium'
}

$recs = @()
if ('cpu'    -in $breaches) { $recs += 'Profile worker CPU; identify hot endpoints.' }
if ('memory' -in $breaches) { $recs += 'Investigate memory leak; raise app pool memory limit; tune cache.' }
if ($breaches | Where-Object { $_ -like 'disk_*' }) { $recs += 'Disk subsystem is slow; check antivirus exclusions and storage health.' }
if ($breaches | Where-Object { $_ -like 'w3wp:*' }) { $recs += 'Recycle the affected worker(s) and capture a memory dump for offline analysis.' }
if ($recs.Count -eq 0) { $recs = @('No remediation needed; resources are within limits.') }

Write-SkillResult (New-SkillResult -Skill $SKILL -Ok $true -Findings $findings `
    -RootCause $rootCause -Confidence $confidence -Recommendations $recs `
    -Raw @{
        sample_count    = $samples.Count
        window_seconds  = $SampleSeconds
        cpu             = $cpuStat
        memory_mb       = $memStat
        disk_sec_read   = $diskRdStat
        disk_sec_write  = $diskWrStat
        w3wp            = $w3wpStats
        breaches        = $breaches
    })
exit 0
