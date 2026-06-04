---
id: iis_logs
name: iis_logs
version: 2.0
role: entry_point
description: Parse IIS W3C logs, compute KPIs (p95/p99/error rates), classify problems, and recommend follow-up skills.
runtime:
  python: scripts/iis_analyzer.py
  pwsh:   scripts/iis_analyzer.ps1
needs_admin: false
---

## When to use
First step for any IIS performance or reliability question. Run me before any other skill in this collection.

## Inputs

| Name | Type | Required | Notes |
|---|---|---|---|
| `log` | path | yes | A single `.log` file **or a directory**. Directories are walked recursively (depth-first); every `.log` file is classified by its `#Software:` header and only IIS W3C files are parsed. |
| `--auto-trigger` | flag | no | After analysis, invoke the skills listed in `raw.skills_to_trigger` via subprocess (`orchestrator/scripts/skill_orchestrator.py`) and append their results to the output JSON. Without this flag, the report only lists recommended skills and invokes nothing. |
| `--no-recursive` | flag | no | Disable subdirectory walk |
| `--bucket DUR` | string | no | Time-series bucket size (`30s`, `1m`, `5m`, `1h`). Default `1m` |
| `--around TS` | repeatable | no | Anchor timestamp (e.g. `"2026-05-26 10:15:30"`); returns requests inside `±--window` |
| `--window DUR` | string | no | Half-width of each `--around` query. Default `5m` |
| `--filter EXPR` | string | no | Multi-key filter; applied to global search and inside every `--around` window (see syntax below) |
| `--report PATH` | path | no | Write a self-contained HTML report (inline SVG charts) to PATH |

This skill reads IIS log files directly; it does **not** consume a JSON context.

### Folder auto-discovery

When `log` is a directory, the skill recursively walks it and classifies every
`.log` by its `#Software:` header. **Only files classified as IIS W3C are
parsed**; FTP and HTTPERR files are listed in `raw.detected_other_logs` and
surfaced as recommendations to run the matching skill (`ftp_logs`,
`httperror`). Pass `--no-recursive` to limit the scan to the top level.

### Filter syntax

Comma-separated `key=value` pairs:

| Key | Meaning |
|---|---|
| `method=GET` | Exact `cs-method` (case-insensitive) |
| `uri=^/api/` | `cs-uri-stem` regex (`re.search`) |
| `status=500` or `status=500-599` | Single status or inclusive range |
| `ip=10.0.0.1` or `ip=10.0.0.0/24` | Exact IP or CIDR (IPv4/IPv6) |
| `min-time=2000` | `time-taken ≥ N` ms (slow-request hunt) |
| `ua=bot` | `cs(User-Agent)` regex (case-insensitive) |
| `q=token` | Substring match on `cs-uri-query` |

Unknown keys raise a hard error so typos surface immediately.

## Output (contract envelope)

Conforms to [skill_result.schema.json](../_shared/schemas/skill_result.schema.json). Key fields in `raw`:

```json
{
  "metrics":  { "p99_response_time_ms": 8500, "error_5xx_count": 60, "time_range": {...} },
  "problems": [ { "type": "5xx_error", "severity": "critical", "follow_ups": ["httperror","event_log","app_crash"] } ],
  "skills_to_trigger": ["app_crash","event_log","httperror"]
}
```

`problems[].type` ∈ `5xx_error | high_latency | auth_error | suspicious_traffic | not_found`.
Mapping from problem type → follow-up skills lives in [_shared/registry.json](../_shared/registry.json).

## Invocation

```powershell
# basic
python IIS_logs/scripts/iis_analyzer.py C:\inetpub\logs\LogFiles\W3SVC1\u_ex260421.log

# batch (whole directory, recursive by default)
python IIS_logs/scripts/iis_analyzer.py C:\inetpub\logs\LogFiles

# auto-trigger orchestrator
python IIS_logs/scripts/iis_analyzer.py <log> --auto-trigger

# investigate around an incident timestamp with filters + HTML report
python IIS_logs/scripts/iis_analyzer.py C:\inetpub\logs\LogFiles `
       --around "2026-04-21 10:15:30" --window 5m `
       --filter "status=500-599,uri=^/api/" `
       --report incident.html

# slow-request hunt across the whole folder, 30-second buckets
python IIS_logs/scripts/iis_analyzer.py C:\inetpub\logs\LogFiles `
       --bucket 30s --filter "min-time=5000" --report slow.html
```

## Time-series, time-window query & search

The analyzer always produces a time series under `raw.timeseries`:

```jsonc
"timeseries": {
  "bucket_seconds": 60,
  "buckets": [
    {"start": "2026-04-21 10:00:00", "count": 1234,
     "avg_time_ms": 312.5, "p50_time_ms": 120, "p95_time_ms": 1400,
     "p99_time_ms": 5200, "max_time_ms": 9800,
     "error_4xx": 12, "error_5xx": 4}
  ],
  "peak_bucket": { ... }    // when a spike is detected
}
```

When `peak_bucket` is set (count ≥ 5× mean and ≥ 50 requests) a
`traffic_spike` entry is added to `problems`.

`--around TS` produces `raw.around.<TS>` containing
`{window_seconds, summary, entries}`. `--filter` produces `raw.search`
with the matching subset. Both are also rendered in the HTML report.

## HTML report

`--report PATH` writes a single self-contained HTML file with inline SVG:

1. KPI summary cards.
2. Detected problems with severity badges and follow-up skills.
3. Top status codes (bar chart).
4. Requests per bucket (bar chart).
5. Latency percentiles per bucket — p50/p95/p99 multi-series line chart.
6. Throughput + p95 latency dual-axis chart.
7. “Requests around …” section per `--around` anchor (KPIs + table).
8. “Search results” section when `--filter` is non-empty.
9. “Other log files detected” listing FTP / HTTPERR files in the folder.

No external CSS/JS/CDN; the report renders offline.

## Detection thresholds

| Problem | Threshold |
|---|---|
| `5xx_error` | 5xx rate > 1% **or** absolute count > 100 |
| `high_latency` | p99 response time > 5000 ms (critical at > 10000 ms) |
| `auth_error` | 401/403 count > 10 |
| `not_found` | 404 share > 10% |
| `suspicious_traffic` | single client IP > 30% of total traffic |
| `traffic_spike` | one bucket ≥ 5× the mean of the rest **and** ≥ 50 requests (follow_ups left empty by design) |

## Notes
- W3C field layout is read dynamically from the `#Fields:` header, so column ordering does not matter.
- Quoted user-agent / referer fields are parsed with the standard-library `shlex` module.
- Python standard library only — no third-party packages required.
- The contract envelope (`skill`, `ok`, `findings`, `root_cause`, `confidence`, `recommendations`, `raw.metrics`, `raw.problems`, `raw.skills_to_trigger`) is **stable**. New analyses (`raw.timeseries`, `raw.around`, `raw.search`, `raw.detected_other_logs`, `raw.report_html_path`) are additive and the orchestrator does not need to change.

---

## 用途

此技能用于分析IIS（Internet Information Services）日志文件，系统性地识别性能瓶颈和潜在问题。作为**内部诊断工具**，当发现严重错误时，自动建议并协调调用相关专业技能进行**多维度合并分析**。

**核心功能**：
- 🔍 初级诊断：IIS日志层面的问题识别
- 🔗 智能编排：根据问题类型自动触发其他技能
- 📊 联合分析：整合多个数据源的分析结果
- 📋 统一报告：生成跨技能的综合诊断报告

## 何时使用

- 服务器响应缓慢或出现性能问题
- 需要调查HTTP错误或异常请求
- 分析特定时间段内的并发流量模式
- 定期审计和优化Web服务器配置
- 需要生成性能分析报告
- **[新增]** 发现5xx错误时需要深度根因分析

## 工作流程

### 1. 日志采集与准备
- [ ] 收集IIS日志文件（通常位于 `%SystemRoot%\System32\LogFiles\`）
- [ ] 确认日志格式（W3C、IIS或NCSA格式）
- [ ] 验证日志时间范围是否涵盖问题发生期间
- [ ] 检查日志文件大小和完整性

### 2. 数据解析
- [ ] 提取关键字段：
  - 时间戳和请求持续时间 (time-taken)
  - HTTP状态码 (sc-status)
  - 请求方法、URL路径、查询字符串
  - 客户端IP地址 (c-ip)
  - 用户代理和引用页面
  - 发送和接收的字节数

### 3. 指标计算

**性能指标**：
- [ ] 平均请求处理时长
- [ ] 最大/最小响应时间
- [ ] 95%分位数和99%分位数响应时间

**异常指标**：
- [ ] 4xx错误（客户端错误）分布
- [ ] 5xx错误（服务器错误）分布
- [ ] 特定状态码的频率（401、403、404、500等）

**并发指标**：
- [ ] 每分钟请求数 (RPS)
- [ ] 峰值并发请求数
- [ ] 时间段内的请求分布

### 4. 问题识别与跨技能触发
根据计算结果判断，并根据问题严重度自动触发其他技能：

#### 问题分类与触发规则

| 问题类型 | 检测条件 | 触发技能 | 合并分析内容 |
|---------|--------|--------|-----------|
| **5xx服务器错误** | 5xx占比 > 1% 或绝对值 > 100 | ⚡ `httperr分析器`<br/>⚡ `event_log分析器` | IIS错误代码 + Windows事件日志 + 应用程序崩溃 |
| **应用程序崩溃** | 503/500错误激增 | ⚡ `event_log分析器`<br/>⚡ `应用程序崩溃分析器` | 系统事件 + 应用日志 + IIS日志 |
| **权限/认证问题** | 401/403 数量 > 10 | ⚡ `安全审计日志分析` | 失败认证模式 + 用户权限配置 |
| **资源耗尽** | 响应时间>5s且并发>1000 | ⚡ `系统资源监控器` | 内存/CPU/磁盘 + IIS队列深度 |
| **DDoS/异常流量** | RPS突增或特定IP重复请求 | ⚡ `防火墙日志分析` | IP地址黑名单 + WAF规则 |

#### 自动触发逻辑

```
IF 问题_严重度 == "严重" AND 问题类型已识别 THEN
    ├─ 收集相关skill的输入参数（如时间范围、错误代码）
    ├─ 在 raw.skills_to_trigger 中列出推荐技能
    ├─ 仅当 --auto-trigger 被指定时，直接通过 subprocess 调用，不再询问
    └─ 未指定 --auto-trigger 时，仅显示推荐，调用与否由调用方决定
```

**触发时机**：
- ✅ **主动建议**：显示在IIS分析报告的"建议深化分析"部分
- ✅ **自动提示**：在发现严重错误时立即建议相关技能
- ✅ **链式调用**：用户可一键启动多技能联合分析

### 5. 报告生成与多技能数据融合
### 5. 报告生成与多技能数据融合
- [ ] 创建包含以下内容的可视化报告：
  - 响应时间趋势图
  - 状态码分布饼图
  - 并发请求波形图
  - 问题摘要和建议
  
- [ ] **[新增]多技能融合部分**（如有其他技能输出）：
  - 📌 **问题根因链**：IIS日志 → httperr → Event Log → 根本原因
  - 📊 **跨源数据对比**：时间轴对齐各技能数据
  - 🔗 **相关性分析**：标记各来源之间的关联
  - 💡 **综合建议**：基于多源数据的优化方案

### 6. 后续行动与跨技能协作
- [ ] 根据分析结果进行深度调查
- [ ] 生成定制化分析或对比历史数据
- [ ] 建议优化措施或告警阈值

## 跨技能集成指南

### 1️⃣ 与其他技能的交互模式

#### **并行型集成**（推荐）
当检测到多个问题类型时，同时调用多个相关技能：

```
IIS日志分析器
├─ 发现 500错误
│  ├─ 触发 httperr分析器 → 获取HTTP错误详情
│  └─ 触发 event_log分析器 → 获取系统事件
├─ 发现 特定IP大量请求
│  └─ 触发 防火墙日志分析器 → 获取访问控制信息
└─ 整合所有输出 → 生成联合报告
```

#### **链式型集成**
某个技能的输出作为另一个技能的输入：

```
IIS日志分析器
  ↓ (输出：错误时间范围 + 错误代码)
httperr分析器
  ↓ (输出：HTTP错误详情)
event_log分析器
  ↓ (输出：系统级根因)
综合诊断报告
```

### 2️⃣ 数据传递协议

**IIS分析器 → 其他技能**：
```json
{
  "skill_name": "IIS日志分析器",
  "severity": "critical",
  "problem_type": "5xx_error",
  "time_range": {
    "start": "2026-04-21 10:00:00",
    "end": "2026-04-21 10:30:00"
  },
  "context": {
    "error_codes": [500, 503],
    "error_count": 245,
    "affected_urls": ["/api/v1/users", "/api/v1/orders"],
    "error_rate": "12%"
  }
}
```

**其他技能 → IIS分析器**：
```json
{
  "skill_name": "event_log分析器",
  "findings": "应用程序池 DefaultAppPool 在 10:15:30 崩溃",
  "evidence": {
    "event_id": 1000,
    "source": "Application",
    "correlation_time": "2026-04-21 10:15:30"
  }
}
```

### 3️⃣ 相关技能库

**已实现的技能**：
- [ ] `httperr分析器` - 分析HTTP错误日志
- [ ] `event_log分析器` - 分析Windows事件日志
- [ ] `应用程序崩溃分析器` - 应用程序异常诊断

**待实现的技能**：
- [ ] `安全审计日志分析` - 认证/权限问题
- [ ] `系统资源监控器` - 性能资源分析
- [ ] `防火墙日志分析` - 网络层诊断

### 4️⃣ 调用方式

#### **方式A：用户主动触发**
```
用户: "分析IIS日志，发现了500错误，帮我调用httperr和event_log进行深度分析"

IIS分析器:
  1. 执行初步分析
  2. 输出触发建议
  3. 调用 httperr分析器 ← 用户确认
  4. 调用 event_log分析器 ← 用户确认
  5. 整合多源结果
```

#### **方式B：自动智能触发**（推荐）
```
用户: "分析IIS日志"

IIS分析器:
  1. 执行完整分析
  2. 发现严重问题 (500错误 > 10%)
  3. 自动建议: "检测到严重的5xx错误，建议调用以下技能:"
     - ✅ httperr分析器
     - ✅ event_log分析器
  4. 用户选择 "全部调用" 或 "选择调用"
  5. 并行或链式执行所有技能
  6. 生成综合诊断报告
```

## 质量标准

✅ **成功的分析应该**：
- 清晰指出影响最大的问题（延迟、错误或流量）
- 提供可操作的建议（如配置调整、资源扩展等）
- 使用图表和表格使数据易于理解
- 涵盖分析时间范围内的完整数据

✅ **[新增]多技能联合分析的质量标准**：
- 正确识别需要触发的其他技能
- 清晰呈现各技能之间的**相关性**
- 提供**跨源对比**（IIS日志 vs Event Log vs httperr）
- 给出**统一的根因结论**（而不是孤立的分析结果）
- 生成**优先级排序**的修复建议

⚠️ **需要改进的情况**：
- 日志不完整或格式不兼容
- 无法计算所需指标
- 报告缺少关键的可视化
- **[新增]多技能协作失败或数据无关联性**
- **[新增]未能提炼根本原因，只罗列表象问题**

## 示例提示

| 场景 | 提示 |
|------|------|
| 基础分析 | "分析IIS日志，识别今天的性能问题" |
| 特定时间段 | "分析2024年1月15日 10:00-12:00的IIS日志并生成报告" |
| 深度诊断 | "找出导致500错误大幅增加的根本原因" |
| 对比分析 | "对比昨天和今天的并发流量模式" |
| 优化建议 | "基于分析结果，提供性能优化建议" |
| **[新增]多技能分析** | "分析IIS日志中的500错误，并自动调用httperr和event_log分析器进行根因分析" |
| **[新增]跨源关联** | "IIS日志显示访问延迟，请结合系统资源监控器分析CPU和内存使用情况" |
| **[新增]安全诊断** | "发现大量401错误，请调用安全审计日志分析验证认证配置" |

## 相关定制

考虑创建以下相关技能：
- **告警规则生成器**：根据分析结果自动生成监控告警
- **日志清理工具**：自动管理历史日志文件
- **性能基准对比**：与历史数据进行标准化对比分析
- **[新增]多技能编排器**：自动根据问题类型调度技能执行
- **[新增]根因分析引擎**：利用多源数据自动推导根本原因

## 工作流图解

```
┌─────────────────┐
│  用户提交IIS日志 │
└────────┬────────┘
         │
         ▼
┌──────────────────────┐
│  IIS分析器执行分析    │
│  • 解析日志          │
│  • 计算指标          │
│  • 问题识别          │
└────────┬─────────────┘
         │
         ▼
    ┌─────────────┐
    │  问题严重性? │
    └──┬───────┬──┘
       │       │
   严重│      │轻微
     ▼      ▼
  ┌────────────────┐     ┌─────────────┐
  │ 智能触发其他   │     │ 单独输出    │
  │ 技能进行       │     │ IIS报告     │
  │ 合并分析       │     └─────────────┘
  └────┬───────────┘
       │
       ▼
  ┌────────────────────────┐
  │ 并行/链式调用关键技能  │
  │ • httperr分析器        │
  │ • event_log分析器      │
  │ • 资源监控器等         │
  └────┬───────────────────┘
       │
       ▼
  ┌────────────────────────┐
  │ 整合多源分析结果       │
  │ • 时间轴对齐           │
  │ • 相关性分析           │
  │ • 根因推导             │
  └────┬───────────────────┘
       │
       ▼
  ┌────────────────────────┐
  │ 生成综合诊断报告       │
  │ ✅ 单源问题描述        │
  │ ✅ 多源根因分析        │
  │ ✅ 优先级修复建议      │
  └────────────────────────┘
```

## Report sections (envelope v2.1)

This skill emits the standard envelope plus three structured advisory fields seeded from `_shared/playbook.json` via `_shared.playbook.merge_into_result(...)`:

- `solutions[]` — concrete fixes for key problems (`problem_ref / title / severity / steps / references`).
- `next_steps[]` — suggested follow-up actions, optionally pointing at the next skill to run.
- `additional_logs_needed[]` — extra data sources required to deepen analysis.

Legacy `recommendations: string[]` is auto-derived from the three structured fields when not set (prefixes `[fix:...]` / `[next:...]` / `[logs:...]`).

## Log/source dependency

- ``_shared/logs/iis_w3c`` (filter dataclass ``IisFilter`` / ``log_filters.FilterSpec``)

Each shared reader exposes the same surface (`discover / iter_entries / summarise / apply_filter / around_window / query`); this skill calls `query(...)` rather than parsing files inline.
