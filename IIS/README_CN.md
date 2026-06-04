# IIS 诊断技能集合

一套**可组合的 AI 驱动诊断技能**，专用于 Windows IIS 故障排查。每个技能是独立的 Python 模块，读取特定类型的日志，输出结构化 JSON 结果，并通过统一的信封契约与其他技能协作。

---

## 目录

1. [总览](#总览)
2. [技能参考](#技能参考)
3. [诊断流程](#诊断流程)
4. [标准 JSON 契约](#标准-json-契约)
5. [调用方式](#调用方式)
6. [过滤器与时间窗口查询](#过滤器与时间窗口查询)
7. [HTML 报告](#html-报告)
8. [缺失日志门控](#缺失日志门控)
9. [剧本与问题类型](#剧本与问题类型)
10. [共享日志读取器](#共享日志读取器)
11. [项目约定](#项目约定)

---

## 总览

```
事件文件夹 / 日志文件
        │
        ▼
┌───────────────────┐       自动发现所有日志类型
│    orchestrator   │──────────────────────────────────────┐
└───────────────────┘                                      │
        │  分发入口技能                                     │
        ▼                                                  │
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│ iis_logs │  │ ftp_logs │  │httperror │  │event_log │  │  netlog  │
└──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘
        │  发出 problem_types
        ▼
  根据问题类型触发后续技能
┌──────────┐  ┌──────────────┐  ┌──────────────────┐  ┌──────────┐
│app_crash │  │security_audit│  │resource_monitor  │  │ firewall │
└──────────┘  └──────────────┘  └──────────────────┘  └──────────┘
        │
        ▼
  融合后的 SkillResult 信封  →  HTML 报告（可选）
```

---

## 技能参考

| 技能 ID | 文件夹 | 入口脚本 | 角色 | 需要管理员权限？ |
|---|---|---|---|---|
| `iis_logs` | `IIS_logs/` | `scripts/iis_analyzer.py` | 入口点 | 否 |
| `ftp_logs` | `ftp_logs/` | `scripts/ftp_analyzer.py` | 入口点 | 否 |
| `httperror` | `httperror/` | `scripts/httperr_analyzer.py` | 后续分析 | 否 |
| `event_log` | `event_log/` | `scripts/event_log_analyzer.py` | 后续分析 | 是 |
| `app_crash` | `app_crash/` | `scripts/app_crash_analyzer.py` | 后续分析 | 是 |
| `security_audit` | `security_audit/` | `scripts/security_audit_analyzer.py` | 后续分析 | 是 |
| `resource_monitor` | `resource_monitor/` | `scripts/resource_monitor.py` | 后续分析 | 是 |
| `firewall` | `firewall/` | `scripts/firewall_analyzer.py` | 后续分析 | 是 |
| `netlog` | `netlog/` | `scripts/netlog_analyzer.py` | 后续分析 | 否 |
| `orchestrator` | `orchestrator/` | `scripts/skill_orchestrator.py` | 协调者 | 否 |

### iis_logs
解析 IIS W3C 访问日志。计算关键指标（每秒请求数、状态码分布、延迟百分位数），对问题进行分类（`5xx_error`、`high_latency`、`auth_error`、`not_found`、`traffic_spike`），并推荐后续技能。支持时间窗口过滤、正则过滤和 HTML+SVG 报告。

### ftp_logs
解析 Microsoft FTP Service W3C 日志。重建完整会话（CONNECT → USER/PASS → STOR/RETR → QUIT），检测认证失败、暴力破解、传输错误和未完成会话。问题类型：`ftp_auth_failure`、`ftp_upload_error`、`ftp_brute_force`、`ftp_incomplete_session`。

### httperror
解析 HTTP.SYS 错误日志（`%SystemRoot%\System32\LogFiles\HTTPERR\httperr*.log`）。揭示 W3C 日志中不可见的服务端断开原因（如 `Timer_EntityBody`、`Connection_Abandoned_By_ReqQueue`）。由 `5xx_error` 触发。

### event_log
查询 Windows 事件日志（应用程序、系统、安全通道）。将事件关联到 IIS 错误时间窗口。也接受通过 `extra.evtx_paths` 传入的导出 `.evtx` 文件。由 `5xx_error`、`high_latency`、`auth_error` 触发。

### app_crash
解析 Windows 应用程序事件日志中的 .NET 未处理异常和崩溃事件。对异常类型进行分类并建议代码级修复方案。由 `5xx_error` 触发。

### security_audit
诊断认证和权限失败（Windows 认证、Kerberos、匿名访问）。由 `auth_error` 触发。*（框架桩 — PowerShell 实现已完整。）*

### resource_monitor
采样 CPU、内存和磁盘性能计数器，检测主机资源饱和。由 `high_latency` 触发。*（框架桩 — PowerShell 实现已完整。）*

### firewall
解析 Windows 防火墙日志，检测丢弃连接、端口扫描和 DDoS 模式。由 `suspicious_traffic` 触发。*（框架桩 — PowerShell 实现已完整。）*

### netlog
解析 Chromium `edge://net-export` 导出的 JSON 文件。提供 **IIS 无法直接观察到的客户端视角**。可检测：TLS/证书失败、DNS 解析失败、代理配置错误、Kerberos SPN 不匹配、HTTP 认证握手循环。发出的问题类型：`cert_error`、`dns_issue`、`proxy_issue`、`client_request_failure`、`kerberos_spn_mismatch`、`auth_handshake_loop`、`tls_handshake_failure`。当文件夹中存在符合 net-export 结构的 `.json` 文件时，协调者会自动发现并分发。

### orchestrator
**处理任何事件文件夹的推荐起点。** 发现所有日志类型，分发正确的入口技能，根据发现的问题类型进行二次扇出，计算缺失日志门控，并可选择生成 HTML 报告。

---

## 诊断流程

### 流程一 — 文件夹 / 事件包（推荐）

```
python orchestrator/scripts/skill_orchestrator.py C:\incident\logs --report C:\report.html
```

1. **发现** — `log_discovery` 扫描文件夹中的 `.log`（IIS/FTP/HTTPERR）、`.evtx`、`.json`（net-export）。
2. **入口技能** — `iis_logs`、`ftp_logs`、`httperror`、`event_log`、`netlog` 并行运行。
3. **问题聚合** — 合并所有 `raw.problems`。
4. **二次扇出** — `orchestrate()` 使用 `skills_to_trigger` 按需调用 `app_crash`、`security_audit`、`resource_monitor`、`firewall`。
5. **缺失日志门控** — 将预期日志类型（来自剧本 + 子技能的 `additional_logs_needed`）与已发现内容对比，以 `warning` 形式展示差距。
6. **报告** — 带内联 SVG 图表、跨日志上下文和缺失日志表格的 HTML 报告。

### 流程二 — 单个日志文件

```
python IIS_logs/scripts/iis_analyzer.py C:\logs\u_ex260504.log
```

技能输出 JSON 信封。代理读取 `raw.skills_to_trigger` 并逐一调用后续技能。

### 流程三 — 旧版扇出（程序化）

```
python orchestrator/scripts/skill_orchestrator.py @iis_result.json
```

从文件读取 `iis_logs` 的 JSON 结果并分发后续技能。

### 问题类型 → 自动触发技能映射

| 问题类型 | 严重级别 | 自动触发的技能 |
|---|---|---|
| `5xx_error` | 严重 | `httperror`, `event_log`, `app_crash` |
| `high_latency` | 警告 | `resource_monitor`, `event_log` |
| `auth_error` | 警告 | `security_audit`, `event_log`, `netlog` |
| `suspicious_traffic` | 警告 | `firewall` |
| `cert_error` | 严重 | `netlog` |
| `dns_issue` | 警告 | `netlog` |
| `proxy_issue` | 警告 | `netlog` |
| `kerberos_spn_mismatch` | 严重 | `security_audit`, `event_log` |
| `tls_handshake_failure` | 严重 | `netlog`, `event_log` |
| `ftp_brute_force` | 严重 | `firewall` |
| `ftp_auth_failure` | 警告 | `firewall`, `security_audit` |

---

## 标准 JSON 契约

### 输入（传递给每个技能的上下文）

```json
{
  "time_range": { "start": "2026-05-04T10:00:00", "end": "2026-05-04T10:30:00" },
  "problem_type": "5xx_error",
  "extra": {
    "evtx_paths": ["C:\\incident\\app.evtx"],
    "netlog_paths": ["C:\\incident\\netlog.json"]
  }
}
```

### 输出信封（v2.1 版本）

```json
{
  "skill": "iis_logs",
  "ok": true,
  "findings": [
    { "summary": "60 个 5xx 错误（占 49%）", "severity": "critical", "evidence": { "type": "5xx_error" } }
  ],
  "root_cause": "负载下应用程序池回收",
  "confidence": "high",
  "recommendations": ["[fix:...] 回收应用程序池", "[next:...] 运行 event_log", "[logs:...] 收集 httperr*.log"],
  "solutions": [
    {
      "problem_ref": "5xx_error",
      "title": "重启应用程序池",
      "severity": "critical",
      "steps": ["Get-IISAppPool | Where-Object State -eq Started", "Restart-WebAppPool -Name <pool>"],
      "references": ["https://learn.microsoft.com/iis/..."]
    }
  ],
  "next_steps": [
    { "action": "与应用程序事件日志关联", "skill": "event_log" }
  ],
  "additional_logs_needed": [
    { "log_kind": "evtx", "why": "需要应用程序/系统事件", "how_to_collect": "wevtutil epl Application app.evtx", "skill": "event_log" }
  ],
  "raw": { "problems": [...], "metrics": {...}, "skills_to_trigger": ["event_log", "httperror"] }
}
```

**关键字段说明：**
- `ok` — 仅在技能发生不可恢复错误时为 `false`（检查 stderr 和退出码）。
- `confidence` — 基于数据量和信号清晰度的 `high / medium / low`。
- `raw.skills_to_trigger` — 代理必须接下来调用这些技能。
- `raw.missing_logs`（仅协调者）— 调查所需但用户未提供的日志类型。

---

## 调用方式

### 直接 CLI — Python

```bash
# iis_logs：分析单个文件
python IIS_logs/scripts/iis_analyzer.py C:\logs\u_ex260504.log

# iis_logs：分析文件夹，带时间窗口
python IIS_logs/scripts/iis_analyzer.py C:\logs --around "2026-05-04 10:15:00" --window 15m

# iis_logs：带过滤器和 HTML 报告
python IIS_logs/scripts/iis_analyzer.py C:\logs --filter "status=500-599,method=POST" --report C:\out\report.html

# httperror：文件夹模式
python httperror/scripts/httperr_analyzer.py --folder C:\logs\HTTPERR

# event_log：离线 evtx 文件
python event_log/scripts/event_log_analyzer.py '{"extra":{"evtx_paths":["C:\\incident\\app.evtx"]}}'

# netlog：解析 net-export JSON
python netlog/scripts/netlog_analyzer.py '{"extra":{"netlog_paths":["C:\\incident\\netlog.json"]}}'

# orchestrator：完整文件夹分析
python orchestrator/scripts/skill_orchestrator.py C:\incident --report C:\out\report.html

# orchestrator：错误驱动的锚点发现
python orchestrator/scripts/skill_orchestrator.py C:\incident --error "NullReferenceException" --report C:\out\report.html
```

### 直接 CLI — PowerShell（备用）

```powershell
# iis_logs
pwsh IIS_logs/scripts/iis_analyzer.ps1 C:\logs\u_ex260504.log

# event_log
pwsh event_log/scripts/event_log_analyzer.ps1
```

### JSON 上下文文件

```bash
echo '{"time_range":{"start":"2026-05-04T10:00:00","end":"2026-05-04T10:30:00"},"problem_type":"5xx_error"}' > ctx.json
python IIS_logs/scripts/iis_analyzer.py @ctx.json
```

### 通过 GitHub Copilot CLI

从此文件夹启动 `copilot`（以便加载 `AGENTS.md`）：

```
分析 IIS 日志 C:\inetpub\logs\LogFiles\W3SVC1\u_ex260504.log — 计算关键指标并运行所有后续技能

调查 2026-05-04 10:00 至 10:30 之间 C:\incident\logs 下的 5xx 波动，生成 HTML 报告

我的站点间歇性返回 503 — 检查 C:\logs\iis 并找出根本原因

从 edge://net-export 收集客户端 netlog，放入事件文件夹，然后运行完整的编排分析
```

---

## 过滤器与时间窗口查询

### `--around` / `--window`

将分析集中在一个或多个时间戳前后的 ±窗口范围内：

```bash
python IIS_logs/scripts/iis_analyzer.py C:\logs --around "2026-05-04 10:15:00" --window 15m
# 多个锚点：
python IIS_logs/scripts/iis_analyzer.py C:\logs --around "10:15:00" --around "10:45:00" --window 5m
```

### `--filter`

```
以逗号分隔的 key=value 对：
  method=POST
  uri=/api/checkout          （子字符串或正则）
  status=500-599             （状态码范围）
  ip=10.0.0.0/8              （CIDR）
  min-time=2000              （毫秒）
  ua=python-requests         （正则）
  q=checkout                 （全文子字符串）
  user=jsmith                （仅 FTP）
  cmd=STOR                   （仅 FTP）
```

### `--error REGEX`（协调者）

扫描所有文本日志以查找正则表达式，将匹配行的时间戳转换为 `--around` 锚点：

```bash
python orchestrator/scripts/skill_orchestrator.py C:\incident --error "Timer_AppPool|503"
```

### JSON `extra` 字段

| 字段 | 接受技能 | 用途 |
|---|---|---|
| `extra.evtx_paths` | `event_log`, `orchestrator` | 离线导出的 `.evtx` 文件 |
| `extra.netlog_paths` | `netlog`, `orchestrator` | `edge://net-export` JSON 文件 |
| `extra.folder` | `httperror`, `iis_logs`, `ftp_logs` | 递归扫描的文件夹 |
| `extra.no_recursive` | `httperror` | 禁用递归扫描 |

---

## HTML 报告

传入 `--report <路径>.html` 获取自包含的 HTML 报告（内联 SVG，无 JavaScript/CDN）：

```bash
python orchestrator/scripts/skill_orchestrator.py C:\incident --report C:\out\diagnosis.html
```

报告章节：
- **发现** — 按类型列出发现的日志文件
- **锚点** — 推导出的时间锚点和 ±窗口
- **错误定位器** — `--error` 正则匹配结果（如果使用）
- **每技能结果** — 每个入口技能的发现和根本原因
- **根本原因链** — 跨所有技能的综合因果链
- **跨日志上下文** — 存在哪些日志类型以及能否关联
- **缺失的必需日志** — 调查所需但未提供的日志类型
- **解决方案 / 后续步骤 / 所需日志** — 去重后的建议章节

---

## 缺失日志门控

协调者在文件夹模式下自动计算：

```
expected_kinds = playbook.logs_for(每个问题类型) ∪ 子技能.additional_logs_needed
provided_kinds = 已发现文件 ∪ 成功执行的技能
missing        = expected_kinds − provided_kinds
```

每个缺失类型会以以下三种形式展现：
1. 信封中的 `warning` 发现（Finding）。
2. `raw.missing_logs` 中的行（包含 `why` 和 `how_to_collect`）。
3. HTML 报告中的 `<h2>缺失的必需日志</h2>` 表格。

要填补差距，提供缺失文件后重新运行：

```bash
# 提供导出的 evtx：将 app.evtx 放入 C:\incident 后重新运行
python orchestrator/scripts/skill_orchestrator.py C:\incident

# 提供 netlog JSON：将 netlog.json 放入 C:\incident 后重新运行
python orchestrator/scripts/skill_orchestrator.py C:\incident
```

---

## 剧本与问题类型

`_shared/playbook.json` 将每个 `problem_type` 映射到推荐的解决方案、后续步骤和所需附加日志。技能通过调用 `playbook.merge_into_result(result, problem_types)` 自动填充建议字段。

| 问题类型 | 严重级别 | 说明 |
|---|---|---|
| `5xx_error` | 严重 | IIS 返回的 HTTP 500–599 |
| `high_latency` | 警告 | p95/p99 响应时间偏高 |
| `auth_error` | 警告 | 认证/授权失败 |
| `suspicious_traffic` | 警告 | 异常请求模式 |
| `not_found` | 信息 | 高 404 率 |
| `traffic_spike` | 警告 | 请求量突然增加 |
| `cert_error` | 严重 | TLS 证书验证失败 |
| `dns_issue` | 警告 | DNS 解析失败 |
| `proxy_issue` | 警告 | 代理配置错误 |
| `client_request_failure` | 警告 | 通用客户端请求失败 |
| `kerberos_spn_mismatch` | 严重 | Kerberos SPN 不匹配 |
| `auth_handshake_loop` | 警告 | HTTP 认证协商循环 |
| `tls_handshake_failure` | 严重 | TLS 握手错误 |
| `ftp_auth_failure` | 警告 | FTP 登录失败 |
| `ftp_upload_error` | 警告 | FTP 传输错误 |
| `ftp_brute_force` | 严重 | FTP 凭据填充攻击 |
| `ftp_incomplete_session` | 信息 | FTP 会话未正常完成 |

---

## 共享日志读取器

所有解析逻辑位于 `_shared/logs/`。技能不直接解析日志字节：

```python
from _shared.logs import iis_w3c, httperr, ftp_w3c, evtx, perf_counter, firewall

# 每个模块都提供统一接口：
iis_w3c.discover(folder, recursive=True)          # → list[Path]
iis_w3c.iter_entries(path)                        # → Iterator[dict]
iis_w3c.summarise(entries)                        # → dict
iis_w3c.apply_filter(entries, filter_spec)        # → Iterator[dict]
iis_w3c.around_window(entries, anchors, seconds)  # → Iterator[dict]
iis_w3c.query(sources, time_range, filter, ...)   # → {entries, summary, truncated, sources_used}
```

日志分类逻辑（`_shared/log_discovery.py`）：
- `.evtx` → `EVTX_KIND`
- 开头 4 KB 含 `"constants"` + `"logSourceType"` 的 `.json` → `NETLOG_KIND`
- 文件名前缀 `httperr*.log` → `HTTPERR_KIND`
- 含 `#Software: Microsoft Internet Information Services` 头部 → `IIS_KIND`
- 含 `#Software: Microsoft FTP Service` 头部 → `FTP_KIND`

---

## 项目约定

- **Python 3.10+，仅使用标准库** — 无第三方包。
- 所有脚本**可从任意工作目录运行**（使用 `Path(__file__).parent` 进行兄弟导入）。
- `iis_logs`、`httperror`、`event_log`、`app_crash` 存在 **PowerShell 变体** — 优先使用 Python；仅在 Python 不可用时使用 `.ps1`。
- **管理员权限**：`event_log`、`security_audit`、`resource_monitor`、`firewall` 在生产主机上可能需要提升权限的 Shell。
- `security_audit`、`resource_monitor`、`firewall` 的 Python 层是**框架桩** — PowerShell 实现已完整，Python 层待完整移植。
- 权威技能注册表：[`_shared/registry.json`](_shared/registry.json)。
- JSON 契约定义：[`_shared/contract.py`](_shared/contract.py)。
