# Microsoft Edge 诊断技能集合

一套**可组合的 AI 驱动诊断技能**，专用于在 Windows 上排查 Microsoft Edge（Chromium）问题。每个技能是面向特定数据源的独立 Python 模块，通过共享信封契约输出结构化 JSON 结果。

---

## 目录

1. [总览](#总览)
2. [技能参考](#技能参考)
3. [诊断流程](#诊断流程)
4. [标准 JSON 契约](#标准-json-契约)
5. [调用方式](#调用方式)
6. [协调者聚合](#协调者聚合)
7. [缺失日志门控](#缺失日志门控)
8. [剧本与问题类型](#剧本与问题类型)
9. [共享数据源读取器](#共享数据源读取器)
10. [项目约定](#项目约定)

---

## 总览

```
用户 / Copilot CLI
        │
        ▼
┌─────────────────────┐
│   edge_diagnostics  │  ← 故障排查的必须第一步
└─────────────────────┘
        │  输出：problems[]、environment、skills_to_trigger[]
        ▼
┌──────────────────────────────────────────────────────────────┐
│                        orchestrator                          │
│  融合结果，计算缺失日志门控，生成 operator_summary            │
└──────────────────────────────────────────────────────────────┘
        │  分发后续技能
        ▼
┌────────────┐ ┌───────────────┐ ┌──────────────┐ ┌─────────────┐
│ edge_crash │ │edge_performance│ │ edge_network │ │ edge_policy │
└────────────┘ └───────────────┘ └──────────────┘ └─────────────┘
┌──────────────────┐ ┌──────────────┐ ┌─────────┐
│ edge_extensions  │ │ edge_netlog  │ │ edge_qa │
└──────────────────┘ └──────────────┘ └─────────┘
        │
        ▼
  融合后的 SkillResult 信封  →  raw.operator_summary（Markdown）
```

---

## 技能参考

| 技能 ID | 文件夹 | 入口脚本 | 角色 | 需要管理员权限？ |
|---|---|---|---|---|
| `edge_diagnostics` | `edge_diagnostics/` | `scripts/edge_diagnostics.py` | 入口点 | 否 |
| `edge_crash` | `edge_crash/` | `scripts/edge_crash_analyzer.py` | 后续分析 | 否 |
| `edge_performance` | `edge_performance/` | `scripts/edge_performance.py` | 后续分析 | 否 |
| `edge_network` | `edge_network/` | `scripts/edge_network.py` | 后续分析 | 否 |
| `edge_policy` | `edge_policy/` | `scripts/edge_policy.py` | 后续分析 | 否 |
| `edge_extensions` | `edge_extensions/` | `scripts/edge_extensions.py` | 后续分析 | 否 |
| `edge_netlog` | `edge_netlog/` | `scripts/edge_netlog.py` | 后续分析 | 否 |
| `edge_qa` | `edge_qa/` | `scripts/edge_qa.py` | 知识库 | 否 |
| `orchestrator` | `orchestrator/` | `scripts/edge_orchestrator.py` | 协调者 | 否 |

### edge_diagnostics
**必须最先调用的入口技能。** 检测已安装的 Edge 渠道（稳定版/Beta/Dev/Canary）、版本号、配置文件路径、托管状态（浏览器是否由组策略控制）以及最近的 Crashpad 报告。根据环境快照对问题类型进行分类，并填充 `skills_to_trigger`。支持 `--auto-trigger` 参数自动运行后续技能。

### edge_crash
枚举 `User Data/Crashpad/reports/` 下的崩溃报告，对崩溃签名进行分类（GPU 崩溃、渲染进程被杀、OOM 等）并建议针对性修复方案。由 `crash`、`hang`、`render_process_gone` 触发。

### edge_performance
通过进程表采样实时 `msedge.exe` 进程的 CPU 使用秒数、工作集大小、句柄数量及渲染/GPU/工具类型。标记内存占用过高的渲染器标签页或 GPU 内存压力。由 `slow_startup`、`high_cpu`、`high_memory`、`page_slow` 触发。

### edge_network
诊断影响 Edge 连接性的代理设置、DNS 解析和证书有效性问题，并与系统级网络配置进行关联。由 `page_load_failure`、`cert_error`、`proxy_issue`、`dns_issue`、`sync_error` 触发。

### edge_policy
读取 `HKLM\Software\Policies\Microsoft\Edge` 和 `HKCU\Software\Policies\Microsoft\Edge` 注册表项，列出所有已应用的组策略/Intune/MDM 策略，并标记可能阻止功能或更新的策略。由 `managed_browser`、`feature_blocked`、`update_blocked`、`extension_blocked` 触发。

### edge_extensions
从 `Preferences` / `Secure Preferences` 枚举每个配置文件下安装的扩展程序，标记高风险扩展（异常权限、被策略禁用、强制安装等）。由 `extension_issue`、`high_memory`、`page_slow` 触发。

### edge_netlog
解析 Chromium `edge://net-export` 导出的 JSON 文件 — **浏览器自身的网络事件日志**。分类：
- 证书/TLS 失败（`cert_error`）
- DNS 解析失败（`dns_issue`）
- 代理解析失败（`proxy_issue`）
- 通用 URL 请求失败（`page_load_failure`）
- 超过阈值的慢速请求（`page_slow`）

由 `page_load_failure`、`cert_error`、`proxy_issue`、`dns_issue`、`page_slow` 触发。当 `extra.netlog_paths` 传入 `edge_diagnostics` 时也会自动触发。

### edge_qa
内置知识库技能，回答常见 Edge 问题：功能标志、键盘快捷键、IE 模式、同步行为、配置文件管理、企业部署等。由 `question` 问题类型或直接调用触发。

**Microsoft Learn MCP 集成。** Python 技能本身无法调用 MCP 工具（它们仅存在于 Copilot CLI Agent 中）。该技能改为输出 `raw.mslearn_lookup` 数据块，其 `suggested_calls[]` 数组告诉 Agent 应调用哪些 `microsoft_docs_search` / `microsoft_docs_fetch` 查询。Agent 随后将 MS Learn 的实时结果融合到最终答案中，并引用其 URL。完整契约见 [edge_qa/SKILL.MD](edge_qa/SKILL.MD)；如需完全离线运行，请设置 `extra.use_mslearn: false`。

### orchestrator
接收 `edge_diagnostics` 的输出，分发所有列出的后续技能，去重建议字段，计算缺失日志门控，并写入 `raw.operator_summary`（无需 HTML 查看器即可在终端阅读的 Markdown 摘要）。

---

## 诊断流程

### 流程一 — 标准故障排查

```bash
# 第一步：运行 edge_diagnostics
python edge_diagnostics/scripts/edge_diagnostics.py '{}'

# 第二步：将其输出传给协调者
python edge_diagnostics/scripts/edge_diagnostics.py '{}' | \
  python orchestrator/scripts/edge_orchestrator.py @-
```

或一条命令完成：

```bash
python edge_diagnostics/scripts/edge_diagnostics.py --auto-trigger
```

### 流程二 — 已知问题类型

```bash
# 已知是崩溃问题
python orchestrator/scripts/edge_orchestrator.py \
  '{"skills_to_trigger":["edge_crash","edge_policy"],"problems":[{"type":"crash","severity":"critical","summary":"Edge 启动时崩溃"}]}'
```

### 流程三 — 知识问答

```bash
# 1. 本地 KB 查询 + 输出 MS Learn MCP 建议
python edge_qa/scripts/edge_qa.py '{"question":"如何通过组策略配置 IE 模式？"}'

# 2. Agent（Copilot CLI）读取 raw.mslearn_lookup.suggested_calls 并执行：
#      microsoft_docs_search("Microsoft Edge 如何通过组策略配置 IE 模式？")
#      microsoft_docs_search("Microsoft Edge Enable Internet Explorer (IE) mode for a site")
#      microsoft_docs_fetch("https://learn.microsoft.com/deployedge/edge-ie-mode")
#    然后将 MS Learn 的实时结果与本地 KB 答案融合，并引用相应 URL。

# 完全离线（跳过 MCP 建议）：
python edge_qa/scripts/edge_qa.py '{"question":"如何启用 IE 模式？","extra":{"use_mslearn":false}}'
```

### 流程四 — Netlog 分析

```bash
# 收集：打开 edge://net-export → 开始记录 → 复现问题 → 停止 → 保存 JSON
# 分析：
python edge_netlog/scripts/edge_netlog.py \
  '{"extra":{"netlog_paths":["C:\\Users\\user\\Downloads\\chrome-net-export-log.json"]}}'

# 或通过协调者，附带 netlog：
python orchestrator/scripts/edge_orchestrator.py \
  '{"skills_to_trigger":["edge_policy"],"problems":[{"type":"page_load_failure","severity":"critical","summary":"页面无法加载"}],"extra":{"netlog_paths":["C:\\netlog.json"]}}'
```

### 问题类型 → 自动触发技能映射

| 问题类型 | 严重级别 | 触发的技能 |
|---|---|---|
| `crash` | 严重 | `edge_crash`, `edge_extensions`, `edge_policy` |
| `hang` | 严重 | `edge_crash`, `edge_performance`, `edge_extensions` |
| `render_process_gone` | 严重 | `edge_crash`, `edge_extensions` |
| `slow_startup` | 警告 | `edge_performance`, `edge_extensions`, `edge_policy` |
| `high_cpu` | 警告 | `edge_performance`, `edge_extensions` |
| `high_memory` | 警告 | `edge_performance`, `edge_extensions` |
| `page_slow` | 警告 | `edge_network`, `edge_netlog`, `edge_performance` |
| `page_load_failure` | 严重 | `edge_network`, `edge_netlog`, `edge_policy` |
| `cert_error` | 严重 | `edge_network`, `edge_netlog`, `edge_policy` |
| `proxy_issue` | 警告 | `edge_network`, `edge_netlog`, `edge_policy` |
| `dns_issue` | 警告 | `edge_network`, `edge_netlog` |
| `sync_error` | 警告 | `edge_network`, `edge_policy` |
| `update_blocked` | 警告 | `edge_policy` |
| `extension_issue` | 警告 | `edge_extensions`, `edge_policy` |
| `managed_browser` | 信息 | `edge_policy` |
| `question` | 信息 | `edge_qa` |

---

## 标准 JSON 契约

### 输入

```json
{
  "time_range": { "start": "2026-05-04T10:00:00", "end": "2026-05-04T10:30:00" },
  "problem_type": "crash",
  "question": "Edge 启动时为什么崩溃？",
  "extra": {
    "profile": "Default",
    "netlog_paths": ["C:\\Users\\user\\Downloads\\netlog.json"]
  }
}
```

### 输出信封（v2.1 版本）

```json
{
  "skill": "edge_crash",
  "ok": true,
  "findings": [
    { "summary": "过去 24 小时内 3 次崩溃 — 签名：GPU_PROCESS_LAUNCH_FAILED",
      "severity": "critical", "evidence": { "count": 3, "signature": "GPU_PROCESS_LAUNCH_FAILED" } }
  ],
  "root_cause": "GPU 进程启动失败 — 可能是驱动程序问题",
  "confidence": "high",
  "recommendations": ["[fix:...] 更新显卡驱动", "[next:...] 运行 edge_policy"],
  "solutions": [
    { "problem_ref": "crash", "title": "更新或回滚显卡驱动",
      "severity": "critical",
      "steps": ["设备管理器 → 显示适配器 → 更新驱动程序"],
      "references": ["https://learn.microsoft.com/microsoft-edge/..."] }
  ],
  "next_steps": [
    { "action": "检查策略是否强制开启了硬件加速", "skill": "edge_policy" }
  ],
  "additional_logs_needed": [
    { "log_kind": "netlog", "why": "检查崩溃是否与网络调用相关",
      "how_to_collect": "打开 edge://net-export，复现问题后保存 JSON", "skill": "edge_netlog" }
  ],
  "raw": { "crash_reports": [...], "observed_problem_types": ["crash"] }
}
```

**关键字段说明：**
- `ok` — 仅在技能发生不可恢复错误时为 `false`。
- `confidence` — `high / medium / low`。
- `raw.operator_summary`（仅协调者）— 终端友好的 Markdown 摘要。
- `raw.missing_logs`（仅协调者）— 调查所需但未提供的日志类型。

---

## 调用方式

### Python CLI

```bash
# edge_diagnostics：基础环境扫描
python edge_diagnostics/scripts/edge_diagnostics.py '{}'

# edge_diagnostics：自动触发所有推荐的后续技能
python edge_diagnostics/scripts/edge_diagnostics.py --auto-trigger

# edge_crash：带时间范围
python edge_crash/scripts/edge_crash_analyzer.py \
  '{"time_range":{"start":"2026-05-04T10:00:00","end":"2026-05-04T10:30:00"}}'

# edge_policy：检查已应用的策略
python edge_policy/scripts/edge_policy.py '{}'

# edge_netlog：分析 net-export JSON
python edge_netlog/scripts/edge_netlog.py \
  '{"extra":{"netlog_paths":["C:\\Users\\user\\Downloads\\netlog.json"]}}'

# edge_qa：回答问题
python edge_qa/scripts/edge_qa.py '{"question":"如何启用 IE 模式？"}'

# orchestrator：从诊断结果进行完整编排
python orchestrator/scripts/edge_orchestrator.py @diagnostics_result.json
```

### JSON 上下文文件

```bash
echo '{"problem_type":"page_load_failure","extra":{"netlog_paths":["C:\\netlog.json"]}}' > ctx.json
python edge_netlog/scripts/edge_netlog.py @ctx.json
```

### 通过 GitHub Copilot CLI

从此文件夹启动 `copilot`（以便加载 `AGENTS.md`）：

```
我的 Edge 启动时一直崩溃 — 运行 edge_diagnostics，然后编排它推荐的后续技能

调查今天 10:00 到 10:30 之间的 Edge 崩溃波动：用该时间窗口运行 edge_crash

如何通过组策略配置 IE 模式站点列表？请使用 edge_qa

Edge 显示 NET::ERR_CERT_AUTHORITY_INVALID — 分析 C:\netlog.json 中的 net-export 日志
```

---

## 协调者聚合

协调者将每个子技能的结果融合到一个信封中，并写入三个额外的 `raw` 字段：

### `raw.cross_source_context`
```json
{
  "sources_used": ["crashpad", "edge_registry"],
  "shared_problem_types": ["crash"],
  "skills_run": ["edge_crash", "edge_policy"],
  "had_input_problems": true
}
```

### `raw.missing_logs`
```json
[
  {
    "log_kind": "netlog",
    "why": "需要从浏览器端诊断代理/TLS 失败",
    "how_to_collect": "打开 edge://net-export，点击"开始记录到磁盘"，复现问题，点击"停止"。",
    "skill": "edge_netlog"
  }
]
```

### `raw.operator_summary`
包含以下内容的 Markdown 字符串：
- `# Edge orchestrator summary`（Edge 协调者摘要）
- 按严重级别分组的主要发现
- 解决方案 / 后续步骤 / 所需日志章节
- `## Missing required logs`（缺失的必需日志）章节（如有）

即使没有 HTML 查看器，也可直接在终端阅读。

---

## 缺失日志门控

```
expected = playbook.logs_for(problem_types) ∪ 子技能.additional_logs_needed
provided = 从 extra.* 解析的 EXTRA_KEY_TO_KIND ∪ 成功技能的 SKILL_PRODUCES_KINDS
missing  = expected − provided
```

填补 `netlog` 差距的方法：
```bash
# 从 Edge 收集：
#   1. 打开新的 Edge 标签页
#   2. 导航到 edge://net-export
#   3. 点击"开始记录到磁盘"→ 选择输出文件
#   4. 复现问题
#   5. 点击"停止"
#   6. 传入 JSON 文件：
python orchestrator/scripts/edge_orchestrator.py \
  '{"problems":[{"type":"page_load_failure","severity":"critical","summary":"..."}],
    "extra":{"netlog_paths":["C:\\netlog.json"]}}'
```

---

## 剧本与问题类型

`_shared/playbook.json` 将每个 `problem_type` 映射到解决方案、后续步骤和所需日志。技能通过调用 `playbook.merge_into_result(result, problem_types)` 自动填充建议字段。

| 问题类型 | 严重级别 | 说明 |
|---|---|---|
| `crash` | 严重 | Edge 进程崩溃 |
| `hang` | 严重 | Edge 无响应 |
| `render_process_gone` | 严重 | 渲染进程被杀（"啊，崩溃了！"） |
| `slow_startup` | 警告 | Edge 启动异常缓慢 |
| `high_cpu` | 警告 | `msedge.exe` CPU 占用过高 |
| `high_memory` | 警告 | `msedge.exe` 内存占用过高 |
| `page_slow` | 警告 | 页面加载缓慢 |
| `page_load_failure` | 严重 | 页面无法加载 |
| `cert_error` | 严重 | TLS 证书错误 |
| `proxy_issue` | 警告 | 代理配置错误 |
| `dns_issue` | 警告 | DNS 解析失败 |
| `sync_error` | 警告 | Edge 同步不工作 |
| `update_blocked` | 警告 | Edge 更新被策略阻止 |
| `extension_issue` | 警告 | 扩展程序引发问题 |
| `extension_blocked` | 信息 | 扩展程序被策略阻止 |
| `managed_browser` | 信息 | 浏览器由组策略/Intune 托管 |
| `feature_blocked` | 信息 | 功能被策略禁用 |
| `question` | 信息 | 用户有知识类问题 |

---

## 共享数据源读取器

所有数据访问位于 `_shared/sources/`。技能不直接访问 Edge 文件：

```python
from _shared.sources import crashpad, edge_registry, user_data, processes, netlog

# 每个模块都提供统一接口：
module.discover(...)                  # → 可用数据源列表
module.iter_entries(source)           # → Iterator[dict]
module.summarise(entries)             # → dict
module.apply_filter(entries, filter)  # → Iterator[dict]
module.query(...)                     # → {entries, summary, truncated, sources_used}
```

| 模块 | 过滤器数据类 | 读取内容 |
|---|---|---|
| `crashpad` | `CrashpadFilter(signature, process_type, min_size_bytes)` | `User Data/Crashpad/reports/*.dmp` |
| `edge_registry` | `PolicyFilter(category, name_contains, hive)` | `HKLM/HKCU\Software\Policies\Microsoft\Edge` |
| `user_data` | `EdgeProfileFilter(profile_name, extension_id, enabled_only)` | 配置文件 `Preferences`、`Extensions/` |
| `processes` | `ProcessFilter(min_cpu_seconds, min_working_set_mb)` | 实时 `msedge.exe` 快照 |
| `netlog` | `NetlogFilter(source_type, phase, contains)` | `edge://net-export` JSON |

---

## 项目约定

- **Python 3.10+，仅使用标准库** — 无第三方包。
- 所有脚本**可从任意工作目录运行**。
- **只读设计** — 没有任何技能会修改 Edge 设置或终止进程。
- **Windows 优先** — 在其他操作系统上会优雅降级（输出带说明的 `ok: true` 空数据信封）。
- 当技能遇到权限限制时，`raw` 中会有 `needs_elevation: true` 标识。
- 权威技能注册表：[`_shared/registry.json`](_shared/registry.json)。
- JSON 契约定义：[`_shared/contract.py`](_shared/contract.py)。
