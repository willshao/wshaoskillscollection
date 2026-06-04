# IIS 诊断技能系统

## 📁 项目结构

```
IIS/
├── IIS_logs/                          # ⭐ 主技能：IIS日志分析
│   ├── SKILL.MD
│   ├── iis_analyzer.py               # Python实现 (完整)
│   └── iis_analyzer.ps1              # PowerShell实现 (完整)
│
├── httperror/                         # HTTP错误分析 (HTTP.SYS层)
│   ├── SKILL.MD
│   ├── httperr_analyzer.py           # Python实现
│   └── httperr_analyzer.ps1          # PowerShell实现
│
├── event_log/                         # Windows事件日志分析
│   ├── SKILL.MD
│   ├── event_log_analyzer.py         # Python实现
│   └── event_log_analyzer.ps1        # PowerShell实现
│
├── app_crash/                         # .NET应用崩溃分析
│   ├── SKILL.MD
│   └── app_crash_analyzer.py         # Python实现
│
├── security_audit/                    # 安全审计日志分析
│   ├── SKILL.MD
│   └── security_audit_analyzer.py    # Python实现
│
├── resource_monitor/                  # 系统资源监控
│   ├── SKILL.MD
│   └── resource_monitor.py           # Python实现
│
├── firewall/                          # 防火墙日志分析
│   ├── SKILL.MD
│   └── firewall_analyzer.py          # Python实现
│
├── orchestrator/                      # ⭐ 技能编排器（多技能协调）
│   ├── SKILL.MD
│   └── skill_orchestrator.py         # Python实现
│
└── README.md                          # 本文件
```

## 🎯 核心概念

### 报告内容（v2.1 envelope）

每个 skill 输出的 JSON 报告（以及 orchestrator 的 HTML 报告）除了原有的指标和发现数据之外，会包含三个结构化字段，回答用户在数据展示之外最关心的问题：

| 字段 | 内容 |
|---|---|
| `solutions[]` | 针对关键问题的具体修复方案（步骤化），含 `problem_ref / title / severity / steps / references` |
| `next_steps[]` | 建议的下一步排查动作（含 `action / why / skill`，指向应继续运行的 skill） |
| `additional_logs_needed[]` | 当前数据不足以下结论时需要补采的日志（含 `log_kind / why / how_to_collect / skill`） |

这三个字段由 [_shared/playbook.json](_shared/playbook.json) 按 `problem_type` 提供模板，skill 在生成报告时调用 `_shared.playbook.merge_into_result(...)` 自动注入，并可追加场景化条目。若调用方未设置旧的 `recommendations` 字段，envelope 会自动把上述三段扁平化为带前缀 (`[fix:...]` / `[next:...]` / `[logs:...]`) 的字符串列表，向后兼容。

`orchestrator` 在多 skill 聚合时对这三段做去重（key 分别为 `(problem_ref,title)` / `(action,skill)` / `(log_kind,skill)`），并额外暴露 `raw.cross_log_context = {available, time_range, correlatable, note}`；HTML 报告会渲染 `Solutions` / `Next steps` / `Additional logs needed` / `Cross-log context` 四个顶层 `<h2>` 区段。

### 共享日志读取层（[_shared/logs/](_shared/logs/)）

所有 skill 不再各自实现日志解析。每种日志/数据源在 `_shared/logs/` 下有一个统一接口模块：`iis_w3c.py`、`httperr.py`、`ftp_w3c.py`、`evtx.py`、`perf_counter.py`、`firewall.py`。它们都对外暴露相同的 API（`discover / iter_entries / summarise / apply_filter / around_window / query`），过滤器为每种日志独立的 dataclass（如 `HttpErrFilter`、`EvtxFilter`）。Skill 只声明“要什么”（时间窗、过滤条件、投影列），不再关心“怎么解析”。多 skill 编排时，orchestrator 可直接组合多个 `query()` 来构造跨日志上下文。

### 分层架构

```
┌─────────────────────────────────────────────────────────┐
│  用户故障排查请求                                          │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│  IIS日志分析器 (入口点)                                   │
│  • 解析IIS日志                                          │
│  • 计算性能指标                                        │
│  • 问题分类与严重度评估                               │
│  • 触发相关诊断技能                                   │
└─────────────────────────────────────────────────────────┘
                          ↓
    ┌───────────────────────────────────────────────┐
    │  技能编排器 (协调中心)                          │
    │  • 确定诊断执行计划                           │
    │  • 并行/链式调度技能                          │
    │  • 整合多源分析结果                           │
    │  • 生成综合诊断报告                           │
    └───────────────────────────────────────────────┘
              ↙       ↓        ↘         ↙
    ┌──────────┐  ┌─────────┐  ┌──────────┐  ┌─────────┐
    │ httperr  │  │ event   │  │   app    │  │ security│
    │ 分析器    │  │  log    │  │  crash   │  │ audit   │
    │(HTTP层)  │  │ 分析器   │  │ 分析器    │  │ 分析器   │
    └──────────┘  └─────────┘  └──────────┘  └─────────┘
              ↘       ↓        ↙         ↘
┌─────────────────────────────────────────────────────────┐
│  综合根因分析报告                                         │
│  • 多源证据关联                                         │
│  • 根本原因链推导                                      │
│  • 优先级排序的解决方案                               │
│  • 后续诊断建议                                        │
└─────────────────────────────────────────────────────────┘
```

## 🚀 快速开始

### 方式一：基础IIS分析（仅分析IIS日志）

**Python**：
```bash
cd IIS_logs
python iis_analyzer.py "C:\inetpub\logs\LogFiles\W3SVC1\u_ex260421.log"
```

**PowerShell**：
```powershell
cd IIS_logs
.\iis_analyzer.ps1 -LogFile "C:\inetpub\logs\LogFiles\W3SVC1\u_ex260421.log"
```

### 方式二：自动多技能诊断（推荐）

**Python**（启用自动技能触发）：
```bash
cd IIS_logs
python iis_analyzer.py "C:\inetpub\logs\LogFiles\W3SVC1\u_ex260421.log" --auto-trigger
```

**PowerShell**（启用自动技能触发）：
```powershell
cd IIS_logs
.\iis_analyzer.ps1 -LogFile "C:\inetpub\logs\LogFiles\W3SVC1\u_ex260421.log" -AutoTrigger
```

### 方式三：完整综合诊断（使用编排器）

```bash
# 步骤1：生成IIS分析结果
cd IIS_logs
python iis_analyzer.py "C:\inetpub\logs\LogFiles\W3SVC1\u_ex260421.log" > iis_result.json

# 步骤2：运行编排器进行多技能诊断
cd ../orchestrator
python skill_orchestrator.py "$(cat ../IIS_logs/iis_result.json)" > comprehensive_report.json

# 步骤3：查看综合报告
cat comprehensive_report.json | jq .
```

## 📊 工作流程说明

### 场景1：检测到5xx错误

```
IIS分析器检测到500错误
    ↓
问题分类: "5xx_error" (严重)
    ↓
自动触发的技能:
  • HTTP错误分析器 → 查看HTTP.SYS层错误代码
  • Event Log分析器 → 查看系统事件（应用崩溃）
  • 应用崩溃分析器 → 分析.NET异常和堆栈跟踪
    ↓
并行执行上述技能
    ↓
编排器整合结果:
  ✓ HTTP层错误代码
  ✓ 系统事件相关性
  ✓ 应用堆栈跟踪
    ↓
根因推导:
  证据链: HTTP 500 → 系统事件 "应用池回收" → .NET OutOfMemoryException
  
结论: 应用程序内存泄漏导致应用池回收
    ↓
建议:
  1. 立即: 检查应用程序代码中的内存分配
  2. 短期: 增加应用池内存限制和回收策略
  3. 长期: 性能分析和优化内存使用
```

### 场景2：检测到认证错误

```
IIS分析器检测到大量401/403错误
    ↓
问题分类: "auth_error" (警告)
    ↓
自动触发: 安全审计分析器
    ↓
查询安全事件日志:
  • EventID 576: 特殊权限分配
  • EventID 562: 资源访问失败
    ↓
结论: 应用程序池身份缺少文件访问权限
    ↓
建议: 为应用程序池身份配置NTFS权限
```

## 🔧 技能参数说明

### 各技能接收的上下文参数

```json
{
  "time_range": {
    "start": "2026-04-21 10:00:00",
    "end": "2026-04-21 10:30:00"
  },
  "problem_type": "5xx_error | high_latency | auth_error | suspicious_traffic",
  "metrics": {
    "total_requests": 5000,
    "error_rate_percent": 5.2,
    "p99_response_time_ms": 8500,
    "status_code_distribution": { "500": 250, "503": 15 }
  }
}
```

## 📈 输出报告格式

### IIS分析器输出

```json
{
  "timestamp": "2026-04-21T10:30:00",
  "metrics": { ... },
  "problems": [
    {
      "type": "5xx_error",
      "severity": "critical",
      "description": "...",
      "trigger_skills": ["httperror", "event_log", "app_crash"]
    }
  ],
  "skills_to_trigger": ["httperror", "event_log", "app_crash"],
  "recommended_action": "调用相关技能进行深度分析"
}
```

### 编排器综合报告

```json
{
  "timestamp": "2026-04-21T10:32:00",
  "report_type": "comprehensive_diagnosis",
  "execution_summary": { ... },
  "multi_source_findings": [
    {
      "skill": "event_log",
      "analysis": { ... }
    },
    {
      "skill": "app_crash",
      "analysis": { ... }
    }
  ],
  "root_cause_analysis": {
    "chain": [
      { "skill": "httperror", "finding": "HTTP 500.30" },
      { "skill": "event_log", "finding": "应用池回收" },
      { "skill": "app_crash", "finding": "OutOfMemoryException" }
    ],
    "conclusion": "应用程序内存泄漏 → 应用池回收 → 500.30错误",
    "confidence": "high"
  },
  "recommendations": [ ... ]
}
```

## 💡 常见诊断场景

| 问题 | 触发技能 | 预期结论 |
|-----|--------|--------|
| 500/503错误激增 | httperror, event_log, app_crash | 应用崩溃或资源耗尽 |
| 响应延迟 >5s | resource_monitor, event_log | 内存/CPU不足或I/O瓶颈 |
| 401/403频发 | security_audit, event_log | 权限配置错误 |
| 单IP大流量 | firewall | DDOS或爬虫攻击 |

## 🔍 调试建议

### 启用详细日志

```bash
# Python版本
python iis_analyzer.py "log_file" --debug

# PowerShell版本
.\iis_analyzer.ps1 -LogFile "log_file" -Verbose
```

### 查看技能执行日志

编排器会在stderr输出每个技能的执行状态：
```
✅ httperror 完成
✅ event_log 完成
❌ app_crash 失败: Timeout
```

## 📝 新增技能指南

如需添加新技能：

1. **创建文件夹**：在 `IIS/` 下创建 `new_skill/`
2. **编写SKILL.MD**：描述技能目的、工作流程
3. **实现Python脚本**：输入context JSON，输出分析结果JSON
4. **（可选）实现PowerShell版本**
5. **更新编排器**：在 `skill_plans` 中注册新技能

## 🎓 最佳实践

1. **从基础分析开始**：先运行IIS分析器理解问题
2. **循序渐进**：根据问题严重度决定是否调用其他技能
3. **时间轴对齐**：所有分析都基于相同的时间范围
4. **多角度验证**：多个技能的一致结论增加可信度
5. **保存报告**：记录历次诊断结果用于对比分析

## 📞 故障排除

### Python模块缺失

```bash
pip install -r requirements.txt
```

### PowerShell执行策略

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 权限不足

以管理员身份运行，某些日志（如Event Log）需要管理员权限。
