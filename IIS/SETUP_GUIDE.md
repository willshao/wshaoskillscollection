# GitHub Copilot CLI — IIS 诊断技能集成配置指南

> 📅 创建日期：2026-05-26  
> 🎯 目标：将本地 IIS 诊断技能集合注册到 GitHub Copilot CLI，使其在任意目录下都能被 Copilot 识别和调用。

---

## 📋 目录

1. [前提条件](#1-前提条件)
2. [项目结构概览](#2-项目结构概览)
3. [配置步骤](#3-配置步骤)
   - [步骤一：确认 AGENTS.md 存在](#步骤一确认-agentsmd-存在)
   - [步骤二：确认 SKILL.MD 和 registry.json](#步骤二确认-skillmd-和-registryjson)
   - [步骤三：设置环境变量（全局加载）](#步骤三设置环境变量全局加载)
   - [步骤四：创建全局指令文件](#步骤四创建全局指令文件)
4. [验证配置](#4-验证配置)
5. [使用方式](#5-使用方式)
6. [技能清单](#6-技能清单)
7. [常见问题](#7-常见问题)

---

## 1. 前提条件

| 条件 | 说明 |
|---|---|
| GitHub Copilot 订阅 | 需要有效的 Copilot 许可证 |
| Copilot CLI 已安装 | 通过 `winget install GitHub.Copilot` 安装 |
| Python 3.10+ | 技能脚本使用 Python 标准库 |
| PowerShell 6+ | 部分技能有 PowerShell 版本 |

---

## 2. 项目结构概览

```
C:\workfile\SkillsCollection\IIS\
├── _shared/                    # 共享模块（contract.py, registry.json）
├── IIS_logs/                   # 入口技能：IIS 日志分析
│   ├── SKILL.MD
│   └── scripts/
│       ├── iis_analyzer.py
│       └── iis_analyzer.ps1
├── httperror/                  # 后续技能：HTTP.SYS 错误分析
├── event_log/                  # 后续技能：Windows 事件日志
├── app_crash/                  # 后续技能：.NET 崩溃分析
├── security_audit/             # 后续技能：安全审计（框架）
├── resource_monitor/           # 后续技能：资源监控（框架）
├── firewall/                   # 后续技能：防火墙分析（框架）
├── orchestrator/               # 协调器：多技能编排
├── AGENTS.md                   # ⭐ Copilot 自动加载的指令文件
├── README.md
└── requirements.txt
```

---

## 3. 配置步骤

### 步骤一：确认 AGENTS.md 存在

**文件位置：** `C:\workfile\SkillsCollection\IIS\AGENTS.md`

**为什么需要这一步：**  
`AGENTS.md` 是 GitHub Copilot CLI 约定的指令文件之一。当 Copilot 在某个目录启动时，会自动扫描并加载该目录下的 `AGENTS.md`。这个文件告诉 Copilot：
- 有哪些技能可用
- 每个技能的调用方式（入口脚本、输入输出格式）
- 技能之间的调用规则和优先级

> Copilot CLI 支持的指令文件还包括：`CLAUDE.md`、`GEMINI.md`、`.github/copilot-instructions.md` 等。  
> `AGENTS.md` 放在 git 仓库根目录或当前工作目录下即可被自动识别。

**检查方式：**

```powershell
Test-Path "C:\workfile\SkillsCollection\IIS\AGENTS.md"
# 应返回 True
```

---

### 步骤二：确认 SKILL.MD 和 registry.json

**文件位置：**
- 每个技能子目录下的 `SKILL.MD`
- `_shared/registry.json`

**为什么需要这一步：**  
- **SKILL.MD** 是每个技能的独立说明文档，定义了技能的元数据（id、版本、触发条件）、输入输出格式和使用场景。Copilot 读取它来理解单个技能的能力。
- **registry.json** 是所有技能的集中注册表，定义了技能之间的关系（谁是入口、谁是后续）、问题类型到技能的映射，以及共享模块的路径。这让 orchestrator 和 Copilot 能够自动编排多个技能的调用链。

**检查方式：**

```powershell
# 检查所有 SKILL.MD 是否存在
Get-ChildItem -Path "C:\workfile\SkillsCollection\IIS" -Recurse -Filter "SKILL.MD"

# 检查 registry.json
Test-Path "C:\workfile\SkillsCollection\IIS\_shared\registry.json"
```

---

### 步骤三：设置环境变量（全局加载）

**配置内容：** 设置 `COPILOT_CUSTOM_INSTRUCTIONS_DIRS` 用户级环境变量

**为什么需要这一步：**  
默认情况下，Copilot CLI 只会在**当前工作目录**和 **git 仓库根目录**下查找 `AGENTS.md`。这意味着如果您在 `C:\Users\wshao` 目录下启动 Copilot，它不会加载 `C:\workfile\SkillsCollection\IIS\AGENTS.md`。

`COPILOT_CUSTOM_INSTRUCTIONS_DIRS` 环境变量告诉 Copilot CLI 额外扫描指定目录中的指令文件。设置后，**无论您在哪个目录启动 Copilot，都会自动加载该目录下的指令文件**。

**执行命令：**

```powershell
# 设置用户级环境变量（永久生效，重启终端后可用）
[System.Environment]::SetEnvironmentVariable(
    'COPILOT_CUSTOM_INSTRUCTIONS_DIRS',
    'C:\workfile\SkillsCollection\IIS',
    'User'
)
```

**注意事项：**
- 使用 `'User'` 级别，不需要管理员权限
- 设置后需要**打开新的终端窗口**才能生效
- 如果需要添加多个目录，用分号 `;` 分隔：
  ```powershell
  [System.Environment]::SetEnvironmentVariable(
      'COPILOT_CUSTOM_INSTRUCTIONS_DIRS',
      'C:\workfile\SkillsCollection\IIS;C:\workfile\OtherSkills',
      'User'
  )
  ```

**验证：**

```powershell
# 新终端中验证
$env:COPILOT_CUSTOM_INSTRUCTIONS_DIRS
# 应输出：C:\workfile\SkillsCollection\IIS
```

---

### 步骤四：创建全局指令文件

**文件位置：** `C:\Users\wshao\.copilot\copilot-instructions.md`

**为什么需要这一步：**  
步骤三让 Copilot 加载了 `AGENTS.md` 中的技能调用规则，但**全局指令文件提供了额外的补充说明**，例如：
- 告诉 Copilot 技能的绝对路径（当不在技能目录时也能正确调用）
- 提供简洁的技能列表作为快速参考
- 可以添加其他全局性的自定义指令

`~/.copilot/copilot-instructions.md` 是 Copilot CLI 的**用户级全局指令**，在任何目录启动时都会被加载。

**文件内容：**

```markdown
# Global Copilot Instructions

## IIS Diagnostics Skills

This environment has a set of IIS diagnostic skills available at `C:\workfile\SkillsCollection\IIS`.

When the user asks about IIS troubleshooting, log analysis, or server diagnostics:

1. Read `C:\workfile\SkillsCollection\IIS\AGENTS.md` for the full skill registry and usage rules.
2. Follow the standard contract and invocation rules defined there.
3. Available skills: `iis_logs`, `httperror`, `event_log`, `app_crash`, `security_audit`, `resource_monitor`, `firewall`, `orchestrator`.

To invoke a skill:
\```
python C:\workfile\SkillsCollection\IIS\<skill_folder>\scripts\<entry>.py '<json-context>'
\```
```

**创建方式：**

```powershell
# 如果文件不存在，直接创建
New-Item -Path "$HOME\.copilot\copilot-instructions.md" -ItemType File -Force
# 然后用编辑器写入上述内容
code "$HOME\.copilot\copilot-instructions.md"
```

> 💡 **步骤三 vs 步骤四的区别：**
> - 步骤三（环境变量）：让 Copilot **直接加载** AGENTS.md 原始内容，包含完整的技能调用规则
> - 步骤四（全局指令）：提供**补充上下文**，如绝对路径和快速参考
> - 两者配合使用效果最佳，但如果只选一个，**步骤三更关键**

---

## 4. 验证配置

完成上述配置后，按以下步骤验证：

### 4.1 打开新终端

```powershell
# 必须打开新终端窗口，环境变量才会生效
```

### 4.2 在任意目录启动 Copilot

```powershell
cd ~
copilot
```

### 4.3 检查指令加载状态

在 Copilot CLI 中运行以下命令：

```
/instructions    # 查看已加载的指令文件列表
/env             # 查看完整环境信息，包含 skills、指令等
```

### 4.4 测试技能调用

在 Copilot CLI 中输入：

```
列出所有可用的 IIS 诊断技能
```

如果 Copilot 能正确列出 8 个技能，说明配置成功。

---

## 5. 使用方式

### 基本用法

```
# 分析单个 IIS 日志文件
分析 IIS 日志 C:\inetpub\logs\LogFiles\W3SVC1\u_ex260526.log

# 针对特定时间段调查 5xx 错误
调查今天 10:00 到 10:30 之间的 5xx 错误

# 完整诊断流程
运行 iis_logs 分析日志，然后根据结果自动触发后续技能，最后用 orchestrator 融合诊断
```

### 技能调用链

```
用户请求 → iis_logs（入口分析）
                ↓ 识别问题类型
          ┌─────┼─────────┐
          ↓     ↓         ↓
     httperror event_log app_crash  ...（后续技能）
          └─────┼─────────┘
                ↓
          orchestrator（融合结果，输出最终诊断）
```

---

## 6. 技能清单

### 核心技能

| Skill ID | 角色 | 功能 | 需要管理员 | 状态 |
|---|---|---|---|---|
| `iis_logs` | 🟢 入口 | 解析 IIS W3C 日志，计算 KPI，分类问题 | 否 | ✅ 完整 |
| `orchestrator` | 🔵 协调器 | 多技能编排，融合诊断结果 | 否 | ✅ 完整 |

### 后续诊断技能

| Skill ID | 触发条件 | 功能 | 需要管理员 | 状态 |
|---|---|---|---|---|
| `httperror` | 5xx 错误 | 解析 HTTP.SYS 错误日志 | 否 | ✅ 完整 |
| `event_log` | 5xx / 高延迟 / 认证错误 | 查询 Windows 事件日志 | ✅ 是 | ✅ 完整 |
| `app_crash` | 5xx 错误 | 分析 .NET 崩溃事件 | ✅ 是 | ✅ 完整 |
| `security_audit` | 认证错误 | 权限/认证诊断 | ✅ 是 | ⚠️ 框架 |
| `resource_monitor` | 高延迟 | CPU/内存/磁盘监控 | ✅ 是 | ⚠️ 框架 |
| `firewall` | 可疑流量 | 防火墙日志/DDoS 检测 | ✅ 是 | ⚠️ 框架 |

### 问题类型与技能映射

| 问题类型 | 默认严重性 | 触发的后续技能 |
|---|---|---|
| `5xx_error` | 🔴 critical | httperror → event_log → app_crash |
| `high_latency` | 🟡 warning | resource_monitor → event_log |
| `auth_error` | 🟡 warning | security_audit → event_log |
| `suspicious_traffic` | 🟡 warning | firewall |
| `not_found` | 🔵 info | *(无后续)* |

---

## 7. 常见问题

### Q: 配置后 Copilot 没有识别到技能？

**A:** 确认以下几点：
1. 是否在**新终端窗口**中启动的 Copilot（环境变量需要新终端生效）
2. 运行 `/instructions` 检查是否加载了指令文件
3. 检查环境变量：`$env:COPILOT_CUSTOM_INSTRUCTIONS_DIRS`

### Q: 技能脚本执行失败？

**A:** 检查：
1. Python 3.10+ 是否已安装：`python --version`
2. 需要管理员权限的技能（event_log、app_crash 等）是否以管理员身份运行终端
3. 技能的标准输入格式是否正确（参考各技能的 SKILL.MD）

### Q: 如何添加新的技能？

**A:** 按照现有结构：
1. 创建新的子目录（如 `my_new_skill/`）
2. 添加 `SKILL.MD` 描述文件
3. 在 `scripts/` 下放置入口脚本
4. 更新 `_shared/registry.json` 注册新技能
5. 更新 `AGENTS.md` 中的技能列表

### Q: 如何移除全局配置？

**A:**
```powershell
# 移除环境变量
[System.Environment]::SetEnvironmentVariable('COPILOT_CUSTOM_INSTRUCTIONS_DIRS', $null, 'User')

# 删除全局指令文件
Remove-Item "$HOME\.copilot\copilot-instructions.md"
```

---

## 📎 参考资料

- [GitHub Copilot CLI 官方文档](https://docs.github.com/copilot/concepts/agents/about-copilot-cli)
- [Copilot 自定义指令说明](https://docs.github.com/copilot/how-tos/use-copilot-agents/use-copilot-cli)
- 项目 README：`C:\workfile\SkillsCollection\IIS\README.md`
- 技能注册表：`C:\workfile\SkillsCollection\IIS\_shared\registry.json`
