# IIS诊断技能系统 - 脚本文件组织结构

## 📁 完整的文件结构

```
IIS/
├── README.md                          # 项目总体文档
├── QUICK_START.md                     # 快速参考
├── requirements.txt                   # 依赖说明
│
├── IIS_logs/                          # ⭐ IIS日志分析技能
│   ├── SKILL.MD                       # 技能说明文档
│   └── scripts/                       # 💾 脚本实现
│       ├── iis_analyzer.py            # Python版本（~600行）
│       └── iis_analyzer.ps1           # PowerShell版本
│
├── httperror/                         # HTTP错误分析技能
│   ├── SKILL.MD                       # 技能说明文档
│   └── scripts/                       # 💾 脚本实现
│       ├── httperr_analyzer.py        # Python版本（~350行）
│       └── httperr_analyzer.ps1       # PowerShell版本
│
├── event_log/                         # Windows事件日志分析技能
│   ├── SKILL.MD                       # 技能说明文档
│   └── scripts/                       # 💾 脚本实现
│       ├── event_log_analyzer.py      # Python版本（~300行）
│       └── event_log_analyzer.ps1     # PowerShell版本
│
├── app_crash/                         # .NET应用崩溃分析技能
│   ├── SKILL.MD                       # 技能说明文档
│   └── scripts/                       # 💾 脚本实现
│       ├── app_crash_analyzer.py      # Python版本（~250行）
│       └── app_crash_analyzer.ps1     # PowerShell版本
│
├── security_audit/                    # 安全审计日志分析技能
│   ├── SKILL.MD                       # 技能说明文档
│   └── scripts/                       # 💾 脚本实现
│       └── security_audit_analyzer.py # Python框架实现
│
├── resource_monitor/                  # 系统资源监控技能
│   ├── SKILL.MD                       # 技能说明文档
│   └── scripts/                       # 💾 脚本实现
│       └── resource_monitor.py        # Python框架实现
│
├── firewall/                          # 防火墙日志分析技能
│   ├── SKILL.MD                       # 技能说明文档
│   └── scripts/                       # 💾 脚本实现
│       └── firewall_analyzer.py       # Python框架实现
│
└── orchestrator/                      # ⭐ 技能编排器
    ├── SKILL.MD                       # 技能说明文档
    └── scripts/                       # 💾 脚本实现
        └── skill_orchestrator.py      # Python版本（~400行）
```

## 📝 脚本用途速查表

| 技能 | Python脚本 | PowerShell脚本 | 功能描述 |
|-----|-----------|-------------|--------|
| **IIS_logs** | ✅ iis_analyzer.py | ✅ iis_analyzer.ps1 | 解析IIS日志、计算指标、问题分类、触发相关技能 |
| **httperror** | ✅ httperr_analyzer.py | ✅ httperr_analyzer.ps1 | 分析HTTP.SYS错误日志、提取错误代码、关联IIS日志 |
| **event_log** | ✅ event_log_analyzer.py | ✅ event_log_analyzer.ps1 | 分析Windows事件日志、与IIS错误关联、推导根因 |
| **app_crash** | ✅ app_crash_analyzer.py | ✅ app_crash_analyzer.ps1 | 分析.NET应用崩溃、提取堆栈跟踪、诊断异常原因 |
| **security_audit** | ✅ security_audit_analyzer.py | ⏳ 计划中 | 分析认证/权限问题 |
| **resource_monitor** | ✅ resource_monitor.py | ⏳ 计划中 | 监控系统资源（CPU/内存/磁盘） |
| **firewall** | ✅ firewall_analyzer.py | ⏳ 计划中 | 检测异常流量和DDOS攻击 |
| **orchestrator** | ✅ skill_orchestrator.py | ⏳ 计划中 | 协调多技能并行/链式执行、整合结果 |

## 🚀 使用示例

### 方式1：直接运行IIS分析（Python）

```bash
cd IIS_logs/scripts
python iis_analyzer.py "C:\inetpub\logs\LogFiles\W3SVC1\u_ex260421.log"
```

### 方式2：运行IIS分析（PowerShell）

```powershell
cd IIS_logs\scripts
.\iis_analyzer.ps1 -LogFile "C:\inetpub\logs\LogFiles\W3SVC1\u_ex260421.log"
```

### 方式3：自动触发多技能分析

```bash
cd IIS_logs/scripts
python iis_analyzer.py "log.log" --auto-trigger
```

### 方式4：编排器完整诊断

```bash
# 生成IIS分析结果
cd IIS_logs/scripts
python iis_analyzer.py "log.log" > result.json

# 运行编排器
cd ../../orchestrator/scripts
python skill_orchestrator.py "$(cat ../../IIS_logs/scripts/result.json)"
```

## 💻 脚本清单

### 完整实现的脚本（生产就绪）✅

| 脚本 | 行数 | 状态 |
|-----|-----|------|
| iis_analyzer.py | ~600 | ✅ 完整 |
| iis_analyzer.ps1 | ~200 | ✅ 完整 |
| httperr_analyzer.py | ~350 | ✅ 完整 |
| httperr_analyzer.ps1 | ~150 | ✅ 完整 |
| event_log_analyzer.py | ~300 | ✅ 完整 |
| event_log_analyzer.ps1 | ~180 | ✅ 完整 |
| app_crash_analyzer.py | ~250 | ✅ 完整 |
| app_crash_analyzer.ps1 | ~50 | ✅ 完整 |
| skill_orchestrator.py | ~400 | ✅ 完整 |

### 框架实现的脚本（框架代码已提供）⏳

| 脚本 | 行数 | 状态 | 说明 |
|-----|-----|------|------|
| security_audit_analyzer.py | ~30 | ⏳ 框架 | 基础框架，待实现完整逻辑 |
| resource_monitor.py | ~30 | ⏳ 框架 | 基础框架，待实现完整逻辑 |
| firewall_analyzer.py | ~30 | ⏳ 框架 | 基础框架，待实现完整逻辑 |

## 🔗 脚本间调用关系

```
iis_analyzer.py
  ↓ (检测问题后自动调用)
  ├─→ scripts/httperr_analyzer.py
  ├─→ scripts/event_log_analyzer.py
  ├─→ scripts/app_crash_analyzer.py
  ├─→ scripts/security_audit_analyzer.py
  ├─→ scripts/resource_monitor.py
  └─→ scripts/firewall_analyzer.py

编排器使用流程：
iis_analyzer.py → 生成结果 → skill_orchestrator.py → 整合所有技能输出
```

## 📋 文档清单

| 文档 | 位置 | 内容 |
|-----|------|------|
| 项目概览 | README.md | 项目结构、使用指南、最佳实践 |
| 快速参考 | QUICK_START.md | 命令速查、问题排查、场景指南 |
| 本文档 | scripts_guide.md | 脚本组织、调用关系、使用示例 |
| 技能说明 | */SKILL.MD | 各个技能的工作流程和参数说明 |

## 🎯 核心特性

✅ **标准化接口**：所有脚本统一接收JSON context，输出JSON report  
✅ **模块化设计**：每个技能独立运行，也可协调执行  
✅ **自动触发**：IIS分析器自动识别问题并触发相关技能  
✅ **并行执行**：编排器支持多技能并行诊断  
✅ **跨源融合**：整合多个脚本的分析结果  

## 🔧 维护建议

1. **扩展新技能**：复制框架实现文件，实现新分析逻辑
2. **更新技能地址**：修改脚本中的 `skill_map` 字典，指向新脚本位置
3. **测试**：每个脚本独立测试，然后集成测试
4. **文档**：更新SKILL.MD和README.md

---

**总结**：所有代码实现现已从SKILL.MD中分离出来，放在各技能的`scripts/`文件夹中，便于版本控制、单元测试和独立运行。
