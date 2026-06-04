# IIS诊断技能系统 - 快速参考

## 📋 一句话快速诊断

```bash
# Python（推荐）
cd IIS/IIS_logs && python iis_analyzer.py "C:\path\to\iis.log" --auto-trigger

# PowerShell
cd IIS\IIS_logs; .\iis_analyzer.ps1 -LogFile "C:\path\to\iis.log" -AutoTrigger
```

## 🎯 核心技能一览

| 技能 | 诊断对象 | 关键输入 | 主要输出 |
|-----|--------|--------|--------|
| **IIS_logs** | IIS W3C日志 | 日志文件路径 | 性能指标、问题分类、触发列表 |
| **httperror** | HTTP.SYS错误日志 | 时间范围 | HTTP错误代码、DDOS检测 |
| **event_log** | Windows事件日志 | 时间范围、问题类型 | 关联事件、根因推导 |
| **app_crash** | .NET应用异常 | 崩溃事件数据 | 堆栈跟踪、异常类型、建议 |
| **security_audit** | 安全审计日志 | 时间范围 | 认证失败、权限问题 |
| **resource_monitor** | 系统性能计数器 | 监控时段 | CPU/内存/磁盘使用、瓶颈 |
| **firewall** | 防火墙/WAF日志 | 异常IP信息 | 流量模式、DDOS指标、IP风险 |
| **orchestrator** | 编排所有技能 | IIS分析结果 | 综合诊断报告、根因链 |

## 🔄 问题 → 技能触发 映射表

```
500/503错误 → httperror + event_log + app_crash
↓
查看HTTP底层错误 + 系统事件 + 应用异常
↓
自动推导: 应用崩溃/资源耗尽/权限问题

---

响应延迟 >5s → resource_monitor + event_log
↓
检查系统资源 + 相关系统事件
↓
自动推导: 内存不足/CPU瓶颈/I/O阻塞

---

401/403频发 → security_audit + event_log
↓
检查权限配置 + 认证事件
↓
自动推导: 应用池身份错误/权限配置错误

---

异常流量 → firewall
↓
检查防火墙日志
↓
自动推导: DDOS攻击/恶意爬虫
```

## 💻 命令速查

### Python

```bash
# 基础分析
cd IIS_logs
python iis_analyzer.py "log_file.log"

# 自动触发相关技能
python iis_analyzer.py "log_file.log" --auto-trigger

# 传入时间范围和自定义参数
python -c "
import json
context = {
    'time_range': {'start': '2026-04-21 10:00:00', 'end': '2026-04-21 11:00:00'},
    'problem_type': '5xx_error'
}
import sys
sys.argv = ['event_log_analyzer.py', json.dumps(context)]
exec(open('event_log_analyzer.py').read())
"
```

### PowerShell

```powershell
# 基础分析
cd IIS_logs
.\iis_analyzer.ps1 -LogFile "C:\inetpub\logs\LogFiles\W3SVC1\*.log"

# 自动触发
.\iis_analyzer.ps1 -LogFile "log_file.log" -AutoTrigger

# 传递上下文
$context = @{
    time_range = @{start = "2026-04-21 10:00:00"; end = "2026-04-21 11:00:00"}
    problem_type = "5xx_error"
}
.\event_log_analyzer.ps1 -Context ($context | ConvertTo-Json)
```

## 📊 输出字段说明

### IIS分析器关键输出

```json
{
  "metrics": {
    "total_requests": 5000,           // 总请求数
    "avg_response_time": 250,         // 平均响应时间(ms)
    "p99_response_time": 8500,        // 99分位响应时间(ms)
    "error_rate_percent": 5.2,        // 错误率(%)
    "status_5xx_count": 250           // 5xx错误个数
  },
  "problems": [
    {
      "type": "5xx_error",            // 问题类型
      "severity": "critical",         // 严重度: critical/warning/info
      "trigger_skills": [...]         // 建议调用的技能
    }
  ]
}
```

### 编排器综合报告关键字段

```json
{
  "root_cause_analysis": {
    "chain": [
      {"skill": "event_log", "finding": "应用池回收"},
      {"skill": "app_crash", "finding": "OutOfMemoryException"}
    ],
    "conclusion": "应用程序内存泄漏导致回收",
    "confidence": "high"  // high/medium/low
  },
  "recommendations": [
    {
      "priority": "high",
      "action": "立即检查应用程序代码内存分配"
    }
  ]
}
```

## ⚠️ 常见问题

### Q: 技能执行超时怎么办？
A: 增加超时时间，检查系统性能
```bash
# 编辑 skill_orchestrator.py 中的 timeout 参数
"timeout": 120  # 改为120秒
```

### Q: 找不到Event Log怎么办？
A: 确保以管理员身份运行，部分日志需要管理员权限

### Q: 如何保存详细日志？
A: 重定向输出到文件
```bash
python iis_analyzer.py "log.log" > report.json 2> debug.log
```

## 🔗 技能间数据流

```
IIS日志分析器
└─ 输出: {time_range, problem_type, metrics}
    ├─→ httperror分析器
    │   └─ 输出: {analysis, error_codes}
    │
    ├─→ event_log分析器
    │   └─ 输出: {correlated_events, root_cause}
    │
    ├─→ app_crash分析器
    │   └─ 输出: {crash_analysis, stack_trace}
    │
    └─→ 编排器
        └─ 输入: {所有技能输出}
            └─ 输出: {综合诊断报告}
```

## 📌 最佳实践

```
✅ DO:
  1. 指定准确的时间范围
  2. 等待所有技能完成再分析结果
  3. 结合多个技能的发现推导结论
  4. 记录诊断过程便于事后分析

❌ DON'T:
  1. 在事件发生后立即诊断（可能数据还未写入）
  2. 只看单一技能报告做决策
  3. 忽视置信度低的结论
  4. 对诊断结果盲目执行修复
```

## 🎓 学习路径

### 初级: 学会基础分析
```bash
python iis_analyzer.py your_log.log
# 理解输出的指标和问题分类
```

### 中级: 理解技能触发逻辑
```bash
# 阅读 IIS_logs/SKILL.MD 的"跨技能集成指南"部分
# 理解什么问题触发什么技能
```

### 高级: 自定义诊断流程
```bash
# 修改 orchestrator/skill_orchestrator.py
# 根据实际场景调整诊断策略
```

---

**更多详情请查看**: [README.md](./README.md)
