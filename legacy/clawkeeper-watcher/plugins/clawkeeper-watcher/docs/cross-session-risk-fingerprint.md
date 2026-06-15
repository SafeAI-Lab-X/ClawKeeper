# 跨会话风险指纹 (Cross-Session Risk Fingerprint)

## 概述

跨会话风险指纹是 Clawkeeper-Watcher 远端模式的核心特色能力之一。它将 decision-memory 中沉淀的历史决策数据转化为可复用的「风险指纹库」，自动识别导致 stop 或 ask_user 的重复工具组合与停止原因，并在新请求命中已知模式时附加预警信息。

远端越用越聪明——系统从历史决策中自动提炼风险指纹，让相同类型的风险不再需要从零判断。

---

## 工作原理

### 指纹定义

一个「风险指纹」是从历史非 continue 决策中提取的归一化签名，由两个维度构成：

| 维度     | 来源                                 | 示例              |
| -------- | ------------------------------------ | ----------------- |
| 工具组合 | 决策记录中的 `toolNames`（排序去重） | `bash,exec`       |
| 停止原因 | 决策记录中的 `stopReason`            | `tool_loop_limit` |

两个维度拼接形成指纹 key：

```
bash,exec|tool_loop_limit
write|waiting_user_confirmation
|user_requested_stop            ← 无工具调用时
```

> 指纹 key 故意不包含 riskLevel——相同工具+原因但不同风险等级的记录视为同一模式，聚合时自动保留最高风险等级。

### 数据流

```
┌─────────────────────────────────────────────────────────────────┐
│                     context-judge 请求到达                        │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │  judgeForwardedContext  │  ← 现有判定逻辑，不改动
              └────────────┬───────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │   resolveFingerprint   │  ← 新增：指纹匹配
              │                        │
              │  1. 检查 config 启用    │
              │  2. 读取缓存指纹库      │
              │  3. 匹配当前上下文      │
              └────────────┬───────────┘
                           │
                    ┌──────┴──────┐
                    │ 命中？       │
                    ├─ 是 → 附加   │  decision.fingerprint = { ... }
                    └─ 否 → 跳过   │  字段不出现，完全向后兼容
                           │
                           ▼
              ┌────────────────────────┐
              │  appendDecisionMemory  │  ← 现有持久化逻辑
              └────────────┬───────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │     返回 HTTP 响应      │
              └────────────────────────┘
```

### 缓存策略

指纹库通过内存缓存管理，避免每次请求都读取磁盘：

- **TTL**：5 分钟自动过期
- **数据量**：仅保存非 continue 或中等以上风险的决策，7 天约 ~700 条记录
- **内存占用**：100 个唯一指纹约 20KB
- **冷启动**：首次请求读取 7 个 JSONL 文件，约 1-5ms

---

## 配置

在插件配置的 `contextJudge` 块下添加 `fingerprint` 子对象：

```json
{
  "contextJudge": {
    "fingerprint": {
      "enabled": true,
      "lookbackDays": 7,
      "minOccurrences": 2
    }
  }
}
```

| 参数             | 类型    | 默认值  | 说明                                                 |
| ---------------- | ------- | ------- | ---------------------------------------------------- |
| `enabled`        | boolean | `false` | 是否启用跨会话风险指纹匹配（仅 remote 模式生效）     |
| `lookbackDays`   | integer | `7`     | 回溯天数，扫描最近 N 天的决策历史                    |
| `minOccurrences` | integer | `2`     | 最小出现次数，指纹出现 >= 该值时才标记为已知风险模式 |

---

## 响应格式

### 命中时

当当前请求的工具组合 + 停止原因匹配到已知风险模式时，响应中额外携带 `fingerprint` 字段：

```json
{
  "version": 1,
  "decision": "ask_user",
  "stopReason": "waiting_user_confirmation",
  "shouldContinue": false,
  "riskLevel": "high",
  "summary": "...",
  "mode": "remote",
  "fingerprint": {
    "matched": true,
    "key": "bash,exec|waiting_user_confirmation",
    "occurrences": 5,
    "maxRiskLevel": "high",
    "sessionCount": 3,
    "lastSeen": "2026-03-24T10:30:00.000Z",
    "toolNames": ["bash", "exec"],
    "stopReason": "waiting_user_confirmation",
    "warning": "This tool+reason combination has triggered 5 non-continue decisions across 3 session(s) in the lookback window."
  }
}
```

### 未命中时

`fingerprint` 字段**不出现**（非 null，非空对象），现有消费方完全不受影响。

### 字段说明

| 字段           | 类型     | 说明                               |
| -------------- | -------- | ---------------------------------- |
| `matched`      | boolean  | 固定为 `true`（仅命中时返回）      |
| `key`          | string   | 指纹签名，格式 `<tools>\|<reason>` |
| `occurrences`  | number   | 历史出现次数                       |
| `maxRiskLevel` | string   | 历史中观测到的最高风险等级         |
| `sessionCount` | number   | 涉及的独立会话数                   |
| `lastSeen`     | string   | 最近一次出现的时间戳 (ISO 8601)    |
| `toolNames`    | string[] | 涉及的工具列表（排序）             |
| `stopReason`   | string   | 停止原因                           |
| `warning`      | string   | 人类可读的预警描述                 |

---

## CLI 命令

### 查看指纹库

```bash
openclaw clawkeeper-watcher fingerprints [options]
```

| 选项         | 说明          | 默认 |
| ------------ | ------------- | ---- |
| `--days <N>` | 回溯天数      | 7    |
| `--min <N>`  | 最小出现次数  | 2    |
| `--json`     | JSON 格式输出 | -    |

### 示例

```bash
# 查看最近 7 天的风险指纹
openclaw clawkeeper-watcher fingerprints

# 查看最近 14 天、至少出现 3 次的指纹，JSON 输出
openclaw clawkeeper-watcher fingerprints --days 14 --min 3 --json
```

### 输出示例

```
Risk Fingerprints (2 known patterns)

------------------------------------------------------------------------
  Key:       bash,exec|tool_loop_limit
  Tools:     bash, exec
  Reason:    tool_loop_limit
  Count:     5 occurrences across 3 session(s)
  Max Risk:  high
  Last Seen: 2026-03-24T10:30:00.000Z
------------------------------------------------------------------------
  Key:       write|waiting_user_confirmation
  Tools:     write
  Reason:    waiting_user_confirmation
  Count:     3 occurrences across 2 session(s)
  Max Risk:  medium
  Last Seen: 2026-03-23T14:20:00.000Z
------------------------------------------------------------------------

Lookback: 7 day(s) | Min occurrences: 2
```

---

## 适用场景

| 场景                                      | 指纹如何帮助                                               |
| ----------------------------------------- | ---------------------------------------------------------- |
| 同一个 bash+exec 组合反复触发工具循环限制 | 新请求进来时立即预警「这个组合在过去 7 天已触发 5 次停止」 |
| 某个高风险工具调用频繁需要用户确认        | 指纹记录确认频次和涉及会话数，帮助评估是否调整策略阈值     |
| 新会话重现旧问题                          | 跨会话匹配让系统不必从零开始识别风险，缩短判定延迟         |
| 治理复盘                                  | CLI 查看指纹库，快速了解过去一段时间的主要风险模式分布     |

---

## 架构细节

### 涉及文件

| 文件                                | 职责                                                             |
| ----------------------------------- | ---------------------------------------------------------------- |
| `src/core/risk-fingerprint.js`      | 核心模块：key 生成、历史读取、指纹提取、匹配、缓存、报告         |
| `src/core/risk-fingerprint.test.js` | 34 个单元测试                                                    |
| `src/core/decision-memory.js`       | 共享工具函数 (`getBeijingDateStamp`, `resolveDecisionMemoryDir`) |
| `src/plugin/context-judge-http.js`  | HTTP handler 集成点                                              |
| `src/plugin/sdk.js`                 | 配置传递                                                         |
| `src/plugin/cli.js`                 | `fingerprints` CLI 子命令                                        |
| `src/index.js`                      | 公开导出                                                         |
| `openclaw.plugin.json`              | 配置 schema 定义                                                 |

### 公开 API

```js
import {
  resolveFingerprint, // 顶层入口：config 检查 → 缓存读取 → 匹配
  loadDecisionHistory, // 读取 N 天的 JSONL 历史记录
  extractFingerprints, // 从记录中提取指纹频率 Map
  matchFingerprint, // 匹配当前上下文与指纹库
  buildFingerprintReport, // 生成人类可读报告
  getCachedFingerprintMap, // 获取带缓存的指纹 Map
  invalidateFingerprintCache, // 强制清除缓存
} from "clawkeeper-watcher";
```

### 设计约束

- **仅 remote 模式**：指纹匹配依赖 decision-memory，后者仅在 remote 模式下持久化
- **向后兼容**：`fingerprint` 字段仅在命中时出现，不破坏现有响应 schema
- **零新依赖**：纯 Node.js 内置模块
- **优雅降级**：无历史数据时静默跳过，不产生错误；损坏的 JSONL 行自动忽略
- **功能默认关闭**：需要显式设置 `fingerprint.enabled: true` 才生效
