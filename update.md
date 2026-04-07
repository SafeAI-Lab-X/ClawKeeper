### 功能一 执行前拦截门

实现层：plugin，挂在 OpenClaw 的 `before_tool_call` hook 上，与 path-guard 并列、在 plugin 进程内同步决策。

实现内容：在 AI 调用 bash 类工具前，按规则正则匹配命令文本，命中红/黄线危险命令立即同步阻断，bash 工具拿不到执行机会。覆盖 fork bomb、磁盘 wipe、`rm -rf /`、`curl|sh`、shutdown/reboot、防火墙清空、`chmod 777` 等 7 类高危场景。

改动部分：

| 文件                         | 类型 | 内容                                                         |
| :--------------------------- | :--- | :----------------------------------------------------------- |
| `src/config/core-rules.json` | 改   | 新增 `executionGate` 配置段 + 7 条 `dangerousCommands` 规则  |
| `src/core/exec-gate.js`      | 新建 | 规则加载 + 命令文本抽取 + 正则匹配 + 主判决函数              |
| `src/core/interceptor.js`    | 改   | `before_tool_call` hook 在 path-guard 之后串接 exec-gate，命中返回 `{ block: true, blockReason }` |
| `test/exec-gate.test.js`     | 新建 | 8 条单元测试                                                 |

测试结果：

1. fork bomb 字面量被命中 `exec.fork-bomb` 规则，bash 工具同步中断，命令未执行。

   ```
   [Clawkeeper] BLOCKED Clawkeeper blocked dangerous command (CRITICAL) [exec.fork-bomb]: Classic bash fork bomb. Command=echo ':(){ :|:& };:'
   [tools] exec failed: Clawkeeper blocked dangerous command (CRITICAL) [exec.fork-bomb] ...
   ```

2. `dd if=/dev/zero of=/dev/sda bs=1M` 被命中 `exec.disk-wipe` 规则，写盘前同步拦截，零副作用。

   ```
   [Clawkeeper] BLOCKED Clawkeeper blocked dangerous command (CRITICAL) [exec.disk-wipe]: Disk wipe / low-level format. Command=dd if=/dev/zero of=/dev/sda bs=1M
   ```

3. 良性命令 `ls /tmp` 正常放行，目录内容被 LLM 正确读取，未出现误拦。

### 功能五 Token 预算控制

实现层：plugin，主闸门挂在 OpenClaw 的 `before_agent_reply` hook 上（首次新增的非 `before_tool_call` hook），副闸门复用 `before_tool_call`，记账层挂在 `llm_output` hook 上，全部在 plugin 进程内同步决策。

实现内容：在 `~/.openclaw/workspace/clawkeeper/budget.json` 维护一个滚动窗口的 token 用量计数器（默认 1 天）。每次 LLM 调用结束后从 `event.usage` 累加 input/output/total，超过 80% 阈值打 warn 日志，超过 100% 阈值熔断后续 LLM 调用与工具调用。三类配额（input/output/total）任一超限即判 over，窗口过期自动重置，状态文件原子写入避免并发损坏。

改动部分：

| 文件                         | 类型 | 内容                                                         |
| :--------------------------- | :--- | :----------------------------------------------------------- |
| `src/config/core-rules.json` | 改   | 新增 `budgetGuard` 配置段：开关 / windowDays / warnRatio / limits（测试阶段 input=1000, output=500, total=1500） |
| `src/core/budget-guard.js`   | 新建 | 预算加载/原子写、滚动窗口判定、`recordUsage` 累加、`checkBudget` 纯查询、`formatBudgetSummary` 摘要 |
| `src/core/interceptor.js`    | 改   | 导入 budget-guard；`before_tool_call` hook 在四道闸门最前加 budget 兜底；`llm_output` hook 在原日志基础上调 `recordUsage` 并打 warn/over 日志；新增 `createBeforeAgentReplyHook` 工厂返回 `{handled: true, reply: {...}}` 短路 LLM |
| `src/plugin/sdk.js`          | 改   | 注册第 6 个 hook：`before_agent_reply` budget guard          |
| `test/budget-guard.test.js`  | 新建 | 8 条单元测试（往返存读、累加、warn/over 阈值、单维度超限、滚动窗口重置、缺文件 fail-open、摘要格式化） |

测试结果：

针对预算守卫构造了「空预算累加 / 强制超限拦截 / 还原恢复」三组端到端 case，全部通过 OpenClaw 真实 agent 触发。

1. 空预算累加（基线）：删除 budget.json 后执行 `echo hello`，命令正常执行，文件自动落地，`usage.calls=1`、`lastDecision: "ok"`、input/output 各几十到几百 token，状态结构完整。

2. 强制超限拦截：把 budget.json 的 usage 直接改写为 input=99999/output=99999/total=199998 模拟严重超限，再发 `echo hi` 工具调用，被 `before_tool_call` 副闸门同步阻断，bash 工具未执行；同时 `llm_output` 计入新一轮 token，`BUDGET OVER` 日志打印。

   ```
   [Clawkeeper] BLOCKED Clawkeeper blocked tool call: token budget exhausted (input=100140/1000 output=100136/500 total=200276/1500 calls=101)
   [tools] exec failed: ... raw_params={"command":"echo hi"}
   [Clawkeeper] BUDGET OVER input=100291/1000 output=100281/500 total=200572/1500 calls=102
   ```

3. 还原后恢复：删除 budget.json 后重新执行 `echo recovered`，命令正常放行，文件自动重建为新窗口、计数从 0 起算、`lastDecision` 回到 `ok`，验证 hot-reload 与窗口重置行为正确。

已知限制：

`before_agent_reply` 主闸门只在 OpenClaw 的 channel-dispatch 路径（gateway 模式）触发，`openclaw agent --local`（embedded 模式）不跑该层 hook，因此 embedded 下的 LLM 调用本身仍会发生一次，token 会被叠加进下一轮预算；但工具调用层的副闸门照常生效，agent 拿不到任何工具能力，实质上被冻住。完全 0-token 严格阻断需要把判决层下沉到 watcher（v1.2 目标），届时通过 watcher remote 的 cost 估算 + 跨 agent 共享预算实现真正的"前置不调 LLM"。

### 功能二

### 功能三 输入校验升级

实现层：plugin，挂在 OpenClaw 的 `before_tool_call` hook 上，串接在 path-guard 与 exec-gate **之前**作为最前一道闸门，在 plugin 进程内同步决策。

实现内容：在 AI 调用工具前，按 per-tool JSON Schema 子集校验参数（必填字段、类型、长度上限、正则、未知字段策略）。畸形输入（缺字段、类型错、超长、含 NUL/换行）在进入下游正则匹配前即被同步阻断。零依赖、自带 ~140 行轻量校验器，未知工具默认 pass-through 保持向后兼容。

改动部分：

| 文件                                       | 类型 | 内容                                                         |
| :----------------------------------------- | :--- | :----------------------------------------------------------- |
| `src/config/core-rules.json`               | 改   | 新增 `inputValidator` 配置段（开关 + 失败策略 + 未知工具策略） |
| `src/config/tool-schemas/bash.json`        | 新建 | bash 工具 schema，含 `shell`/`exec` 别名，command 上限 8000 字符 |
| `src/config/tool-schemas/read_file.json`   | 新建 | read_file 工具 schema，含 `read`/`fs_read`/`file_read` 别名，path 上限 4096 |
| `src/config/tool-schemas/write_file.json`  | 新建 | write_file 工具 schema，含 `write`/`fs_write`/`file_write` 别名，content 上限 1MB |
| `src/core/input-validator.js`              | 新建 | 轻量 JSON-Schema 子集校验器（type/required/properties/additionalProperties/minLength/maxLength/pattern/enum） |
| `src/core/interceptor.js`                  | 改   | `before_tool_call` hook 在最前串接 validator，命中返回 `{ block: true, blockReason }` |
| `test/input-validator.test.js`             | 新建 | 9 条单元测试                                                 |

测试结果：

针对参数校验器构造了「正确 / 类型错 / 缺必填字段 / 还原」四组端到端 case，全部通过 OpenClaw 真实 agent 触发，验证 schema `aliases` 机制正确匹配 OpenClaw 实际工具名 `exec`。

1. 参数正确（基线）：原始 schema 下执行 `pwd`，三道门全部通过，正常返回 `/root/.openclaw/workspace`，无任何 BLOCKED 日志。

2. 参数类型错误：临时把 bash schema 中 `command` 的 `type` 由 `string` 改为 `number`，再次执行 `pwd`，被 input-validation 同步拦截。LLM 收到失败后改发 `"123"` 重试，仍是字符串字面量，再次被同一道闸门拦下，证明无绕过空间。

   ```
   [Clawkeeper] BLOCKED Clawkeeper blocked malformed tool input for 'exec': input validation failed: $.command: expected number, got string
   [tools] exec failed: ... raw_params={"command":"pwd"}
   [Clawkeeper] BLOCKED Clawkeeper blocked malformed tool input for 'exec': input validation failed: $.command: expected number, got string
   [tools] exec failed: ... raw_params={"command":"123"}
   ```

3. 缺少 required 字段：临时给 schema 加一个虚假必填字段 `ritual`（LLM 不会主动传），执行 `pwd` 被命中 required 校验拦截，错误信息精确定位到 JSON 路径 `$.ritual`。

   ```
   [Clawkeeper] BLOCKED Clawkeeper blocked malformed tool input for 'exec': input validation failed: $.ritual: required field missing
   [tools] exec failed: ... raw_params={"command":"pwd"}
   ```

4. 字符串超长（早期回归 case）：临时把 `command` 的 `maxLength` 改为 3，执行 `ls /tmp`（7 字符）被命中长度上限拦截。

   ```
   [Clawkeeper] BLOCKED Clawkeeper blocked malformed tool input for 'exec': input validation failed: $.command: string longer than maxLength=3 (got 7)
   ```

5. 还原 schema 后再次执行 `pwd` / `ls /tmp` 均正常放行，验证 hot-reload 行为正确，无残留状态。

### 功能四 危险文件保护清单

实现层：plugin，所有逻辑挂在 OpenClaw 的 before_tool_call hook 上，在 plugin 进程内同步决策。

实现内容：在 AI 调用工具前，先检查它要碰的文件路径是不是在"不许动"清单里——是就直接打回去，LLM 拿不到文件内容。

改动部分：

| 文件                         | 类型 | 内容                                                         |
| :--------------------------- | :--- | :----------------------------------------------------------- |
| `src/config/core-rules.json` | 改   | 新增 22 条 `protectedPaths` 规则 + `pathGuard` 配置段        |
| `src/core/path-guard.js`     | 新建 | 路径规范化 + glob 匹配 + 参数抽取 + 主判决函数               |
| `src/core/interceptor.js`    | 改   | before_tool_call hook 调 guard，命中返回 `{ block: true, blockReason }` |
| `test/path-guard.test.js`    | 新建 | 14 条单元测试                                                |

测试结果：

1. `~/.bashrc`在`core-rules.json`中被列为了保护文件，因此执行时被阻止。

   ![image-20260406220737285](C:/Users/buzheng/AppData/Roaming/Typora/typora-user-images/image-20260406220737285.png)

   ![image-20260406221355088](C:/Users/buzheng/AppData/Roaming/Typora/typora-user-images/image-20260406221355088.png)

2. `tmp`文件作为安全文件，执行读指令时正常放行。

   ![image-20260406221611014](C:/Users/buzheng/AppData/Roaming/Typora/typora-user-images/image-20260406221611014.png)

   ![image-20260406221723215](C:/Users/buzheng/AppData/Roaming/Typora/typora-user-images/image-20260406221723215.png)