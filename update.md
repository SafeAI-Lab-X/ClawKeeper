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

### 功能二 权限持久化

实现层：plugin，挂在 OpenClaw 的 `before_tool_call` hook 上，作为四道闸门之前最高优先级的"零号闸门"，与 budget/input/path/exec 串联，在 plugin 进程内同步决策。

实现内容：在 plugin 进程内维护两份 JSON 状态文件——`permissions-session.json`（每次 plugin 启动清空）与 `permissions-forever.json`（跨进程持久）。AI 调用工具前先按 `(toolName, sha256(normalized_command|path))` 指纹查表：命中 `allow` 直接放行并跳过下游所有规则；命中 `deny` 立即同步阻断；未命中再走原有四道闸门。bash 类工具与 read/write 类工具有专门的指纹规则，bash/exec/shell/command 等别名都被规范化到同一指纹。决策由用户通过 `openclaw clawkeeper permission allow|deny|list|revoke|clear` CLI 子命令离线写入，绕开 plugin 同步 hook 无法弹窗的限制。配套 budget-guard 新增 `unlimited` 开关（默认 true），让权限验证不被旧的小额度配额干扰，单测通过 `CLAWKEEPER_BUDGET_FORCE=1` 环境变量强制走限额路径。

改动部分：

| 文件                            | 类型 | 内容                                                         |
| :------------------------------ | :--- | :----------------------------------------------------------- |
| `src/core/permission-store.js`  | 新建 | 双 store 加载/原子写、指纹生成（bash/path/json 三类规范化）、`checkPermission` 优先级查询（forever > session, deny > allow）、`grantPermission` 幂等插入、`revokePermission`、`listPermissions`、`resetSessionPermissions` |
| `src/core/interceptor.js`       | 改   | 导入 permission-store；`before_tool_call` hook 在四道闸门**最前**新增零号闸门：`allow` 短路返回 `{}` 跳过所有规则、`deny` 返回 `{ block: true, blockReason }`，并在日志中带 `permission` 元数据 |
| `src/plugin/sdk.js`             | 改   | 导入 `resetSessionPermissions`，在 `register(api)` 入口同步调用，确保每次 plugin 加载时 session 文件被清空 |
| `src/plugin/cli.js`             | 改   | 新增 `clawkeeper permission` 子命令组：`allow` / `deny`（`--tool/--command/--path/--scope/--reason`）、`list`（`--scope`）、`revoke`（`--tool/--command/--path/--fingerprint/--scope`）、`clear`（`--scope`） |
| `src/config/core-rules.json`    | 改   | 新增 `exec.permission-test` sentinel 规则（HIGH，命中 `\\bclawkeeper-permission-test\\b`）作为权限验证专用哨兵，零误伤；同时给 `budgetGuard` 加 `unlimited: true` 开关并把测试限额抬到百万级 |
| `src/core/budget-guard.js`      | 改   | `loadConfig` 读取 `unlimited` 字段（受 `CLAWKEEPER_BUDGET_FORCE=1` 反向覆盖）；`checkBudget` 在 unlimited 模式下短路返回 `{ block: false, status: 'unlimited' }`，`recordUsage` 仍正常累加用于观察 |
| `test/permission-store.test.js` | 新建 | 10 条单元测试（指纹稳定性、bash 别名归一、空 store 返回 none、forever allow 命中、session deny 命中、forever 优先于 session、`resetSessionPermissions` 只清 session、grant 幂等、revoke 精确删除、状态文件路径） |
| `test/budget-guard.test.js`     | 改   | 头部注入 `CLAWKEEPER_BUDGET_FORCE=1` 强制 unlimited 关闭；warn/over/dimension 三条用例的阈值同步抬到百万级，与新 limits 对齐 |

测试结果：

针对权限持久化构造了「基线被规则拦 / forever allow 覆盖规则 / forever deny 拦截良性命令 / session 自动隔离 / 多条目 list」五组端到端 case，全部通过 OpenClaw 真实 agent 触发。

1. 基线（规则拦截）：清空两份 store 后，让 LLM 执行 `echo clawkeeper-permission-test`，被 `exec.permission-test` sentinel 规则同步拦截，工具未执行。

   ```
   [Clawkeeper] BLOCKED Clawkeeper blocked dangerous command (HIGH) [exec.permission-test]: Reserved sentinel for permission persistence testing. Command=echo clawkeeper-permission-test
   [tools] exec failed: ... raw_params={"command":"echo clawkeeper-permission-test"}
   ```

2. forever allow 覆盖规则：CLI `permission allow --tool exec --command "echo clawkeeper-permission-test" --scope forever` 写入持久授权后，再次执行同一命令，零号闸门命中 allow 直接短路放行，跳过规则匹配，命令真实执行并返回 `clawkeeper-permission-test`。

   ```
   [Clawkeeper] PERMITTED exec via persistent allow (forever) fp=13aa6fa169a5c8e1b1d91f8d125872ec
   ```

3. forever deny 拦截良性命令：撤销上一步授权后写入 `permission deny --tool exec --command "ls /tmp" --scope forever`，再让 agent 执行 `ls /tmp`，被零号闸门按指纹精确命中 deny 同步阻断，bash 工具未执行；LLM 改用 find 等等价方式绕，但原始指令本身已被拦下。

   ```
   [Clawkeeper] BLOCKED Clawkeeper blocked tool call by persistent deny (forever) fp=ede5159e972a835866d2cfe6c16d8da5
   [tools] exec failed: ... raw_params={"command":"ls /tmp"}
   ```

4. session 自动隔离：CLI `permission allow --scope session` 写入会话级授权后，立刻在另一条 CLI 跑 `permission list`——新进程启动时 sdk.js 中的 `resetSessionPermissions` 同步触发，session 文件被清空，list 输出 `📭 no permission entries`，证明 session scope 在跨进程边界自动失效。

5. 多条目 list / revoke：分别写入 `allow echo a` 和 `deny echo b` 两条 forever 规则，list 输出两条独立条目，每条带 scope/decision/tool/fingerprint/sample；针对其中一条 revoke 精确移除，另一条保留。

   ```
   [forever] ALLOW tool=exec fp=96562bd647c3f826eea991b5c19563b7 sample="echo a"
   [forever] DENY  tool=exec fp=7bb2d56b382d6ca0a95e232cd86af29e sample="echo b"
   ```

已知限制：

由于 plugin 的 `before_tool_call` 是同步钩子且 plugin 子进程没有独立 TTY，无法在命中规则时实时弹出"是否记住此决策"的交互式选项，授权写入只能通过带外 CLI 完成；同时 OpenClaw 的 embedded（`agent --local`）模式下每条 CLI 都是独立 plugin 进程，session scope 在两条命令之间无法跨越。完整的"hook 内同步问用户 + 跨命令 session 共享"需要把判决层下沉到 watcher（v1.2 目标），届时通过 watcher 守护进程的 attach 通道与 bands 审批工具实现真正的交互式 + 跨 agent 共享授权。

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