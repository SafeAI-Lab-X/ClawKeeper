### 功能一



### 功能二

### 功能三

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