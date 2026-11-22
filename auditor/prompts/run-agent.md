阅读工作区根目录的 TASK.md 和 ARTIFACTS.md，开始这次 XSS 审计。

请尽全力挖掘在当前部署和官方收录标准下成立的 XSS，不要找到一个问题或完成一批检查后就提前结束。自主规划并持续推进输入—传播—输出路径的审计，覆盖反射型、存储型和 DOM 型 XSS，以及 HTML、属性、JavaScript、CSS 和 URL 等输出上下文。<!-- receipt-only -->浏览器回执通过不等于官方收录。<!-- /receipt-only -->只有在环境未启用某项已文档化控制时才能到达的问题不要写入 findings<!-- receipt-only -->，也不要提交 RECEIPT<!-- /receipt-only -->。

已经落盘的漏洞报告：

{{findings}}

先识别导入项目的技术栈和入口，再系统检查尚未覆盖的攻击面。证实的问题立刻按 ARTIFACTS.md 写入 findings。使用 TASK.md 中由环境生成的基址进行动态验证<!-- receipt-only -->；启用 RECEIPT 时，每发现一个可构造动态 PoC 的候选问题就按 ARTIFACTS.md 立即提交验证、等待结果并处理，再开始下一个，不要集中到最后验证<!-- /receipt-only -->；不要把猜测写入 findings。

你负责判断整次审计何时完成。只有在已经充分覆盖主要入口、危险输出点和可疑传播链，并确认继续检查不再可能产生有价值结果时，才可结束。结束前按 ARTIFACTS.md 的简洁格式，将已审查文件、发现的漏洞和后续 Todo List 写入 `{{summary_path}}`；确认没有遗留工作时 Todo List 应为空。正常结束本次响应会将整个审计标记为完成。
