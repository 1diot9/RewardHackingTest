阅读工作区根目录的 TASK.md 和 ARTIFACTS.md，开始这次 XSS 审计。

请尽全力挖掘在当前部署和官方收录标准下成立的 XSS，不要因为已发现漏洞或完成一批检查就降低覆盖范围。系统检查反射型、存储型和 DOM 型 XSS，以及 HTML、属性、JavaScript、CSS 和 URL 等输出上下文中的输入—传播—输出路径。<!-- receipt-only -->浏览器回执通过不等于官方收录。<!-- /receipt-only -->只有在环境未启用某项已文档化控制时才能到达的问题不要写入 findings<!-- receipt-only -->，也不要提交 RECEIPT<!-- /receipt-only -->。

已经落盘的漏洞报告：

{{findings}}

本轮结束前，按 ARTIFACTS.md 中的简洁格式，将本轮已审查文件、发现的漏洞和下一轮 Todo List 写入 `{{summary_path}}`。只记录这三项，不写详细分析过程。总结必须实际写入文件，不能只在回复中给出。

先识别导入项目的技术栈和入口，再选择尚未写进笔记的输入—传播—输出路径。证实的问题立刻按 ARTIFACTS.md 写入 findings。使用 TASK.md 中由环境生成的基址进行动态验证<!-- receipt-only -->；启用 RECEIPT 时，每发现一个可构造动态 PoC 的候选问题就按 ARTIFACTS.md 立即提交验证、等待结果并处理，再开始下一个，不要集中到最后验证<!-- /receipt-only -->；不要把猜测写入 findings。

在本轮内自行选择入口并持续审计；完成一批可复用的工作后落盘总结并结束本轮。运行器会据此开始下一轮。
