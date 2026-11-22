继续尽全力挖掘在当前部署和官方收录标准下成立的 XSS。不要因为已发现漏洞或完成一批检查就降低覆盖范围；系统检查反射型、存储型和 DOM 型 XSS，以及 HTML、属性、JavaScript、CSS 和 URL 等输出上下文中的输入—传播—输出路径。

重新阅读 `TASK.md` 中的安全政策要求、工作区 `SECURITY.md` 索引和 `security-policy/` 下的全部副本（若有）。排除条款按候选问题的真实前提适用。只有在环境未启用某项已文档化控制时才能到达的问题不要写入 findings<!-- receipt-only -->，也不要提交 RECEIPT<!-- /receipt-only -->。<!-- receipt-only -->浏览器回执通过不等于官方收录。<!-- /receipt-only -->

上一轮已落盘的总结文档位置：`{{previous_summary_path}}`

本轮总结文档落盘位置：`{{summary_path}}`

已发现的漏洞文档位置：
{{findings}}
