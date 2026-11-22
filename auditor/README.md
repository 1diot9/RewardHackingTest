# 通用 XSS 审计器

这是一个基于 Claude Agent SDK（Python）的任意源码项目 XSS 审计器。创建项目时上传源码 ZIP；项目下可创建多个拥有独立工作区的审计任务。提示词位于 `prompts/*.md`，运行时代码负责加载和替换占位符。

项目和任务按以下流程准备：

1. 环境准备：在项目页初始化，Agent 生成 Python 环境脚本、`receipt-manifest.json` 和 `receipt-adapter.json`。动态环境必须由上游默认分支的最新提交编译得到；缺少编译器或运行时时应先安装。该提交无法建成时，Agent 写入 `environment/INITIALIZATION_FAILED.md`，系统不再测试，也不接受改用旧镜像凑合的环境。系统检查 Docker，运行脚本验证服务及各账号登录，成功后清理测试实例；失败时保留该次测试实例、运行目录和脚本快照，反馈 Agent 最多修改五次（最多测试六次），最终失败记录在 `INITIALIZATION_FAILED.md`。失败记录包含 Compose 项目名和路径；运行目录可能包含测试凭据。新建审计时将验证器使用的环境材料与 Manifest 固定为独立快照。模型调用产生的费用不计入审计预算。

失败的初始化测试位于项目 `setup/runtime/initialization/<运行 ID>/`：`environment/` 是本次测试的脚本快照，`run/` 是运行目录。排错完成后，可在 PowerShell 中设置 `$env:RECEIPT_RUN_ID='<运行 ID>'`、`$env:RECEIPT_RUN_DIR='<run 的绝对路径>'` 和 `$env:COMPOSE_PROJECT_NAME='receipt-<运行 ID>'`，执行 `python '<environment 的绝对路径>/start.py' --cleanup`，再删除对应的运行 ID 目录。每个失败实例都需分别清理。
2. 审计：检查任务工作区中的环境材料后，手动开始审计。Agent 只读项目的导入源码，报告写入任务的 `findings/`。如提供靶场地址，Agent 可进行受限的动态验证；否则完成静态源码审计。

前端的“漏洞报告”区域只展示 Agent 写入的 `findings/*.md`。启用验证器时，提交候选项需提供候选项到报告路径的关联，系统根据最近一次 RECEIPT 返回值显示“审核通过”“审核不通过”或“待审核”（包括验证不确定）。关联和状态独立保存，不解析报告正文。笔记、PoC 与验证原始结果不在该区域展示。

## ZIP 导入边界

仅接受 ZIP，最多包含 100,000 个文件、解压后最多 250 MiB。导入器会拒绝空包、超过上限的压缩包，以及绝对路径、父目录路径和符号链接；在 Windows 上也会拒绝系统不支持的文件名。导入时支持 Windows 长路径，使用源码的外部工具仍需自身支持长路径。导入的源码保存在项目目录，同项目下的审计共享源码；Agent 不能改写它。

## 可选验证器

验证器沿用 RECEIPT 协议：创建任务时由用户在前端选择一个可信 Manifest。Agent 仅能调用内置的同步验证工具提交受约束的版本化 PoC 清单；工具会在当前 Agent 回合内完成隔离重放，并仅返回脱敏的 `poc_id`、verdict 和 reason。身份、路径和最终判定由任务绑定的可信 Manifest 与 Adapter 决定，Agent 不能选择或读取它们；但可在每个 PoC 中声明认证步骤及受害者触发操作，验证器只会将这些步骤应用到该路径预先固定的账号。前端/API 的人工重放端点也只能使用任务已经绑定的 Manifest：

排查失败时，可查看任务工作区 `receipt/diagnostics.jsonl`：每行包含阶段和运行 ID，适用时记录命令退出码、超时、错误输出或异常。日志位于受保护的 RECEIPT 目录，不提供给 Agent；记录前会过滤已知凭据及敏感字段行，仍应按敏感运行数据管理。历史验证不会自动补全诊断信息，需重新验证后查看。

```text
POST /api/tasks/{task_id}/receipt/verify
{"poc_id":"001-example"}
```

Manifest 不需要签名。内置 `generic-compose` Adapter 使用项目初始化产物，每次重放启动独立 Compose 项目；动态宿主机端口和随机账号仅通过本次运行的 `receipt-run.json` 传递。在“设置 → RECEIPT 验证器”中配置独立的证据签名密钥和不可变 digest 形式的攻击者镜像后即可使用。设置保存在本地 `auditor/data/state.json`，密钥只以掩码形式返回前端；未在设置中填写时，仍兼容读取 `RECEIPT_EVIDENCE_HMAC_KEY` 和 `RECEIPT_ATTACKER_IMAGE` 环境变量。文件及脚本契约见 [验证器文件契约](../docs/contracts/receipt_adapter.md)。自定义可信 Adapter 仍可通过 `RECEIPT_TRUSTED_ADAPTER_MODULES` 安装。静态检查通过不保证重放成功。

设置页的“自动配置”会保留已有配置，缺少密钥时生成随机密钥，缺少镜像配置时使用 `python:3.12-slim` 的仓库 digest；镜像在本地不存在时会通过 Docker 拉取。使用前请启动 Docker；拉取失败时页面会显示错误，且不会保存部分配置。

## 运行

在“设置 → 初始化网络代理”中可为新启动的环境初始化 Agent 启用 HTTP/HTTPS 代理，例如 `http://127.0.0.1:7890`（端口以本机代理软件为准）。支持填写逗号分隔的额外直连地址；`localhost`、`127.0.0.1`、`::1`、`host.docker.internal` 和已知靶场地址自动加入直连列表，其他内网地址需自行添加。设置保存在本地 `auditor/data/state.json`，不支持在代理地址中填写账号密码。设置只作用于新建的初始化 Agent 会话；各工具是否遵循代理变量取决于自身实现。Docker 镜像拉取、构建和容器网络需要在 Docker 中分别配置。

双击仓库根目录的 `start-auditor.bat`，或 `auditor/start.bat`。脚本会在需要时安装依赖，启动 API（`127.0.0.1:8787`）与前端（`127.0.0.1:5179`）。

双击 `auditor/restart.bat`，或运行 `powershell -ExecutionPolicy Bypass -File .\auditor\restart.ps1`，可先停止审计器再重新启动。若端口仍被占用，脚本会报错并停止重启。

先在“模型商”中完成连接、模型获取和定价；随后创建项目并上传 ZIP，在项目中初始化环境和创建审计。靶场地址是可选项，但启用验证器时必须提供。删除项目会删除其审计和工作区；初始化可能启动的 Docker 资源需要按生成的环境说明单独清理。密钥位于 `auditor/data/state.json`，项目和任务数据分别位于 `auditor/projects/`、`auditor/workspaces/`，均不应提交。
