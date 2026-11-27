# XSS 审计与验证引擎

基于 Claude Agent SDK 的源码 XSS 审计工具。它将源码导入、环境准备、Agent 审计和可选的 RECEIPT 隔离重放整合到一个本地 Web 界面中，帮助审计人员检查候选漏洞并管理报告。

本仓库包含引擎及其前端，不包含待审计项目、靶场或审计工作区。请仅对获得授权的项目和环境进行测试。

## 主要功能

- **项目导入**：上传源码 ZIP；同一项目可创建多个独立审计任务，Agent 以只读方式访问导入的源码。
- **环境准备**：Agent 生成环境脚本和验证器配置，系统测试服务与账号登录，并保存失败测试的诊断材料。
- **XSS 审计**：通过可编辑提示词驱动 Agent 检查源码；提供目标地址时可进行受限动态验证。
- **RECEIPT 验证**：使用可信 Manifest 和 Adapter 重放候选 PoC，返回验证结果；内置 `generic-compose` Adapter 为每次重放启动独立 Compose 项目。
- **报告与任务管理**：在界面中查看漏洞报告、验证状态、任务进度及模型用量。

## 环境要求

- Windows、PowerShell、Python 和 Node.js/npm。
- 可用的模型服务及其连接、模型和定价配置。
- 使用环境初始化或 RECEIPT 动态重放时，需要运行 Docker 和 Docker Compose，并能够获取所需镜像。

Python 依赖见 `requirements.txt`，前端依赖见 `frontend/package.json`。首次启动时脚本会检查并安装缺失的依赖。

## 快速开始

1. 克隆仓库，在根目录双击 `start.bat`，或运行：

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\start.ps1
   ```

2. 打开 <http://127.0.0.1:5179/>。后端默认监听 `127.0.0.1:8787`。
3. 在“模型商”中配置连接、获取模型并设置定价。
4. 创建项目并上传源码 ZIP，在项目中初始化环境，然后创建并开始审计任务。

使用 `stop.bat` 停止服务，使用 `restart.bat` 重启；也可分别运行对应的 PowerShell 脚本。初始化 Agent 的 HTTP/HTTPS 代理可在“设置 → 初始化网络代理”配置，该设置只影响新启动的初始化会话，不会自动配置 Docker 网络或镜像拉取。

## 审计和验证流程

1. **导入源码**：仅支持 ZIP，最多 100,000 个文件、解压后最多 250 MiB。导入器拒绝空包、超限文件、绝对路径、父目录路径及符号链接；Windows 上也会拒绝不受支持的文件名。
2. **准备环境**：初始化 Agent 生成环境脚本、`receipt-manifest.json` 和 `receipt-adapter.json`。动态环境要求从上游默认分支的最新提交构建。系统测试服务及账号，失败时反馈 Agent 修改；最终无法完成时记录失败原因。
3. **执行审计**：任务使用固定的环境材料和 Manifest 快照。Agent 将报告写入工作区的 `findings/`；未提供靶场地址时执行静态审计。
4. **验证候选项**：启用验证器后，Agent 提交受约束的版本化 PoC 清单，由绑定的可信 Manifest 和 Adapter 决定身份、路径及最终判定。界面按最近一次验证结果展示报告状态；静态检查通过不代表重放一定成功。

## RECEIPT 配置与排错

在“设置 → RECEIPT 验证器”中配置独立的证据签名密钥和以不可变 digest 指定的攻击者镜像。自动配置可补齐缺失项，并在镜像不存在时尝试拉取。也可通过 `RECEIPT_EVIDENCE_HMAC_KEY` 和 `RECEIPT_ATTACKER_IMAGE` 提供配置；自定义可信 Adapter 通过 `RECEIPT_TRUSTED_ADAPTER_MODULES` 指定。

人工重放使用任务已绑定的 Manifest：

```http
POST /api/tasks/{task_id}/receipt/verify
Content-Type: application/json

{"poc_id":"001-example"}
```

验证失败时可查看任务工作区的 `receipt/diagnostics.jsonl`。日志会过滤已知凭据和敏感字段行，但仍应作为敏感运行数据管理。初始化失败时，项目的 `setup/runtime/initialization/<运行 ID>/` 保留环境脚本快照和运行目录；排错完成后应按生成的环境说明清理对应 Docker 资源。

## 目录结构

```text
app/           FastAPI 后端、审计任务和验证器
frontend/      React 前端
prompts/       可编辑的 Agent 提示词
runtime/       PoC 运行时辅助代码
tests/         后端测试
data/          本地配置和状态（不提交）
projects/      导入的项目及初始化数据（不提交）
workspaces/    审计任务工作区和结果（不提交）
```

`data/state.json` 可能包含模型服务凭据和验证器密钥，请妥善保管。删除项目会删除其审计任务和工作区；初始化过程中启动的 Docker 资源可能需要单独清理。

## 开发与测试

在仓库根目录运行：

```powershell
python -m unittest discover -s tests -v
npm --prefix frontend run build
```

前端开发服务器可通过 `npm --prefix frontend run dev` 启动。API 和前端的一键启动脚本面向本地使用。
