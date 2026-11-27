# 漏洞文档

每条已证实、可完整追踪输入—传播—输出链路的 XSS 单独一个 Markdown 文件，放在 `findings/`，文件名用三位序号加短横线加英文短名，例如 `findings/001-template-output.md`。

文档使用下面的小节，没有的信息写「无」，不要省略小节：

## 标题

一句话。

## 攻击者角色

明确写出能够控制漏洞输入的角色、所需最低权限及依据；无需登录时写「匿名」。有多个可能角色时逐一列出，并注明哪些已确认、哪些仍待验证。不要填写账号或密码；证据不足时如实写「待确认」及已知条件，不要猜测。

## 受害者角色

明确写出需要访问或操作触发位置的角色及所需权限；有多个可能角色时逐一列出，并注明哪些已确认、哪些仍待验证。写明受害者与攻击者是否必须是不同账号；证据不足时如实写「待确认」及已知条件，不要猜测。<!-- receipt-only -->只确认一个角色时，写上与验证清单一致的角色 ID，且不要写「待确认」。<!-- /receipt-only -->

## 类型

反射型、存储型、DOM 型三选一。

## 前提

未登录，或所需用户组。

## 入口

请求方法、路径、参数。

## 代码位置

源码文件路径、行号，以及负责输出的类/方法/函数或模板布局名称。

## 原因

数据从哪里进入，在哪一次输出时没有按 HTML 上下文编码。

## 复现

按顺序写出最小化验证请求及所需账号角色（不要粘贴密码）；仅有静态证据时，写清调用链和可触发该路径的输入条件。<!-- receipt-only -->启用 RECEIPT 时如实记录其验证结论，不要将未通过验证描述为验证成功。<!-- /receipt-only -->

## 证据

引用具体源码片段或动态响应，说明标记如何进入 HTML、JavaScript、CSS 或 URL 执行上下文。

## PoC

对应脚本的相对路径，例如 `poc/001-template-output.py`；没有攻击脚本时写「无」。<!-- receipt-only -->启用 RECEIPT 时，同时记录候选项 `poc_id` 与验证结论。<!-- /receipt-only -->

# PoC 脚本

不要用 Write、Edit 或重定向写入 `poc/`。只能调用 `submit_poc`（工具全名 `mcp__audit__submit_poc`）。检查不通过时文件不会落盘。

标准输出是证据片段。退出码 0 表示观察到证据，1 表示没有。

脚本必须是下面这个形状。把编号、标记、基址和 `run` 里的请求换成这次漏洞的内容。`default_base_url` 必须等于 TASK.md 里由环境动态生成的本次靶场基址，不能照抄示例地址。<!-- receipt-only -->RECEIPT 重放时验证器会注入隔离环境的基址。<!-- /receipt-only -->标记形如 `xss001finder`：`xss` 加三位序号，再加 4 到 24 位小写字母或数字。标记里不能有网址，也不能读取 Cookie 或其他浏览器数据。

```python
from poclib import Poc

POC = Poc(
    poc_id="001-finder-query",
    marker="xss001finder",
    default_base_url="http://127.0.0.1:17778/",
)

def run(ctx):
    response = ctx.request("GET", "/index.php", params={"q": ctx.marker})
    ctx.expect(ctx.marker in response.text, response.text[:500])

if __name__ == "__main__":
    POC.main(run)
```

约束：

- 必须使用 `from poclib import Poc`。可导入非受限模块，例如 `base64`、`binascii`、`json`、`hashlib`、`hmac`；PBKDF2 可使用 `hashlib.pbkdf2_hmac`。禁止相对导入、通配符导入，以及 `os`、`sys`、`socket`、`subprocess`、`urllib`、`requests` 等受限模块。请求只能走 `ctx.request`，断言只能走 `ctx.expect`。
- `ctx.request` 的路径用站内相对路径。它会拒绝基址以外的主机。
- 不要把密码写进文件。
<!-- receipt-only -->- RECEIPT 重放时，`ctx.username` 和 `ctx.password` 都是空字符串。攻击者需要登录时，在候选项里声明 `attacker_login`，不要在 `run` 里调用目标的登录接口。
- 验证器用当前威胁路径的攻击者账号执行 `attacker_login`，并把浏览器得到的会话 Cookie 交给 `ctx.request`。如果应用使用浏览器存储中的令牌构造认证头，在 `submit_poc` 的 `attacker_auth_headers_json` 声明映射，例如 `[{"source":"localStorage","key":"stirling_jwt","header":"Authorization","prefix":"Bearer "}]`；也支持 `sessionStorage`。只提交存储键和映射，不提交令牌值。后续请求自动附带认证信息。
- 不声明 `attacker_login` 时，攻击者脚本以匿名会话运行。
<!-- /receipt-only -->- 响应只用 `status`、`headers`、`text`、`url`。
- 如果创建了可删除的内容，先 `ctx.on_cleanup(函数)` 登记删除。成功和失败都会调用它。

<!-- receipt-only --># RECEIPT 候选项

任务启用 RECEIPT 时，动态 PoC 分两步提交。不要用 Write、Edit、Shell 或重定向写入 `poc/` 或 `receipt/`。

1. 调用 `submit_poc`（工具全名 `mcp__audit__submit_poc`）登记一条候选项。有攻击者脚本时，`source` 是完整脚本，通过后写入 `poc/<poc_id>.py`，并把脚本正文快照写入 `receipt/candidates/<poc_id>.json`。没有攻击者写入步骤的反射型、DOM 型把 `source` 留空，只写候选文件。`victim_json` 是 JSON 对象字符串。`attacker_login_json` 和 `claim_json` 可留空。校验失败时两个文件都不写。同一 `poc_id` 再次提交只覆盖这一条；若该候选项已有验证结论，结论会改回待验证。
2. 先创建对应报告并写明已知的攻击者和受害者权限及触发条件，再调用 `start_receipt`（工具全名 `mcp__audit__start_receipt`）验证这一条。参数只有 `poc_id` 和 `report_path`（`findings/<文件名>.md`）。它只重放已登记的快照，不读取 `poc/*.py`，也不接收脚本文本。报告缺失或无法选择链路时不会执行验证，结果为 INDETERMINATE。

每次调用都必须包含 `poc_id`、`marker`、`source` 和 `victim_json`。`victim_json` 是字符串，其中包含实际的受害者访问配置，不能省略或用占位路径；`source` 是完整脚本，无攻击者写入步骤时才传空字符串，不能传 `placeholder`。例如无攻击者步骤时参数形状为 `{"poc_id":"001-example","marker":"xss001example","source":"","victim_json":"{\"url\":\"/actual-victim-path\",\"actions\":[]}"}`；路径仅为说明，必须换成实际路径。`attacker_login_json`、`claim_json`、`callback_json` 不需要时可省略。旧版 `submit_receipt_poc_bundle` 已停用，继续旧任务时也要使用当前的逐项提交流程。

采用逐项闭环：每发现一个可构造动态 PoC 的候选问题，立即登记并验证这一条，等待结果，根据结果修正或如实更新报告，再继续下一个。不要先积累多个 PoC 或报告，等全部写完后才统一验证。修改脚本或受害者动作后，必须再次 `submit_poc`，然后对同一个 `poc_id` 重新 `start_receipt`。一次验证只重放当前这一条。

`start_receipt` 是**同步验证工具**：在结果返回前，当前 Agent 回合会阻塞。系统依据 `report_path` 和验证返回值更新报告状态，不解析报告正文来改状态。选择验证路径时会读取「受害者角色」小节；只写明一个角色 ID 且不含「待确认」时，只验证该受害者。返回包含 `poc_id`、`verdict`（`ACCEPTED`、`REJECTED`、`INDETERMINATE`）和非敏感 `reason` 代码；失败时还包含英文说明 `reason_description`。选中路径结论不一致时，说明会按受害者角色 ID 分组，给出每组的结论、原因、条数，以及浏览器动作序号和元素是未找到还是被拦截。分组仍然不含链路 ID、账号、token、Cookie、选择器或页面证据。收到 `REJECTED` 后再修改 PoC 并重新登记、验证。受害者登录或受害者动作因元素未找到或被拦截而超时也是 `REJECTED`（reason 仍可能是 `BROWSER_ERROR`）：报告会离开待验证，系统不会因这份报告再次自动重放。收到 `INDETERMINATE` 时，若分组里已有走完动作的 `REJECTED`，按该组原因修改，不要把整次结果写成基础设施不可用，也不得把它描述为验证成功；没有这种分组时，再记录验证基础设施不可用。

每个 `poc_id` 的 `start_receipt` 最多执行 5 次，返回的 `remaining_verifications` 是剩余次数；验证失败也计次，重新登记候选项或更换报告路径不会重置。系统自动重放和人工 API 不计入此上限。

`submit_poc` 的 JSON 参数不要包 Markdown 代码块。`victim_json` 的形状如下；对象不得附加未列出的字段：

```json
{
  "url": "/relative/path?value={{receipt_token}}",
  "login": [
    {"type": "goto", "path": "/login"},
    {"type": "fill", "selector": "#username", "value": "{{username}}"},
    {"type": "fill", "selector": "#password", "value": "{{password}}"},
    {"type": "click", "selector": "button[type=submit]"},
    {"type": "assert_visible", "selector": "#account"}
  ],
  "actions": [
    {"type": "click", "selector": "#open-preview"},
    {"type": "wait", "milliseconds": 300}
  ]
}
```

`attacker_login_json` 是与 `victim.login` 相同形状的 JSON 数组。`attacker_auth_headers_json` 可选，声明登录后从 `localStorage` 或 `sessionStorage` 读取的键及其请求头映射，必须同时声明 `attacker_login_json`。`claim_json` 只能包含可选的 `finding_type` 和 `note`。

目标在受害者阶段要向攻击者地址取数据时，另传可选的 `callback_json`。它只声明静态响应，脚本不能自己监听，也不能把回连主机名写进源码。验证器在同一个攻击者容器里按这些路由应答，并把 `http://attacker:8090` 注入为 `ctx.callback_origin`。本地直接运行脚本时，该属性是空字符串。响应正文里的 `{{receipt_token}}` 在应答时替换。未登记的路径返回空响应，不回显请求内容。受害者浏览器仍然只能打开站内地址。

```json
{
  "routes": [
    {
      "method": "GET",
      "path": "/control/filtering/status",
      "status": 200,
      "content_type": "application/json",
      "body": "{\"enabled\":true,\"filters\":[{\"url\":\"javascript:window.__receipt_accept('{{receipt_token}}');undefined\"}]}"
    }
  ]
}
```

```python
def run(ctx):
    hostname = ctx.callback_origin
    response = ctx.request("POST", "/config", data={"hostname": hostname})
    ctx.expect(response.status == 200 and hostname, response.text[:300])
```

路由最多 8 条。方法只允许 `GET`、`POST`、`PUT`、`HEAD`。路径必须是以单个 `/` 开始的绝对路径，不能带查询、片段或 `..`。`status` 为 200 到 599。`content_type` 只允许 `application/json`、`text/plain`、`text/html`、`application/javascript`、`text/xml`。正文最多 8192 字节，占位符只允许 `{{receipt_token}}`。不需要回连时把 `callback_json` 留空。

- `marker` 不能与其他候选项重复。同一 `poc_id` 再次提交可以沿用自己的 `marker`。
- 脚本可读取 `ctx.receipt_token`，把本轮 token 写入待触发的载荷。声明了 `callback_json` 时，还可以读取 `ctx.callback_origin`，把它写入目标配置；不要把回连地址写成字符串常量。
- `attacker_login` 和 `victim.login` 均可省略；省略即以匿名会话执行。攻击者请求需要登录时必须写出 `attacker_login`：仅允许 `goto`、`fill`、`click`、`assert_visible`，首步必须是站内相对路径的 `goto`，末步必须是 `assert_visible`，且必须各有一次 `{{username}}` 与 `{{password}}` 的 `fill`。验证器把可信威胁路径中的账号代入这些步骤。脚本继续用 `ctx.request` 访问业务接口，会话 Cookie 和声明的认证头由库自动附带。`ctx.username` 和 `ctx.password` 在重放中为空，不能用来登录。Agent 不得指定身份、账号或 Cookie。
- `victim.url` 必须是站内相对 URL。`actions` 只允许 `click`、`fill`、`select`、`scroll`、`wait`；只能使用 CSS selector，不能执行任意 JavaScript。`click`、`fill`、`select`、`scroll` 的选择器必须只命中一个元素。目标是重复条目时，选择器必须落到包含本次 marker 的那一条，再点击其中的按钮。URL 及 `fill` / `select` 的 `value` 可写 `{{receipt_token}}`，由验证器在每次重放时替换。
- `victim.url` 和受害者登录的 `goto.path` 不得包含认证或会话查询参数；受害者身份由验证器建立。
- XSS 载荷必须在受害者页面实际执行的位置调用 `window.__receipt_accept(token)`。`token` 来自攻击脚本的 `ctx.receipt_token`，或经 `{{receipt_token}}` 注入受害者 URL/动作；不要自行生成或硬编码 token。
- 不得提交或猜测攻击者/受害者身份、威胁路径、账号、密码、Cookie、浏览器调试端口、CDP 地址或回连主机名。回连响应只放在 `callback_json`，主机名只能读取 `ctx.callback_origin`。身份和地址由验证器的可信 Manifest 和 Adapter 决定。
- 一次 `start_receipt` 返回前，不要假定验证已经完成，也不要另行请求 HTTP 验证接口。同步结果是继续挖掘、修正 PoC 或标记验证结论的唯一依据。

<!-- /receipt-only --># 轮次总结

每轮总结写入运行提示指定的 `notes/round-NNN-summary.md`。总结尽可能简洁，只记录以下三项：

```markdown
# 本轮总结

## 已审查文件

- `相对于源码目录的文件路径`

## 发现的漏洞

- `findings/对应漏洞文档.md`

## 下一轮计划

- [ ] 一项可直接执行的审计任务
```

文件和漏洞使用列表；本轮没有发现漏洞时写「无」。下一轮计划必须使用 Todo List（`- [ ]`）。不要记录详细分析过程、请求响应或其他扩展内容。总结必须非空且实际落盘，不能只写在回复里。
