# 标题

后台媒体库列表页 `sid` 参数未编码回显到多个表单 action 与 hidden input 属性，造成反射型 XSS（匿名构造链接 → admin/editor 点击触发）。

## 攻击者角色

匿名（无需登录）。反射型场景中攻击者只需构造恶意链接（`GET /admin/media.php?sid=<payload>`）诱导已登录后台用户访问。已通过靶场动态确认：payload 在受害者（admin）会话的响应中原样回显于 6 处属性上下文。

## 受害者角色

- admin（角色 ID `admin`，对应账号 admin1）：已通过靶场动态确认（admin1 会话请求 `admin/media.php?sid=<payload>`，payload 原样输出且可闭合属性；其中上传模态框、外部资源模态框及编辑/移动模态框的输出不受媒体数量条件限制，页面必定渲染）。
- editor（角色 ID `editor`，对应账号 editor1）：`admin/views/media.php` 为所有后台角色共用模板，media 模块在 writer/editor 的 `checkRolePermission` 白名单内，同一 URL 同样回显。已确认（editor 会话可访问同一页面，模板无条件渲染相关模态框）。

受害者和攻击者必须是不同账号（匿名构造，admin/editor 触发）。

## 类型

反射型。

## 前提

受害者需要已登录后台（admin 或 editor 等可访问 `admin/media.php` 的角色）并点击攻击者构造的链接；无其他前提。

## 入口

- 触发（受害者）：`GET /admin/media.php?sid=<payload>`，参数 `sid`。

## 代码位置

- 输入：`admin/media.php` 第 22 行 `$sid = Input::getStrVar('sid');`（仅 addslashes/trim，无 HTML 编码）。
- 输出模板：`admin/views/media.php` 多处——第 240 行 `<input name="sid" value="<?= $sid ?>" type="hidden" />`（位于 `<?php if ($count > 0): ?>` 块内）；第 318 行 `<form action="./media.php?action=upload<?= '&sid=' . $sid ?>" class="dropzone" id="up-form">`；第 333 行 `<form action="./media.php?action=add_external_resource<?= '&sid=' . $sid ?>" method="post" id="external-resource-form">`；第 446、473、527 行 `<input type="hidden" name="sid" value="<?= $sid ?>" />`（均无条件渲染）。

## 原因

`sid` 参数经 `Input::getStrVar`（addslashes + trim）后直接输出到 `value="<?= $sid ?>"` 与 `action="...&sid=<?= $sid ?>"`，均未做 `htmlspecialchars`。addslashes 插入的 `\` 在 HTML 中不是转义符，浏览器在属性值中遇到第一个 `"` 即终止属性；`>` 闭合标签后，随后的 `<img src=x onerror=...>` 被解析为独立标签并在页面加载时执行（模态框标记始终在 DOM 中，无需任何交互）。

## 复现

1. 攻击者（匿名）构造链接 `http://127.0.0.1:56949/admin/media.php?sid="><img src=x onerror=setTimeout(function(){window.__receipt_accept(\`TOKEN\`)},300)>` 发给受害者。
2. admin1（或 editor1）登录后台后访问该链接。
3. 页面 HTML 中出现 `action="./media.php?action=upload&sid=\"\"><img src=x onerror=...>"` 等多处原始输出，浏览器解析时执行 `onerror`，调用 `window.__receipt_accept(TOKEN)`。

RECEIPT 验证（poc_id `006-media-sid-param-reflected`）：`REJECTED`（`VICTIM_URL_AUTH_PARAMETER`）。该拒绝发生在验证器输入策略层：候选项 victim URL 的查询参数名为 `sid`，被验证器按认证类参数（session-id 命名）静态拦截，两条受害者路径（admin/editor）的浏览器动作均未实际执行，载荷执行与否未被浏览器观察。漏洞本身的动态证据来自直连 HTTP 复现（下节）：同一 URL 与会话下 payload 以原始 HTML 回显于 6 处属性上下文，与已通过回执验证的 003（同一模板同一分词路径的 `date` 参数）构成同型链路。

## 证据

动态证据（靶场 http://127.0.0.1:56949/，admin1 会话请求 `/admin/media.php?sid=%22x%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert%28SID%29%3E`，回显 6 处）：

```html
<form action="./media.php?action=upload&sid=\"x\"><img src=x onerror=alert(SID)>" class="dropzone" id="up-form">
<input type="hidden" name="sid" value=\"\"><img src=x onerror=alert(SID)>" />
```

`action`/`value` 属性被第一个 `"` 提前闭合，`<img src=x onerror=alert(SID)>` 成为活动标签。响应无 CSP 头。

## PoC

`poc/006-media-sid-param-reflected.py`（由 RECEIPT 候选项登记生成；poc_id `006-media-sid-param-reflected`，marker `xss006mediasid`）。验证结论：`REJECTED`（`VICTIM_URL_AUTH_PARAMETER`，验证器拒绝参数名为 `sid` 的 victim URL，浏览器动作未执行；直连 HTTP 复现证据见上）。
