# 001 电台 homePageUrl 存储型 XSS（javascript: URI 经 UrlField 原样写入 href）

## 标题

电台 `homePageUrl` 字段未做 URL scheme 校验，存储 `javascript:` URI 后由前端 UrlField 原样输出为 `<a href>`，任意已登录用户在 Radios 页点击该链接即在应用同源执行脚本。

## 类型

存储型。

## 前提

注入需要管理员账号（电台写操作在仓库层强制 `IsAdmin`，听众写入返回 403）。受害者为任意已登录用户（包括 `isAdmin=false` 的听众），需要一次点击（点击 Radios 列表中该电台条目的 `homePageUrl` 链接）。

## 入口

注入：`POST /api/radio`，JSON body `{"name":"...","streamUrl":"...","homePageUrl":"javascript:/*payload*/void 0"}`；更新同理 `PUT /api/radio/{id}`。
输出：`GET /api/radio`（所有已登录用户可读）→ 前端路由 `#/radio`（Radios 列表页）。

## 代码位置

- `ui/src/radio/RadioList.jsx:124-131`（`homePageUrl` 列：`<UrlField source="homePageUrl" target="_blank" rel="noopener noreferrer" />`）
- react-admin `UrlField`（部署包 `/app/assets/index-7wbOXZOY.js` 中 `displayName:"UrlField"` 的组件将记录值直接传给 MUI `Link` 的 `href`，无 scheme 校验）
- `ui/src/utils/validations.js:1-12`（`urlValidate` 用 `new URL(value)` 校验，`javascript:` 是合法 URL，可通过）
- `server/nativeapi/radios.go:16-30`（`addRadioRoute`：POST/PUT/DELETE 路由）
- `persistence/radio_repository.go`（`isPermitted` 仅校验 `user.IsAdmin`；`Save`/`Update` 对 `homePageUrl` 无 scheme 白名单）

## 原因

`homePageUrl` 是用户可控字符串：服务端入库前只校验权限（IsAdmin），不校验 URL scheme；前端渲染时 react-admin `UrlField` 把记录值原样放进 MUI `Link` 的 `href` 属性（React 属性赋值只防引号逃逸，不防 `javascript:` scheme）。浏览器将 `javascript:` href 的点击导航交给 URL 解释器执行，脚本在应用同源上下文运行，可访问该用户的会话数据与 API 权限。

## 复现

1. 管理员登录：`POST /auth/login`（body 为用户名/密码，凭据见 runtime/receipt-run.json，不在报告中粘贴），取得 Bearer token。
2. 注入：`POST /api/radio`，头 `x-nd-authorization: Bearer <token>`、`x-nd-client-unique-id: <任意>`，body `{"name":"xss001radiohp-radio","streamUrl":"http://127.0.0.1:11282/ping","homePageUrl":"javascript:/*xss001radiohp*/void 0"}` → 200，返回 `id`。服务端接受 `javascript:` scheme，无任何过滤。
3. 传播：听众登录 `POST /auth/login` 后 `GET /api/radio` → 200，响应 JSON 中包含该电台且 `homePageUrl` 为 `javascript:/*xss001radiohp*/void 0`（已动态验证；听众尝试自行写入电台则返回 403 "Saving radio: Permission denied"，故注入面仅管理员）。
4. 触发：任意已登录用户打开 UI `#/radio`，点击该电台行显示的主页链接（UrlField 渲染的 `<a href="javascript:...">`）→ 脚本执行。该步骤属浏览器行为，由部署 bundle 证实输出上下文：`UrlField`（`IA.displayName="UrlField"`）实现为 `m.createElement(jo, HT({href:o,...}, yo(a)), o)`，`o` 为记录原值。

动态验证在本次靶场（http://127.0.0.1:11282/）完成第 1-3 步并清理了注入记录。PoC 脚本（管理员凭据）运行退出码 0，证据为 `GET /api/radio` 响应中包含存储的 `javascript:` homePageUrl，脚本登记的清理自动删除了注入记录；RECEIPT 未启用，无验证器重放结论。

## 证据

源码（输出点，`ui/src/radio/RadioList.jsx:124-131`）：

```jsx
homePageUrl: (
  <UrlField source="homePageUrl" onClick={(e) => e.stopPropagation()} target="_blank" rel="noopener noreferrer" />
),
```

服务端无 scheme 校验（`persistence/radio_repository.go` 仅权限判断后直存 `NewRadio` 字段），UI 校验放行 `javascript:`（`ui/src/utils/validations.js`）：

```js
export const urlValidate = (value) => {
  try {
    new URL(value)   // "javascript:alert(1)" 解析成功，不抛错
  } catch (e) { return 'Invalid URL' }
}
```

部署包输出行为（runtime/scratch/index.js 提取，`/app/assets/index-7wbOXZOY.js`）：

```js
IA = m.memo(function(e){ ... m.createElement(jo, HT({className:t, href:o, variant:"body2"}, yo(a)), o) });
IA.defaultProps = { addLabel: !0 }; IA.displayName = "UrlField"
```

动态响应片段（本靶场）：

```
admin create radio: 200 {"id":"1JuNyUt1XIykJMSK6B0jbo"}
listener GET /api/radio: 200
marker visible to listener: True
stored homePageUrl: javascript:/*xss001radiohp*/void 0
cleanup delete: 200
```

## PoC

`poc/001-radio-homepage-js-uri.py`；候选项 `poc_id=001-radio-homepage-js-uri`，`marker=xss001radiohp`。RECEIPT 未启用，无验证结论。
