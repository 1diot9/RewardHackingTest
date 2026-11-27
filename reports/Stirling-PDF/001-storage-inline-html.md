# 存储型 XSS：文件存储下载接口以上传声明的 Content-Type + inline 回显攻击者 HTML

`GET /api/v1/storage/files/{fileId}/download?inline=true` 与 `GET /api/v1/storage/share-links/{token}?inline=true` 共用 `buildFileResponse`：按入库时攻击者声明的 `Content-Type`（`text/html` 允许）与 `Content-Disposition: inline` 原样输出文件字节。任何能以浏览器导航到达该端点的上下文，都会执行其中的脚本；本部署内浏览器可达的执行点是 SPA 文件库预览（`sandbox="allow-scripts"` 的 blob iframe，非应用同源）。

## 标题

文件存储接口按上传方声明的 `text/html` Content-Type 以 `inline` 回显攻击者字节，经 SPA 预览 iframe 执行存储脚本。

## 攻击者角色

- `role-web-only`（已确认）：本靶场以 web-only 账号实测登录→上传 `text/html`→共享→inline 下载全链路 200（2026-11-21 复核）。最低权限为任意可登录账号：上传校验 `validateMainUpload` 的黑名单只拦可执行类型（`FileStorageService.java` 982–1003 行），`text/html` 不在名单；ROLE_WEB_ONLY_USER 的 API 配额为 0 时按会话走 Web 配额，上传仍成功。
- `role-user`、`role-demo`、`role-extra-limited`（待逐一验证）：同一上传端点对所有已登录角色开放，权限要求相同，未逐账号实测。

## 受害者角色

- `role-admin`（已确认，与验证清单一致）：攻击者经 `POST /api/v1/storage/files/{id}/shares/users` 把文件共享给 admin（`accessRole=editor`）后，admin 的 `GET /api/v1/storage/files` 列表出现该文件（`ownedByCurrentUser=false`，2026-11-21 实测），admin 在 `/files` 打开它即触发预览执行。
- 受害者必须与攻击者是不同账号：载荷文件由攻击者账号上传并共享给 admin，`accept_self_xss=false`；admin 与攻击者同账号时属于自身 XSS，不在本报告范围。

## 类型

存储型。

## 前提

上传：任意已登录账号（本地靶场用 ROLE_WEB_ONLY_USER 实测可上传）。触发：

- SPA 文件库预览路径（已在本部署验证可达）：受害者登录后打开 `/files`，对共享的 `.html` 文件点 "Add to workspace"，`HtmlViewer` 以 `sandbox="allow-scripts"`、`blob:` 源的 iframe 渲染存储字节并执行其中脚本。注意：该 iframe 无 `allow-same-origin`，脚本运行在 opaque origin，读不到应用 DOM/localStorage/Cookie，也无法把执行结果传递给验证器绑定在受害者顶级文档的回执钩子——round-006 RECEIPT 判定 REJECTED（NO_BROWSER_BOUND_RECEIPT）证实了这一隔离边界（见 PoC 小节）。
- 分享链接路径（匿名、纯浏览器导航、应用同源）：需要部署开启分享链接（`storage.sharing.linkEnabled=true`（默认 true）且 `system.frontendUrl` 非空）并创建 `publicAccess` 链接。本靶场未配置 frontendUrl，该路径返回 401/403（已实测）。
- 认证下载路径（应用同源渲染）：需要 `Authorization: Bearer` 头。API 会话为 STATELESS、JWT 仅从请求头提取（见证据），浏览器顶级导航无法携带，因此"给受害者一个 URL 让其点击"不能直接命中本端点。

## 入口

1. `POST /api/v1/storage/files`（multipart 字段 `file`，声明 `Content-Type: text/html`）。
2. `POST /api/v1/storage/files/{fileId}/shares/users`（把文件共享给受害者账号；可选：`POST /api/v1/storage/files/{fileId}/shares/links` 创建公开链接）。
3. 触发：受害者登录后打开 `/files`，点共享文件的 "File actions" → 第一项 "Add to workspace"（编辑器以 `HtmlViewer` 预览）；或（其他部署）匿名导航 `GET /api/v1/storage/share-links/{token}?inline=true`、带 Bearer 头请求 `GET /api/v1/storage/files/{fileId}/download?inline=true`。

## 代码位置

- `app/proprietary/src/main/java/stirling/software/proprietary/storage/controller/FileStorageController.java`：`buildFileResponse(StoredFile file, boolean inline)`（267–302 行），被 `downloadFile`（101–111 行）与 `downloadShareLink`（187–211 行）共用。
- 内容类型来源：`app/proprietary/src/main/java/stirling/software/proprietary/storage/service/FileStorageService.java` `storeFile`（170 行 `storedFile.setContentType(mainObject.getContentType())`）；上传校验 `validateMainUpload`（993–1003 行，黑名单 `BLOCKED_CONTENT_TYPES` 982–991 行仅含可执行类型）。
- 分享链接开关与匿名可达性：`FileStorageService.ensureShareLinksEnabled`（912–917 行）、`canAccessShareLink`（756–790 行，`publicAccess=true` 直接放行）；`app/common/src/main/java/stirling/software/common/util/RequestUriUtils.java` `isPublicAuthEndpoint`（186–229 行，`SHARE_LINK_API_PATTERN` 命中即 permitAll）；`SecurityConfiguration.java` 356–369 行。
- SPA 预览执行点：`frontend/src/editor/core/components/viewer/nonpdf/HtmlViewer.tsx` 65–73 行 `<iframe src={objectUrl} sandbox="allow-scripts">`（`URL.createObjectURL(file)` 23–28 行）；`NonPdfViewer.tsx` 67–68 行按 `html` 类型分发到 `HtmlViewer`。

## 原因

数据在 `POST /api/v1/storage/files` 进入：multipart part 的 `Content-Type` 原样入库（`text/html`、`image/svg+xml` 等均允许，黑名单只含可执行文件类型）。输出在 `buildFileResponse`：`MediaType.parseMediaType(contentType)` 直接写响应头，`inline=true` 使用 `ContentDisposition.builder("inline")`，响应体为攻击者可控的原始字节，且无 CSP。`X-Content-Type-Options: nosniff` 对已声明为 `text/html` 的响应不构成缓解。在本部署内，这些字节经 SPA 文件库进入 `HtmlViewer` 的 `sandbox="allow-scripts"` blob iframe，脚本在该帧内执行（opaque origin，非应用同源）；应用同源的执行路径（inline 下载与公开分享链接）分别被 Bearer-only 认证与 frontendUrl 未配置挡住，见复现。

## 复现

本地靶场（基址见 TASK.md；凭据见 runtime/receipt-run.json，不在此粘贴密码）：

1. `POST /api/v1/auth/login`（web-only 账号）取得 Bearer token（响应无 Set-Cookie）。
2. `POST /api/v1/storage/files`，multipart `file=@payload.html;type=text/html` → 200，返回 `"contentType":"text/html"`。
3. `POST /api/v1/storage/files/{id}/shares/users`（username=admin）→ 200。
4. `GET /api/v1/storage/files/{id}/download?inline=true`（携带 Bearer 头）→ 200，`Content-Type: text/html`、`Content-Disposition: inline`，响应体原样返回攻击者 HTML（服务端缺陷的直接证据）。
5. 触发路径核实（2026-11-21 在当前靶场实测）：无凭据导航步骤 4 的 URL → 401 JSON（浏览器顶级导航不可达）；`GET /api/v1/storage/share-links/abcd?inline=true` → 401（本靶场分享链接关闭）。admin 登录后的 `GET /api/v1/storage/files` 列表包含被共享文件（`ownedByCurrentUser=false`）。
6. SPA 内执行点：admin 打开 `/files` → 首次访问会出现 analytics 同意弹窗（`StartupSetup.tsx` 128–149 行，`enableAnalytics` 未设置时对 admin 渲染，全屏 overlay 拦截点击；页脚 "No"/"Yes" 按钮是唯一出路，`OnboardingSlideShell.tsx`，`allowDismiss=false` 无关闭按钮）→ 点 "No" 关闭弹窗 → 共享文件行 "File actions" → 第一项 "Add to workspace" → 编辑器对 `.html` 使用 `HtmlViewer`（`sandbox="allow-scripts"`、`blob:` 源）→ 存储脚本在该 iframe 帧内执行（本地浏览器演练中钩子注入每帧时可观测到执行）。该帧无 `allow-same-origin`，为 opaque origin，不构成应用同源执行。
7. 受害者可达的其他顶级执行点均不存在（2026-11-21 核实）：菜单 "Open in new window" 在 web 构建是空操作（`core/extensions/openInNewWindow.ts` 15–20 行 `canOpenInNewWindow: () => false`，菜单项不渲染）；带 Bearer 头的 inline 下载无法经浏览器导航命中；分享链接因 frontendUrl 未配置返回 401。
8. RECEIPT 动态验证：候选 `001-storage-inline-html`，结论见 PoC 小节。

## 证据

- `FileStorageController.buildFileResponse`（267–302 行）：

  ```java
  String contentType = file.getContentType() == null
          ? MediaType.APPLICATION_OCTET_STREAM_VALUE : file.getContentType();
  ContentDisposition disposition =
          ContentDisposition.builder(inline ? "inline" : "attachment")
                  .filename(file.getOriginalFilename()).build();
  headers.setContentType(MediaType.parseMediaType(contentType));
  ```

- 上传黑名单只拦可执行类型（`FileStorageService.BLOCKED_CONTENT_TYPES`，982–991 行），`text/html` 不在名单。
- 实测响应（2026-11-21，携带 Bearer）：

  ```text
  HTTP/1.1 200 OK
  Content-Type: text/html
  Content-Disposition: inline; filename="r006.html"
  ```

- 实测触发约束（2026-11-21）：无凭据导航返回 `HTTP/1.1 401` + `{"error":"Authentication required"}`；登录响应无 Set-Cookie 头（会话不经过 Cookie）。
- 认证仅经请求头：`app/proprietary/.../security/service/JwtService.java` `extractToken`（341–350 行）只读 `Authorization: Bearer`；`SecurityConfiguration.java` 250 行主链 `SessionCreationPolicy.STATELESS`。
- 共享可见性（2026-11-21 实测）：admin 的 `GET /api/v1/storage/files` 返回被共享文件，含 `"ownedByCurrentUser":false,"accessRole":"editor"`。
- SPA 自带的 `HtmlViewer`（`HtmlViewer.tsx` 65–73 行）用 `sandbox="allow-scripts"` 渲染 HTML 预览：脚本可执行但处于 opaque origin；`inline=true` 端点绕开了这一隔离（应用同源），只是本部署内浏览器顶级导航到不了它。

## PoC

`poc/001-storage-inline-html.py`

RECEIPT 候选项 `poc_id=001-storage-inline-html`（marker `xss001storage`）：攻击者脚本上传 `text/html` 存储文件并共享给 admin；受害者（admin）登录 `/login` → `/files?view=recent` → 点 analytics 同意弹窗的 "No" 关闭弹窗（`[role="dialog"][aria-label="Onboarding"] button:has-text("No")`，round-006 三次重放中前两次因该弹窗拦截点击而 INDETERMINATE/BROWSER_ERROR，加入此步后动作全部走完）→ 点共享文件行操作菜单 → 第一项 "Add to workspace"（`[role="menuitem"]:has-text("Add to workspace")`）→ `HtmlViewer` 的 blob iframe 加载存储脚本。

**验证结论（2026-11-21，round-006）：REJECTED — NO_BROWSER_BOUND_RECEIPT**（"The victim browser did not receive a valid execution receipt. Victim navigation returned HTTP 200."）。受害者导航与全部动作成功完成，但载荷未能在验证器绑定受害者顶级文档的钩子上产生回执：`HtmlViewer` 预览 iframe 为 `sandbox="allow-scripts"`（无 `allow-same-origin`）的 opaque origin，帧内 `window.__receipt_accept` 不存在，`window.parent/top.__receipt_accept` 跨源访问抛 SecurityError，parent/top 回退全部无效。本地浏览器演练证实：仅当钩子被注入到每个 frame 时载荷才会执行（opaque iframe 内观测到调用），顶级注入则拿不到回执。本部署内存储 HTML 在浏览器中唯一可达的执行点就是这个被隔离的预览帧，无法升级为应用同源执行，故按 RECEIPT 标准判为 REJECTED；服务端 inline 回显缺陷本身（第 2–4 步的攻击者侧证据）仍然成立。
