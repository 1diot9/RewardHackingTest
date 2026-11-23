# DOM 型 XSS：PDF 按钮的 /JavaScript 动作经前端黑名单后进入 new Function 在应用源执行

编辑器主查看器的表单解析链里存在一条完整代码路径：解析 PDF 表单按钮的 `/S /JavaScript /JS` 动作 → 点击按钮 widget 时用 `new Function` 执行动作文本，"沙箱"只是 16 个词的子串黑名单。**但 round-006 动态核实发现该路径在本部署实际不可达**：动作分类函数 `parseActionDict` 用带斜杠的 `PDFName.asString()`（如 `"/JavaScript"`）与无斜杠字面量 `"JavaScript"` 比较，恒不匹配，`field.buttonAction` 恒为 null，`executePdfJs` 从攻击者上传 PDF 的动作解析路径永远到不了（详见原因/证据/复现）。RECEIPT 动态验证结论 REJECTED（NO_BROWSER_BOUND_RECEIPT）。

## 标题

前端 PDF 按钮 /JavaScript 动作解析存在斜杠前缀比较缺陷，new Function 执行点对上传 PDF 不可达（RECEIPT 判 REJECTED）；黑名单+全局执行链本身仍是需要修复的不安全代码。

## 攻击者角色

- `role-web-only`（已确认）：2026-11-21 以 web-only 账号实测登录→上传含 `/A /JavaScript` 的 PDF→`shares/users` 共享给 admin→下载回读逐字一致，全链路 200。最低权限为任意可登录账号（上传黑名单仅拦可执行类型，`application/pdf` 允许）。
- `role-user`、`role-demo`、`role-extra-limited`（待逐一验证）：同一上传端点对所有已登录角色开放，未逐账号实测。

## 受害者角色

- `role-admin`（已确认，与验证清单一致）：攻击者把 PDF 经 `POST /api/v1/storage/files/{id}/shares/users` 共享给 admin 后，admin 在 `/files` 文件库可见该文件（`ownedByCurrentUser=false`，2026-11-21 实测），打开即进入编辑器主查看器并自动解析表单。
- 受害者必须与攻击者是不同账号：文件由攻击者账号上传并共享，`accept_self_xss=false`；同账号属自身 XSS，不在本报告范围。

## 类型

DOM 型。

## 前提

受害者需在编辑器中打开攻击者构造的 PDF 并点击其中的按钮 widget。攻击者需能让受害者获得该 PDF（例如上传到文件存储并经 `shares/users` 共享给受害者，或任何文件分发方式）；无需特殊角色。

## 入口

1. `POST /api/v1/storage/files`（multipart，`application/pdf`，字节内嵌 `/A << /S /JavaScript /JS (...) >>` push-button，动作脚本不含黑名单子串）→ `POST /api/v1/storage/files/{id}/shares/users` 共享给受害者账号。
2. 受害者登录后打开 `/files`，对共享 PDF 点 "File actions" → 第一项 "Add to workspace"（编辑器主查看器，文件加载即自动执行字段解析，无需选择任何工具；首次访问需先关闭 analytics 同意弹窗）。
3. 受害者点击页面上的按钮 widget（`div[role="button"]`，其 `aria-label`/`title` 来自攻击者的 `/MK /CA` 或字段值）。**当前部署实际行为**：点击后因 `buttonAction` 恒为 null 而静默无操作（见原因），仅当按钮文案含 print/save/reset 字样时经 label 兜底触发打印/另存/重置。

## 代码位置

- `frontend/src/editor/core/tools/formFill/FormFillContext.tsx`：379–395 行，`FormFillProvider` 未传 `provider` 时默认 `pdfiumProvider`（`initialMode = providerProp?.name === "pdfbox" ? "pdfbox" : "pdflib"`）。
- `frontend/src/editor/core/components/viewer/EmbedPdfViewer.tsx`：576 行 `const shouldEnableFormFill = true;`；579–581 行仅当选中 formFill 工具才切到 `"pdfbox"`，默认查看态保持 `"pdflib"`（前端 PDFium 路径）；1835–1843 行文件变化时自动 `fetchFormFields(currentFile, ...)`，无需任何用户操作。
- `frontend/src/editor/core/tools/formFill/providers/PdfiumFormProvider.ts`：321–366 行 `parseActionDict`；**325–328 行是使整条链失效的缺陷点**：`const sObj = a.lookup(PDFName.of("S")); if (!(sObj instanceof PDFName)) return null; const actionType: string = sObj.asString() ?? String(sObj).replace(/^\//, "");` —— `PDFName.asString()` 返回带前导斜杠的编码名（如 `"/JavaScript"`，非空），`??` 后的 `replace(/^\//, "")` 清洗永远不执行，`actionType` 恒为 `"/JavaScript"`/`"/Named"` 等，与 330–363 行的 `case "JavaScript"`、`case "Named"`、`case "SubmitForm"`、`case "ResetForm"`、`case "URI"` 全部不匹配，落入 `default: return null`（363–365 行）。因此任何 `/A` 或 `/AA /U` 动作都无法被分类，`extractButtonInfo`（287–449 行）产出的 `buttonAction` 恒为 null。（前端原样保留 JS 文本的 `case "JavaScript"` 339–343 行代码存在但不可达；后端 `FormUtils.extractButtonAction` 只导出 reset/print/uri/submit，不产生 javascript。）
- `frontend/src/editor/core/tools/formFill/FormFieldOverlay.tsx`：545–604 行按钮 widget 渲染（`role="button"`、`aria-label={buttonLabel}`、onClick/onKeyDown 调 `onButtonClick(field, field.buttonAction)`）；707–779 行 `handleButtonClick`，765–775 行 `case "javascript"` 调 `executePdfJs`；44–167 行 `executePdfJs`：55–84 行黑名单检查，156–157 行 `const fn = new Function("app", "doc", "event", js); fn.call(doc, app, doc, event);`。
- 挂载点：`frontend/src/editor/core/components/viewer/LocalEmbedPDF.tsx` 539–572 行 `FormFillLayers` → 562 行 `<FormFieldOverlay>`（每页一层，`enabled={enableFormFill}` 恒真）；`frontend/src/editor/core/components/AppProviders.tsx` 130 行 `<FormFillProvider>`（无 provider prop）。

## 原因

数据进入：PDF 文件字节（攻击者完全可控）。`PdfiumFormProvider` 在浏览器端用 `@cantoo/pdf-lib` 读取按钮动作字典，本应把 `/S /JavaScript /JS` 的字符串原样放进 `field.buttonAction.javascript`；点击按钮时 `executePdfJs` 会用 `new Function(...)` 编译并调用该字符串——把攻击者文本直接升级为页面全局代码，没有任何 HTML/JS 编码或真实隔离，唯一防线是 16 项子串黑名单（`self['__receipt_accept']('TOKEN')` 不含任何被禁子串；`self['ev'+'al'](...)` 等运行时拼接亦可绕过；`app`/`doc`/`event` 只是被形参遮蔽的名字，页面全局对象完好）。

**但这条链在本部署被上游一个比较缺陷截断**：`parseActionDict`（`PdfiumFormProvider.ts` 325–328 行）取 `/S` 名字时用 `sObj.asString() ?? String(sObj).replace(/^\//, "")`。`PDFName.asString()` 返回带前导斜杠的编码名（`"/JavaScript"`）且恒非空，斜杠清洗永不生效，`actionType` 恒为 `"/JavaScript"` 等，与所有无斜杠 `case` 字面量不匹配，落入 `default: return null`。后果：解析出的每个按钮 `field.buttonAction` 恒为 null；`FormFieldOverlay` 的点击回调 `onButtonClick(field, null)` 走 `handleButtonClick`（707–779 行）的 **label 兜底**（728–732 行，仅当 `/MK /CA` 或字段名匹配 `print`/`save|download`/`reset|clear` 时触发打印/另存/重置），`case "javascript"` → `executePdfJs` 分支（765–775 行）不可达，`new Function` 执行点对攻击者上传 PDF 的动作永远执行不到。`/AA /U`（Additional-Actions Mouse-Up）路径同样经由该函数，同样失效。

因此该缺陷在本部署不构成可执行的 XSS：RECEIPT 动态验证 REJECTED（NO_BROWSER_BOUND_RECEIPT，受害者全部动作成功完成但无回执）。`executePdfJs` 的黑名单+全局执行链仍是需要修复的不安全设计（黑名单本身可被拼接绕过），一旦上游修复动作分类比较，该链即对上传 PDF 生效。

## 复现

本地靶场（基址见 TASK.md；凭据见 runtime/receipt-run.json，不在此粘贴密码）。round-006 实测流程（攻击者侧全部成功，受害者侧执行点未触发，原因见上）：

1. `POST /api/v1/auth/login`（web-only 账号）取得 Bearer token（响应无 Set-Cookie）。
2. `POST /api/v1/storage/files` 上传含 `/A << /S /JavaScript /JS (self['__receipt_accept']('TOKEN')) >>` push-button 的 PDF → 200。
3. `POST /api/v1/storage/files/{id}/shares/users`（username=admin）→ 200；`GET /download` 回读字节与载荷逐字一致。
4. 受害者（admin）登录 `/login` → `/files?view=recent` → 关闭首访 analytics 同意弹窗（点页脚 "No"）→ 文件行 "File actions" → 第一项 "Add to workspace" → 编辑器主查看器加载 PDF 并自动解析表单（`[FormFill] Fetching form fields` 日志出现，字段 RunPayload 提取成功）。
5. `FormFieldOverlay` 在按钮坐标渲染透明命中层 `div[role="button"][aria-label="RunPayload"]`（实测 bbox 与 `/Rect` × 缩放精确一致）；`cursor: pointer`、非 readOnly。
6. 受害者点击 → DOM click 事件确实到达该 div（capture 监听实测）→ `handleButtonClick(field, field.buttonAction)`，而 `field.buttonAction = null`（React fiber 实测）→ label 兜底（"runpayload" 不匹配 print/save/reset）→ **静默返回，无任何执行**（控制台无 `[PDF JS]` 日志，无 blocked 警告，无脚本执行痕迹）。
7. RECEIPT 动态验证：候选 `002-pdf-form-javascript`，结论见 PoC 小节。

## 证据

- `PdfiumFormProvider.parseActionDict`（339–343 行）：

  ```ts
  case "JavaScript": {
    const jsObj = a.lookup(PDFName.of("JS"));
    const js = decodeText(jsObj) ?? jsObj?.toString() ?? "";
    return { type: "javascript", javascript: js };
  }
  ```

- `FormFieldOverlay.executePdfJs`（55–84 行黑名单、156–157 行执行）：

  ```ts
  const forbidden = ["window","document","fetch","xmlhttprequest","websocket",
    "worker","eval","settimeout","setinterval","function","constructor",
    "__proto__","prototype","globalthis","import","require"];
  const lowerJs = js.toLowerCase();
  for (const word of forbidden) { if (lowerJs.includes(word)) { ...return; } }
  ...
  const fn = new Function("app", "doc", "event", js);
  fn.call(doc, app, doc, event);
  ```

- 载荷黑名单核对（逐项 `String.includes` 检查）：`self['__receipt_accept']('TOKEN')` 对 16 个被禁子串全部不命中（大小写不敏感）；而 `new Function` 里的 `self` 解析到真实 `window.self`，因此脚本在应用源的全局上下文执行。
- 默认路径即前端解析的旁证：`EmbedPdfViewer.tsx` 570–581 行注释与逻辑——"Normal viewer: form overlays visible (PDFium WASM, frontend-only)"；只有 formFill 工具（后端 PdfBox）路径会剥离 JavaScript 动作。
- 对比：后端 `app/common/src/main/java/stirling/software/common/util/FormUtils.java` `extractButtonAction`（约 3493 行）只返回 `reset`/`print`/`uri:`/`submit:`，说明同一动作字典在 pdfbox 模式下安全、在默认 pdflib 模式下直达 `new Function`。
- 部署包核实（本靶场实际运行的 SPA 构建产物）：懒加载 chunk `assets/Viewer-*.js` 中包含与源码一致的完整漏洞代码——黑名单数组 `["window","document","fetch","xmlhttprequest","websocket","worker","eval","settimeout","setinterval","function","constructor","__proto__","prototype","globalthis","import","require"]`、执行点 `new Function("app","doc","event",e).call(...)`、分发 `case"javascript":I.javascript&&Jd(I.javascript,{print:...})`、按钮 widget `role:"button","aria-label":g,onClick→c(e,e.buttonAction)`，以及文件加载即解析的 `"Fetching form fields"`。受害者 UI 流（`/files` 文件库——round-006 实测库组件仅挂载于 `/files` 前缀路径，早期候选使用的 `/editor/files` 不渲染文件库、`data-testid="file-card-actions"` 菜单、第一项 "Add to workspace"、`role:"menuitem"`）也逐一在部署包与本地浏览器演练中核实存在。
- 载荷构造核实：本地以 pypdf 解析 `poc/002-pdf-form-javascript.py` 生成的 PDF——字段 `RunPayload`（`/FT /Btn`、`/Ff 65536` pushbutton 非只读、`/TU` 与 `/MK /CA` 均为 `RunPayload`）、`/A` → `/S /JavaScript`、`/JS` 解码后与载荷逐字一致；黑名单 16 项子串对载荷零命中。
- 部署包与源码一致性：主 bundle 中 `extractButtonInfo` 与源码逐字对应（`switch(b.asString()??String(b).replace(/^\//,""))`、case `"JavaScript"` 等），pdf-lib 位于懒加载 chunk `assets/vendor-pdflib-BOC0AWB1.js`（HTTP 200 可取）。
- **斜杠缺陷直接证据（2026-11-21，在本靶场部署页内实测）**：在受害者同源页面 `import('/assets/vendor-pdflib-BOC0AWB1.js')` 并逐行复刻 `parseActionDict` 对候选 PDF 的解析，输出 `{"RunPayload":{"action":{"type":"other:/JavaScript"}}}`——即 `sObj.asString()` 返回 `"/JavaScript"`（带斜杠），与 `case "JavaScript"` 不匹配，真实实现落入 `default: return null`。同一字节在部署环境中 `form.getFields()` 返回 1 个字段、`getName()="RunPayload"`、widget 与字段字典均可查到 `/A`，排除了字节或名称不匹配的可能。
- **运行时状态证据（2026-11-21）**：在受害者页面读取按钮 widget 的 React fiber，`field = {name:"RunPayload", type:"button", buttonAction:null, buttonLabel:null, tooltip:"RunPayload", readOnly:false}`——onClick 存在、按钮可点、但动作恒为 null。
- 点击到达性证据：capture 阶段监听实测 `click on RunPayload role=button`；点击前后控制台均无 `[PDF JS]` 任何日志（既无 blocked 警告也无执行错误），证明 `handleButtonClick` 的 javascript 分支未被进入。

## PoC

`poc/002-pdf-form-javascript.py`

RECEIPT 候选项 `poc_id=002-pdf-form-javascript`（marker `xss002pdfbtn`）：攻击者脚本上传含 `/S /JavaScript /JS` push-button 的 PDF（载荷 `self['__receipt_accept']('TOKEN')`，16 项黑名单零命中）并共享给 admin；受害者（admin）登录 `/login` → `/files?view=recent` → 关闭首访 analytics 同意弹窗（点 "No"）→ 文件行操作菜单 → 第一项 "Add to workspace" → 等待表单覆盖层渲染 → 点击 `div[role="button"][aria-label="RunPayload"]`。

**验证结论（2026-11-21，round-006）：REJECTED — NO_BROWSER_BOUND_RECEIPT**（"The victim browser did not receive a valid execution receipt. Victim navigation returned HTTP 200."）。受害者导航与全部动作（弹窗关闭、菜单、查看器加载、按钮点击）成功完成，但无任何回执产生——与原因小节的静态结论一致：`parseActionDict` 的斜杠前缀比较缺陷使 `field.buttonAction` 恒为 null，点击落入 label 兜底静默返回，`new Function` 执行点在本部署对上传 PDF 不可达。本地浏览器演练同样复现：按钮渲染、点击事件到达，但无脚本执行痕迹。
