# 001-markdown-mxss

## 标题

Markdown 文档解密渲染链（showdown→DOMPurify→innerHTML）mXSS 候选链的动态验证——**结论：未成立（RECEIPT 两次 REJECTED，负结果，予以保留）**。

## 攻击者角色

匿名（无需登录）。PrivateBin 允许任何匿名访问者通过 `POST /`（v=2 密文）创建文档；文档明文中的 `paste` 字段由创建者完全控制（客户端加密，服务端只校验 FormatV2 结构与密文熵，不解析明文）。本候选链中攻击者即文档创建者，对应威胁路径 creator-document-to-reader。

## 受害者角色

document-reader（匿名打开文档链接的读者）。受害者与攻击者不必是同一账号；按威胁路径 creator-document-to-reader 要求两者独立。

## 类型

存储型（载荷存于文档密文，经服务端存储分发，在读者浏览器客户端解密后渲染）——候选类型；动态验证未观察到执行。

## 前提

无登录要求。实例配置（runtime/conf/conf.php）允许匿名创建（traffic.limit=0），讨论未开启也可触发；渲染取决于文档自身 adata[1]=markdown。

## 入口

- 攻击者：`POST /`，application/json，body 为 `{"v":2,"adata":[spec,"markdown",0,0],"meta":{"expire":"1week"},"ct":...}`（spec=[iv_b64,salt_b64,10001,256,128,"aes","gcm","none"]）。
- 受害者：`GET /?dd5f50d3d56ba406#<base58key>&<receipt_token>`（HTML 页面，客户端取回密文并解密渲染）。

## 代码位置

- `js/privatebin.js` 2623-2649（`PasteViewer.parsePaste` markdown 分支：`plainText.innerHTML = DOMPurify.sanitize(converter.makeHtml(text), purifyHtmlConfig)`）。
- `js/privatebin.js` 57-103（`purifyHtmlConfig` 等 DOMPurify 配置常量：`FORBID_ATTR: ['id','class','style']`、URI 白名单 `(f|ht)tps?|mailto|magnet`）。
- `js/showdown-2.1.0.js`（markdown→HTML 转换发生在 DOMPurify 之前）。
- `js/privatebin.js` 1271（加密侧 `cryptoSettings(JSON.stringify(adata), spec)`）与 1296-1344（解密侧：AAD=`JSON.stringify(data[1])` 即完整 adata 数组、spec[0]/spec[1] atob 后按原始字节参与 PBKDF2 与 IV、iterations 取 spec[2] 原值）。
- `js/privatebin.js` 1530-1559（`Model.getPasteKey`：截去 key 之后 `&` 内容，base58 解码后 padStart(32)）。
- `js/privatebin.js` 6150-6167（`Controller.showPaste`：普通链接无 `#-` 前缀时自动 `PasteDecrypter.run()`，无需交互）。
- `lib/FormatV2.php` 131（服务端要求 iterations>10000；客户端 `deriveKey` 直接使用 spec[2]，无下限）。
- `lib/Controller.php` `_create`/`_read`（服务端仅验证 FormatV2 结构、strict-base64、密文熵，不解析明文）。

## 原因

攻击者完全控制的 `paste` 明文是整条渲染链上唯一未经服务端编码的 HTML 源：客户端解密后经 `showdown.makeHtml` 转 HTML，再经 `DOMPurify.sanitize(…, purifyHtmlConfig)` 写入 `innerHTML`。本候选验证 mXSS/解析器差异类向量（noscript/style/title/xmp/noembed/template 内容闭合混淆、MathML/SVG 命名空间混淆、`<script>`、`iframe srcdoc` 共 10 个探针）能否在 showdown 2.1.0 + DOMPurify 3.4.17 组合下存活。动态验证结果为否定：在密文已被浏览器正常解密渲染（加密链路与源码逐项核对一致、服务端密文回读逐字节一致、页面 HTTP 200 正常加载）的前提下，RECEIPT 两次均未收到任何探针的执行回执——即全部探针被 DOMPurify 中和，未产生脚本执行。该负结果与静态审计结论一致。

## 复现

1. 攻击者（匿名）以固定密钥/IV/salt 创建 markdown 格式文档（iterations=10001，满足服务端>10000 下限；AAD=完整 adata 数组的紧凑 JSON，与浏览器 WebCrypto 语义一致）：明文含 10 个探针，每个探针在真正执行时调用 `window.__receipt_accept(location.hash.substring(46))`；密文固定使文档 id 确定为 `dd5f50d3d56ba406`（= fnv1a64(base64(ct))，与线上服务器返回一致）。
2. 受害者（document-reader）打开 `/?dd5f50d3d56ba406#6R2oY5HPS1xc9DenZC7B8CZ1WacK5XQ6CPj4mjsbj3sN&{{receipt_token}}`（`Model.getPasteKey` 截去 key 之后 `&` 的内容，token 随 URL 到达页面供载荷读取；普通链接自动解密渲染，无需交互）。
3. RECEIPT 验证：候选项 `poc_id=001-markdown-mxss`（`poc/001-markdown-mxss.py`，`findings/001-markdown-mxss.md`）。结论：**REJECTED / NO_BROWSER_BOUND_RECEIPT（共两次：等待 4s 与 8s 各一次，均为「导航 HTTP 200 正常返回但未收到执行回执」）**。加密链路（key/AAD/salt/iterations/自动解密路径）已逐项与 `js/privatebin.js` 源码核对一致，故失败原因为探针未执行（被 DOMPurify/CSP 防护链中和），而非解密失败或时间不足。候选链判定为不成立。

## 证据

- 动态（本机靶场）：`POST /` 返回 status=0 且 id 与本地 fnv1a64 计算一致（dd5f50d3d56ba406）；`GET /?dd5f50d3d56ba406`（Accept: application/json）回读 ct 与本地加密结果逐字节一致、adata 一致。
- 本地 PoC 脚本（纯 Python、仅依赖 poclib）独立重建相同密文（sha256/PBKDF2/AES-GCM 均与 stdlib 参考实现比对一致），幂等创建/回读验证通过（exit 0）。
- RECEIPT 动态验证：两次 REJECTED（`NO_BROWSER_BOUND_RECEIPT`，victim navigation HTTP 200），等待时间 4000ms/8000ms，均未收到 `window.__receipt_accept` 回执。
- 源码链（已核对）：`PasteDecrypter.decryptPaste`（privatebin.js 5591-5624）→ `PasteViewer.parsePaste`（2623-2649）markdown 分支 `innerHTML = DOMPurify.sanitize(converter.makeHtml(text), purifyHtmlConfig)`；解密路径 1296-1344 与 1530-1559、6150-6167 均与 PoC 加密参数一致。
- 结论证据：动态验证否定了本候选链在本部署（DOMPurify 3.4.17 + 严格 CSP：`default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; sandbox allow-same-origin allow-scripts …`）下的可利用性。

## PoC

`poc/001-markdown-mxss.py`（经 submit_poc 登记生成，RECEIPT 候选项 `poc_id=001-markdown-mxss`）。验证结论：**REJECTED（NO_BROWSER_BOUND_RECEIPT，两次）**——未观察到 XSS 执行证据，候选链不成立；本报告按负结果保留。
