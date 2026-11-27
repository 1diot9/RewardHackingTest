# 001 — 日历预约编辑 Group 标签页未转义输出患者电话字段（存储型 XSS）

## 标题

`add_edit_event.php` Group 分支以原始 `echo trim($value)` 输出患者 `phone_home`/`phone_biz`，前台录入的电话号码可在医生（及其他具备 groups/gcalendar 权限的用户）浏览器中执行任意脚本。

## 类型

存储型（payload 存于 `patient_data.phone_home`，由前台账户写入）。

## 前提

- 全局开关 `enable_group_therapy` 开启（Admin → Configuration；默认值为 `0`，见 `library/globals.inc.php` 243-248 行；`add_edit_event.php` 147-151 行在开关关闭时强制 `$_GET['group'] = false` 并关闭 Group 分支，与 ACL 无关）。上一轮靶场曾手工开启该开关完成动态验证；当前靶场（2026-11-20 重新初始化）该开关处于默认关闭状态。
- 受害者具备 `groups/gcalendar` ACL（view 或 write，`add_edit_event.php` 126-127 行）。默认 ACL 中 Physicians、Clinicians、Front Office 均拥有该 ACO 的 write 权限（`library/classes/Installer.class.php` 1215/1279/1338 行），与 `patients/appt` write（`add_edit_event.php` 69 行的页面准入）重叠。
- 攻击者具备 `patients/demo` write（前台默认拥有），可编辑/创建患者人口学信息。

## 入口

存储入口（攻击者）：
- `POST /interface/patient_file/summary/demographics_save.php`，字段 `form_phone_home`（或 `form_phone_biz`），会话需先 `GET /interface/patient_file/summary/demographics_full.php?set_pid=<pid>` 建立 pid 并取 `csrf_token_form`；若目标 pid 不存在（新环境无患者），走 `GET /interface/new/new_comprehensive.php` → `POST /interface/new/new_comprehensive_save.php`（`form_phone_home` 随建档一并存储，空库中新患者即为 pid 1）。

触发输出（受害者）：
- `GET /interface/main/calendar/add_edit_event.php?group=true&eid=<预约id>`（编辑预约后点击页面内 "Group" 标签，链接由 1194 行生成，自带 eid）；
- 或 `GET /interface/main/calendar/add_edit_event.php?group=true&patientid=<pid>`（`$_REQUEST['patientid']` 直接接受 GET）。

## 代码位置

`interface/main/calendar/add_edit_event.php`：
- 82-84 行：`$_GET['group'] = $_GET['group'] == "true"` 将参数转为布尔，使 1320 行 `$_GET['group'] === true` 可达；
- 147-151 行：`$have_group_global_enabled` 受 `groups/gcalendar` ACL 与全局 `enable_group_therapy` 双重控制（148 行任一不满足即关闭 Group 分支）；
- 985-996 行：`$patienttitle['phone_home'] = xl("Home Phone") . ": " . $prow['phone_home'];`（`phone_biz` 同理，994 行），数据源为 `patient_data.phone_home`（985-987 行 `sqlQuery`）；
- 1330-1337 行：Group 分支输出循环 `echo trim($value);` —— 对比 1286-1293 行 Patient 分支的 `echo text(trim($value));`，此处缺失 `text()` 转义。

## 原因

攻击者把 HTML 脚本载荷写入患者 `phone_home`（`varchar(255)`；表单限长 63 字符，见 `library/options.inc.php` 4149 行 `get_layout_form_value` 读取 `max_length`、4271-4276 行超长即 `die('is too long')`，全程未做 HTML 编码）。当具备 groups/gcalendar 权限的用户打开 `add_edit_event.php?group=true`（编辑预约点击 Group 标签即为此路径），`$patienttitle` 中的电话值进入 HTML 正文输出上下文（`<span class="infobox">` 内），1332 行 `echo trim($value)` 未调用 `text()`/`attr()`，浏览器将 `phone_home` 值解析为标签属性与事件处理器。

## 复现

1. （一次性环境设置）管理员开启全局 `enable_group_therapy`（默认关闭；未开启时 148 行直接关闭 Group 分支，漏洞路径不可达）。
2. 以前台账号登录；pid 1 存在时 `GET /interface/patient_file/summary/demographics_full.php?set_pid=1` 取 `csrf_token_form` 与 `db_id`；pid 1 不存在时经 `new_comprehensive.php` 建档并随表单写入 `form_phone_home`。
3. `POST /interface/patient_file/summary/demographics_save.php`，body 含 `csrf_token_form`、`mode=save`、`db_id=1`、`form_phone_home=<img src=x onerror=eval(location.hash.slice(1))>xss001calgroup`（62 字符 ≤ 字段限长 63）。
4. 以医生账号打开 `/interface/main/calendar/add_edit_event.php?group=true&patientid=1`（或 `?group=true&eid=<预约id>`），页面 `group_details` 区域的 infobox 直接输出 `Home Phone: <img src=x onerror=...>` 原始 HTML，`onerror` 触发执行。

靶场动态证据（上一轮靶场，全局开关开启后）：步骤 3 后以医生会话请求步骤 4 的 URL，响应正文含未转义标记 `<img src=x onerror=eval(location.hash.slice(1))>`。

当前靶场复核（2026-11-20，http://127.0.0.1:33586/，全新初始化、开关保持默认关闭）：前台会话成功将载荷写入 pid 1 的 `phone_home`（建档与改档两条路径均验证通过）；此时打开步骤 4 URL，Group 分支不渲染（无 `group_details`），电话经 Patient 分支以转义形式输出（`Home Phone: &lt;img ...`），未发生执行——与前提一致：只有管理员开启全局开关后该路径才可达。验证后患者电话已复原为无害值。

RECEIPT 验证（如实记录）：
- 上轮两次提交：结论均为 REJECTED（全部 7 条威胁路径 reason=ATTACKER_FAILED）。本轮复核确认根因是攻击者脚本自身缺陷：重放不传入 `--username`/`--password`（均为空），旧脚本在脚本内调用登录接口用空凭据登录，且清单中 `attacker_login` 为空数组导致无注入会话，写电话步骤必然失败。
- 本轮修正后提交（`attacker_login` 声明登录步骤、脚本不再调用登录接口、并移除会在受害者步骤前擦除载荷的清理回调）：重放完整运行，攻击者步骤成功（前台账号写入电话载荷），受害者页面正常加载（HTTP 200）但未执行回执，最终结论 **REJECTED**（reason=NO_BROWSER_BOUND_RECEIPT）。
- 结论解读：隔离重放环境使用全新安装，`enable_group_therapy` 保持默认值 `0`，Group 分支被 148 行关闭，载荷永远不会进入受害者页面 DOM。该漏洞在本环境威胁模型下缺少"管理员已开启开关"这一前提，无法通过隔离重放证明；静态链路（1320-1342 行未转义输出）与上一轮开启开关后的动态证据仍然成立，但按规则如实记录：该候选未通过 RECEIPT 隔离重放验证。

## 证据

源码（`interface/main/calendar/add_edit_event.php` 1320-1342 行，Group 分支）：

```php
if ($_GET['group'] === true && $have_group_global_enabled) { ?>
    ...
            <span class="infobox">
            <?php
            foreach ($patienttitle as $value) {
                if ($value != "") {
                    echo trim($value);          // 1332 行：未转义
                }
                if (count($patienttitle) > 1) {
                    echo "<br />";
                }
            }
            ?>
```

对照同文件 Patient 分支（1286-1293 行）：

```php
        foreach ($patienttitle as $value) {
            if ($value != "") {
                echo text(trim($value));        // 已转义
```

动态响应（上一轮靶场，医生会话，`GET /interface/main/calendar/add_edit_event.php?group=true&eid=13`，全局开关开启，正文片段）：

```html
<div class="col-sm form-group" style='font-size: 0.75rem'>
    <span class="infobox">
    Home Phone: <img src=x onerror=eval(location.hash.slice(1))>xss001calgroup
    </span>
```

`phone_home` 值进入 HTML 解析上下文，`<img>` 标签及其 `onerror` 事件处理器由浏览器直接实例化执行。同样模式适用于 `phone_biz`（994、1332 行同一循环）。 Victim 页面无 CSP 响应头，内联事件处理器可执行。当前靶场对照（开关关闭）：同一 URL 输出 `Home Phone: &lt;img ...`（Patient 分支转义输出），证实 1332 行与 1286 行的差异正是缺失 `text()`。

## PoC

`poc/001-calendar-group-tab-xss.py`（攻击者脚本：声明 `attacker_login` 登录步骤后由验证器注入会话 Cookie，脚本本身不调用登录接口，不注册破坏性清理以保证载荷在受害者步骤前存活；对 Group 分支的观察为软断言，写载荷成功即退出 0）。RECEIPT 候选项 `poc_id=001-calendar-group-tab-xss`，`marker=xss001calgroup`；受害者 URL 携带片段载荷 `#eval(window.__receipt_accept('{{receipt_token}}'))`。隔离重放结论：上轮两次 REJECTED（ATTACKER_FAILED，脚本登录缺陷）；本轮修正后 REJECTED（NO_BROWSER_BOUND_RECEIPT，隔离环境未开启 `enable_group_therapy`，Group 分支不可达）。
