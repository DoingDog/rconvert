# 路由字段可表达性修复规格

## 目标与范围

在基线 `4c1f29d55e47f939b96cf87a5284f947938191ed` 上修复四项已确认的路由字段问题及 DNS escaped-hyphen 字符类投影。公开规则保留原 matcher；目标不能保真表达时，仅跳过该目标并使用现有 unsupported 诊断。生成文件作为来源或白名单时，继续读取实际 bytes。

生产修改限于 `formats.py` 的 process、Mihomo scalar／logical、QX 投影、路由白名单入口和 DNS class 扫描／范围归约。测试新增于 `tests/test_routing_field_regressions.py` 和 `tests/test_dns_hyphen_regressions.py`；既有测试只精确更新 `tests/test_generate.py::SourceFieldContinuationGenerateTests.test_literal_user_agent_and_url_regex_survive_six_products_and_disk_dependency` 的相关 QX body、count 和 unsupported 预期，其余来源、模式、Surge 依赖、发布和旧文件检查保留。README 只更新相关支持说明，规则数量区保持。`rules.py`、`generate.py`、配置、static、生产产物和公共接口不变。

唯一交付目标为 GitHub Actions Ubuntu。允许使用已有 Debian WSL 执行 Linux Python 测试；不启动客户端、Go 程序或 listener，不增加依赖、配置、fallback、隐藏 Rule 缓存或输出格式。

## 公共接口与调用范围

| 公共接口 | 本次验证内容 | 不提供的证明 |
| --- | --- | --- |
| `Rule` | 直接构造的 literal process、native 字面 comma、allow 和 provenance 保持 | 非法任意 Rule 的来源合法性 |
| `parse`、`normalize` | 普通 quoted 与 native 字段区别、重复及输入顺序 | QX 闭源 matcher 的未知 Unicode 语义 |
| `parse_whitelist` | 真实外部白名单及已支持类型 | PROCESS、inbound、USER-AGENT 的新增白名单能力 |
| `render` | 六文件文本、标题数量、目标过滤及现有诊断 | 客户端执行 |
| `generate`、`publish` | 同轮与磁盘 source／white bytes、冻结及旧文件保护、输入不变 | 生产上游全量下载或远程 Actions 执行 |

受影响的共享调用为 `_process_value -> _mihomo_rule / _logical_value / render`、`_logical_value -> _mihomo_rule / render`、`_mihomo_rule -> render / _route_whitelist` 和 `_route_whitelist -> render`。QX 文本和 QX white 必须消费同一个字段可表达性判定。复用 `_delimiters` 的 native 扫描检查括号结构，不新增 parser。

无新增 fixtures 文件、配置键、exports 或公共返回值。集成 fixture 使用操作系统临时目录，由测试构造本地来源、白名单、配置和旧产物；fetch 回调仅用于断言不会访问网络，不模拟转换或客户端。

## R1. Mihomo nonregex process 的边缘 ASCII space

普通 `PROCESS-NAME` 先保留现有 strict hex regex 转换。其后仍原样输出的 `PROCESS-NAME`、`PROCESS-PATH`、`PROCESS-NAME-WILDCARD`、`PROCESS-PATH-WILDCARD`，有效 payload 首尾含 ASCII space 时，Mihomo 目标 unsupported。直接公共 `literal_process=True` 的 PROCESS-NAME 同样适用。

判定只能比较 `strip(' ')`，不修改公共 value。HTAB、NBSP、U+2000、U+2003、U+3000、内部 space、引号和反斜杠保持各自已有能力。原 native 输入按来源语法已经裁剪 ASCII space，正常输出保持。普通 PROCESS-NAME 的 hex 编码、显式 regex、原有 comma 保护和另外五种目标保持。

覆盖首部、尾部、两端、连续、纯 space；顶层、AND／OR／NOT、嵌套、同一逻辑多个错误叶子均检查。任何叶子 unsupported 时整条该目标逻辑跳过，只按顶层 operator 计一次，不计 whitelist-covered。三种 purpose 与三种 no_resolve 均验证。

## R2. Mihomo 非重连 payload 的字面 comma

Mihomo 的最终有效非 regex payload 含字面 comma 时 unsupported。顶层与单个 logical 叶子在 alias、UID／DSCP comma-to-slash、process 和 regex 转换之后检查。logical 父表达式和可重连的 DOMAIN-REGEX、PROCESS-NAME-REGEX、PROCESS-PATH-REGEX 不因结构 comma 被拒绝。

检查在重新追加 native ignored-tail 之前执行，保留 `native_fields` 和 ignored-tail 结构。普通 quoted IN-USER／IN-NAME／REMATCH-NAME、QX HOST-KEYWORD 的 literal comma，以及公共 native keyword／wildcard matcher 均覆盖。原 native `IN-NAME,foo,bar` 的有效 payload 已为 foo，保持正常。

`_route_whitelist` 仅使用同样可表达的 Mihomo 投影；不能把 unsupported 的 white 先加入来源覆盖索引再删除 blocker。保留现有已证明的来源覆盖和 regex 投影能力，不把 comma 删除、改成 slash、增加字段 escape 或改变公共 Rule。

回归保留三个名称类型的 slash-list 及已有 TrimSpace 语义、普通 PROCESS-NAME 的 hex regex、三种 regex comma 重连、UID／DSCP、正常邻居和 `tests/test_formats.py` 的 native ignored-tail 正例。顶层及整条 logical 的 unsupported 精确计数保持。

## R3. QX 字段序列化与回读

共享目标判定覆盖 QX 文本与 route whitelist matcher。现有 comma、控制字符、wildcard 方括号限制保持；以下值仅在 QX unsupported：

- DOMAIN-KEYWORD、native DOMAIN-WILDCARD、USER-AGENT 的起始字面单／双引号，包括未闭合和成对引号。
- 字段首尾会被普通字段读取裁剪的空白，包括 ASCII space、HTAB 和非 ASCII whitespace。
- USER-AGENT 的奇数个尾反斜杠。
- USER-AGENT 中空白后紧接 `#`、`;` 或 `//` 的 literal marker。

保留内部引号、内部空白、普通内部反斜杠、USER-AGENT 的偶数尾反斜杠、无空白前缀的 marker。HOST-KEYWORD 已有字面 backslash／marker 读取必须保留，包括一至三个尾反斜杠和空白后 marker。不发明 Surge、JSON 或 regex 字段编码，不裁剪或改写 matcher，不修改生成依赖的严格 bytes 校验。

QX 继续输出三字段 `LIST`，接口参数仍只在实际输出后记录 interface-option；unsupported 或合法覆盖的规则不计该诊断。逻辑规则仍按顶层 operator 一次 unsupported，不展开叶子。

真实集成覆盖三类 matcher、三种 purpose／no_resolve、同轮及 disk-only source 和 whitelist。white fixture 含健康邻居，避免空磁盘文件触发无关的严格输入校验。窄的 literal quote／空白 white 不得经生成依赖变宽后删除裸 keyword blocker。直接 public white／allow 与真实 parse_whitelist 分别检查。

native wildcard 输入形状闭合由另一任务处理；本任务保留已支持的 native `*`，不以禁用 wildcard 绕过回读问题。

## R4. Mihomo logical 的字面括号

每个输出的 nonregex logical 叶子在完成转换及恢复 native ignored-tail 后，使用现有 native delimiter scanner 检查完整括号平衡及所有前缀不得提前闭合。任一叶子失败时，该目标整条 logical unsupported。

普通 quoted IN-NAME／IN-USER／REMATCH-NAME、PROCESS-PATH／PROCESS-NAME-WILDCARD／PROCESS-PATH-WILDCARD 的单边括号均覆盖。强反例 `AND,((IN-NAME,"12(3"),(IN-USER,"45)6")),PROXY` 必须跳过，不能让两个叶子互相抵消；`12)3(` 即使总数平衡也必须跳过。不得仅检查整个表达式总数或以最终 parse 没有 warning 作为充分条件。

保留 balanced `12(3)`／`foo(bar)`、顶层合法 `foo(`、普通 PROCESS-NAME 已 hex 编码的括号、regex 既有保护和 native ignored-tail 帮助平衡结构的正例。AND／OR／NOT、嵌套、多错误叶子、IP 方向及 no-resolve 保持，诊断按原顶层类型计一次。

## R5. DNS escaped-hyphen 的来源 token 身份

固定 regexp2 `3d5df45b703801b3fe51eb3f5c0dd302e8b0d676` 的 `scanCharSet` 遇到来源 class 的 `\-` 时立即加入 singleton hyphen 并 continue；它不结束 pending range，也不作为紧随 raw `-` 的 range 起点。现有 DNS reducer 无法证明这些组合时，仅拒绝该条 DNS 投影。

在 `_dns_regex(..., encoded=False)` 扫描中记录 escaped hyphen 的位置；当 range 归约准备把它作为起点或终点时返回既有 `None`。`encoded=True` 扫描的是 Go 目标 regex，保持原有语义。不能整类禁止 `\-`，不能将其与 `\x{2D}` 同化，不修改来源 validator、公共 Rule 或其他目标。

四个基本反例为 `[!-\-9]x`、`[^!-\-9]x`、`[\--9]x`、`[^\--9]x`。对普通 ASCII hostname `0x.test`，固定来源真值依次为 true、false、false、true，修复前 DNS 依次为 false、true、true、false。来源真值依据固定源码，不执行客户端，不用 Python re 解释原始来源 regex。

覆盖普通 quoted 和 native YAML 两个来源、正／否定类、property 混合、中性／scoped 分组、重复 escaped hyphen，及 block、公共 allow、真实外部 whitelist 三个消费者。每个被拒绝的消费项精确增加一次 `fin-adb.txt:DOMAIN-REGEX`，没有残留正文；fin.yaml 保留原 matcher。真实 generate／publish、同轮及 disk fin.yaml source／white 均读取实际 bytes，输入和旧文件保护保持。

保留 `[-a]`、`[a-]`、`[\-a]`、`[a\-]`、`[\-a-c]`、`[--0]`、`[!-\x{2D}a]`、`[\x{2D}-a]` 及已证明 property 控制的现有支持。大小写、根点、Unicode 数据、量词／高度、compiled-size、65,536-byte 包括 LF／@@ 的预算不变。

## 诊断与发布验收

1. 六文件 header 仅统计实际正文，Surge 完整文件和拆分文件一致；顺序与重复输入不改变结果。
2. unsupported、目标 whitelist-covered、完整路由 whitelist-covered、interface-option 保持原有含义。完全 unsupported 不得计完整覆盖。
3. 有健康邻居时正常生成六文件，只移除不可表达目标；全目标无有效路由时沿用原冻结条件，旧六文件和输入 bytes 不变。
4. 实际 publish 写入临时 root；同轮依赖与非空磁盘依赖重新读取实际输出，无 warning 或 matcher 静默改变。
5. 每项独立完成失败测试、最小实现、相关回归、规格审查、简化和英文提交。最终执行完整 Linux unittest、diff 检查及范围核查，不能把 Windows skip 当 Ubuntu 验收。

## 已核查的依据与限制

固定 Mihomo `88dcbf7f1614a67c3b36b848ee3592dfa92ada36` 的 `rules/common/base.go` 使用字面 comma split 和 ASCII-space trim；`rules/common/process.go` 的 exact 为 EqualFold，wildcard 使用 ToLower 后的 byte matcher。三个 inbound constructor 使用 slash-list 和 TrimSpace。`rules/logic/logic.go` 对每个字面括号计数，不识别字段引用。以上结论来自已固定源码，未执行客户端。

固定 QX `af6fb594233ec4a3ec6d4ccb3601e9c36b75ea2d` 的官方样例只提供已知三字段格式，现有审计未取得这些特殊字段的官方编码依据。本修复只承诺目标局部 unsupported 和转换器依赖安全，不承诺未知闭源字段语义。

DNS 依据已固定 regexp2 的 `syntax/parser.go:1442-1631`、Mihomo `NewDomainRegex` 和 DNS 的 Go regexp 消费路径。来源推导及公开输出反例已由三个只读审查分别确认；不据此扩大未知 Unicode 范围支持。

不修改已排除的 Mihomo DOMAIN-SUFFIX 大小写、GEOIP,LAN、手工顶层 SRC-IP/CIDR；Go／Python 名称空白差异仍待独立确认。
