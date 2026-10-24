# 功能审查修正设计

## 目标与证据边界

修正普通 Surge wildcard 提前归约、regexp2 conditional 与字符类校验、SUBNET bare BSSID、native NOT 包装空格、native `@@` 输入及 QX 非 ASCII comparison 八项已确认问题，保持公开转换接口、现有目标能力和严格生成依赖检查。

初始代码提交为 `00d20710af4ad62805ad63c609c4796711058de8`，tree 为 `b2d7894c9880471dc8b9e3922ba44d88e6c07f27`。该提交的完整 145 文件 Git archive 已在 Debian GNU/Linux 13、Python 3.13.5 的原生 `/tmp` 执行 1503 tests，结果为 0 failures、0 errors、10 个既有 Windows-only skips，耗时 1221.255 秒。该记录只证明基线状态；组件、最终集成树和实际 Ubuntu Actions 均须另行验收。

R1-R8 均已有公开接口复现和独立双视角复核，八项纳入确定修正范围。30 份历史文档和 38 份测试的补查已完成，未确认额外缺陷；六领域补终报仍须在实施前核对覆盖收据，文档提交不依赖该收据。若终报确认额外实际问题，精确更新受影响要求及所有权后实施；全部覆盖终报收齐前不声明全面审查结束。

已完成复核中，native mixed-format shortcut 的整体禁用建议不采用。R7 的产品依据为 `docs/superpowers/specs/2026-10-11-functional-audit-design.md` U5D2 明确规定 native YAML 的 `@@` 输入拒绝；`tests/test_functional_audit_dns.py` 现有用例只覆盖 `@@DOMAIN`，未覆盖解码后合法 ABP 形状。当前代码和 hosts 回归同时要求保留其他 mixed-format 输入。

## 范围与接口

| owner | 生产修改范围 | 独立回归文件 |
| --- | --- | --- |
| A：R1、R8 | `rules.py` 的 `normalize` wildcard／suffix 与 keyword 归约、`_domain_comparison_value`、`exclude_covered` 的 QX 跨值覆盖 | `tests/test_wildcard_suffix_normalization_regressions.py`、`tests/test_qx_unicode_comparison_regressions.py`；精确调整 `tests/test_rules.py` 两处旧 wildcard 归约断言 |
| B：R2、R3、R4 | `rules.py` 的 `_valid_regex` conditional 与 class 状态／probe，确需时同一 owner 修改捕获预扫描或 deep 校验 | `tests/test_regexp2_conditional_regressions.py`、`tests/test_regexp2_completed_range_regressions.py` |
| C：R5、R6、R7 | `rules.py` 的 `_valid_simple` SUBNET 分支、`_logical_children` native 分支、`parse` 解码后 native `@@` 判定 | `tests/test_subnet_legacy_regressions.py`、`tests/test_native_not_space_regressions.py`、`tests/test_native_allow_regressions.py` |

A、B、C 在实施前核对覆盖收据后，从共同已提交文档 base 的独立 worktree 并行工作。A 连续完成 R1 和 R8，B 连续完成 conditional 和 class，不并发修改同一 `_valid_regex` 的初始化、group 状态及收尾验证。各组的每个行为均完成测试、修正、审查和提交后再进入下一项。只有 A 修改已有 `tests/test_rules.py` 的相关断言，其他新增测试不共享写入文件；发现实际修改范围重叠须调整所有权后继续。

`Rule` 七字段、公开 `parse`／`parse_whitelist`／`normalize`／`exclude_covered`／`render`／`generate`／`publish` 的签名、返回形状及导出不变。六个 `formats.FILES` 文件名、配置、依赖、`static/` 和受控生产产物不变。不添加框架、Unicode 表、provenance 字段、目标类型或客户端配置。

## Requirements

### R1. 归约保留普通 wildcard 已有的 Mihomo 投影

同组 `DOMAIN-SUFFIX,example.com` 与普通 Surge `DOMAIN-WILDCARD,*.example.com` 经 `normalize` 后，必须保留后者仍需生成的 Mihomo regex。已有投影为 `DOMAIN-REGEX,^.*\.example\.com\.?$`；它可匹配全小写 `ads.example.com.`，原生 suffix 无法替代该范围。`example.com.` 不作为此例见证，因为该 wildcard 本身不匹配 apex。

依据为 `normalize` 当前按固定尾段直接删除 wildcard 的分支、`formats._domain_value` 已有可选根点转换，以及固定 [Mihomo suffix matcher](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/rules/common/domain_suffix.go)和 [regex matcher](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/rules/common/domain_regex.go)。匹配差别由固定源码推导，未运行客户端。

- 只保留实际仍需要独立目标投影的普通 Surge wildcard。native／QX 的原安全归约、无法生成该投影时的安全归约、exact／suffix／keyword 与 CIDR 归约保持。
- suffix 继续生成原生 `DOMAIN-SUFFIX`，不改写 payload 或批量转换 regex，不处理已知 suffix 大小写差别。
- 重复、逆序、一次性 iterable、allow、options、literal_process、native_fields 和 domain_source 的 identity 分组保持。
- 来源层外部 suffix white 的原覆盖与目标层实际 matcher 过滤分别验证，不把正常 whitelist 删除改成全面保留。公开 allow 和 raw／generated white 继续按各自入口处理。
- 普通 source、同轮生成 source／white 和已发布非空 disk-only 依赖，均按实际 bytes 重新读取。Mihomo raw regex 重导入不恢复为 Surge wildcard，其他目标按现有类型能力计数。

完成条件：最小 source 的公开 parse -> normalize -> render 和真实 generate／publish 保留必要 regex，六格式正文及 diagnostics 符合各目标能力，原安全归约继续生效。

### R2. expression conditional 的直接 options 校验

`DOMAIN-REGEX`、`PROCESS-NAME-REGEX`、`PROCESS-PATH-REGEX` 遵循 regexp2 `v1.12.0`。`^(?(?=ads)(?i)ads|other)$` 等 expression conditional 的直接子层 inline options 必须拒绝，保留合法邻行及物理行号 warning。

固定 [Mihomo `88dcbf7f1614a67c3b36b848ee3592dfa92ada36` go.mod](https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/go.mod)和 [Mihomo `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8` go.mod](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/go.mod)均使用该版本，对应 regexp2 commit `3d5df45b703801b3fe51eb3f5c0dd302e8b0d676`。[parser.go conditional 分类](https://github.com/dlclark/regexp2/blob/3d5df45b703801b3fe51eb3f5c0dd302e8b0d676/syntax/parser.go#L984-L1035)建立 `ntTestgroup`／`ntTestref`；[options guard](https://github.com/dlclark/regexp2/blob/3d5df45b703801b3fe51eb3f5c0dd302e8b0d676/syntax/parser.go#L1081-L1110)禁止当前父组为 `ntTestgroup` 时消费 options。

- condition、then、else 的直接子层均按真实 group 类型校验，含 scoped／global、启用／关闭 options，以及分支已有 literal 后的 options。
- numeric／named reference 条件须依据完整 capture 集合分类，包含 forward reference。已定义引用的 `ntTestref` 直接 options 合法；未定义词语条件按 expression condition 处理，不创建 capture slot。未定义或非法 numeric 引用仍拒绝。
- `^(a)(?(1)(?i)ads|other)$`、`^(?(?=ads)(?:(?i)ads)|other)$` 和 lookaround／普通嵌套组内部的合法 options 保留。不能一律禁止 conditional 内 flags。
- 保留 capture 编号／名称、backreference、显式捕获模式、x-mode、comment、分支数量及非法 header 的既有边界。

完成条件：三种 regexp2 kind 的 scalar、logical、white、no_resolve 重验及深层路径一致拒绝非法式，合法 matcher 原文和既有目标支持保持。

### R3. expression condition 接受合法 noncapture／atomic header

共享 `_valid_regex` 必须接受 `^(?(?:ads)ads|other)$` 与 `^(?(?>ads)ads|other)$`。读取 condition 时消费完整 header，保留原 matcher，不把 `?:`／`?>` 残留到 Python validation probe。

[固定 parser.go 的 group header](https://github.com/dlclark/regexp2/blob/3d5df45b703801b3fe51eb3f5c0dd302e8b0d676/syntax/parser.go#L852-L864)明确支持 noncapture／atomic；[condition 子节点](https://github.com/dlclark/regexp2/blob/3d5df45b703801b3fe51eb3f5c0dd302e8b0d676/syntax/parser.go#L2137-L2144)与 [writer.go 分支编译](https://github.com/dlclark/regexp2/blob/3d5df45b703801b3fe51eb3f5c0dd302e8b0d676/syntax/writer.go#L216-L240)提供其 expression condition 语义依据。

- condition 内部 alternation 不计入外层 then／else 数量；外层第三分支、condition 直接 comment／named capture 和非法未闭合结构继续拒绝。
- 普通组 condition、四种 lookaround、嵌套 conditional 和 R2 的 options 层级规则共用一致的 group 状态。
- 三种 regexp2 kind、ordinary quoted／unquoted 与 native 两种 header／三种标量、AND／OR／NOT、600／1000 层均保留同一合法性和原文。
- 新接受的 conditional 不因此取得 Surge／QX／DNS 支持。DNS 仍须独立完整结构证书，`URL-REGEX` 保持原 Python 验证。

完成条件：两个最小正例经 parse、域名 white、实际 YAML source／white 同轮及磁盘回读保留；R2 的负例和既有 group／capture 行为不回归。

### R4. completed class range 终点只消费一次

`_valid_regex` 在完成 literal range 后，不得把终点继续当作下一 range 的起点。`^[a-z-\d]$` 合法，`^[a-z--\d]$` 非法；`\p`／`\P`、negation 和 escaped endpoint 的同根情形采用一致状态。

[regexp2 `scanCharSet`](https://github.com/dlclark/regexp2/blob/3d5df45b703801b3fe51eb3f5c0dd302e8b0d676/syntax/parser.go#L1441-L1631)在完成 range 的同一轮跳过新 range-start 分支。后续单个 raw hyphen 可以为 literal，两个 raw hyphen 可以建立新的 pending range；class escape 不能完成 pending literal range。

- raw endpoint 与 `\e`、`\cX`、braced hex、固定宽度 `\xHH`／`\uHHHH`、octal、punctuation escape endpoint 一致消费；固定宽度 escape 的尾部数字不能再次成为 literal。
- pending range、completed range、独立 literal 的 scanner 状态和 Python probe 同步。保持 `\-` 独立加入集合且不结束已有 pending range 的既有 regexp2 行为，继续拒绝真正 literal-to-class range。
- 逐例检查合法／非法的单／双 hyphen、`\dDsSwW`、`\pP`、negation、反向范围、POSIX-looking token、subtraction 与 subtraction 最后出现限制。
- 三种 regexp2 kind、普通／native、logical、white、no_resolve 和 600／1000 层结果一致。原 Rule matcher 不改写，验证 probe 不进入产物。
- DNS 的字符类结构证书、escaped-hyphen 目标限制及行预算独立保持；`URL-REGEX` 的 Python 校验不随此修正变化。不为手工构造的 scalar Rule 增加新的全量 renderer 校验。

完成条件：最小正例保留、负例拒绝并保留邻行，真实 source／white 和 YAML bytes 依赖一致，既有 regex／DNS 回归通过。

### R5. SUBNET 保留合法 legacy bare BSSID

`_valid_simple` 不得将合法 bare BSSID `aa:bb:cc:dd:ee:ff` 的首个冒号直接解释为未知 prefix。普通 Surge scalar 与 logical 的 SUBNET 校验须接受该输入，Surge full 和非 DOMAIN-SET split 保留原值。

[Surge SUBNET 官方定义](https://manual.nssurge.com/rules/protocol-and-network.html)的 Bare value (legacy) 规定，无 prefix 的非 wildcard 值可匹配 SSID、BSSID 或 router IP；[Subnet Group 官方说明](https://manual.nssurge.com/policy-groups/subnet.html)使用同一表达式定义。bare IPv6 文本可以沿用通用 IP 语法接受，但现有证据不承诺 Surge 实际匹配 IPv6 默认网关。

- 保留现有无冒号 bare SSID、IPv4、wildcard SSID 和 quoted whitespace 的支持。含冒号的 bare 兼容仅限明确合法 BSSID 或通用 IP 文本，未知任意 colon 字符串继续拒绝。
- 已识别的 `SSID`／`BSSID`／`ROUTER`／`TYPE`／`MCCMNC` prefix 校验及原大小写、取值、空值、markup 边界不放松，不把非法 prefixed 值回退成 bare。
- scalar 与 AND／OR／NOT 使用共享校验；quoted 普通字段和可回读 Surge bytes 保留原 matcher。SUBNET 不新增 Mihomo、QX、DNS 或外部 white 支持。

完成条件：bare BSSID 的 parse -> render -> parse 与真实 generate／publish 可用，非法 colon／prefix 给出行号 warning，其他目标保持局部 unsupported。

### R6. native NOT 按结构识别带 ASCII space 的包装

native `NOT,( (DOMAIN,a.test) )` 必须接受，并规范化为保留 child list 包装的 `NOT,((DOMAIN,a.test))`。共享 `_logical_children` 的 native 分支按真实外层和 child 范围判断，成功结果必须返回 `wrapped=True`。

固定 [Mihomo logic.go 的 NewNOT](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/rules/logic/logic.go#L37-L65)要求恰好一个 child；[范围扫描与解析](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/rules/logic/logic.go#L88-L172)不要求外层与 child 的左右括号相邻。

- 只修改 native 分支。普通 NOT 的单层兼容、普通 AND／OR 的最小 arity、普通空白行为保持。
- native `NOT,(DOMAIN,a.test)`、空 child、多个 child、额外包装、非法尾字段及无效叶子继续拒绝。native AND／OR 的既有空／单 child 语义保持。
- 保持字面括号平衡、native ASCII trim、regex 内部括号、ignored tail、方向和 no_resolve 语义；HTAB／非 ASCII 空白不按 ASCII space 擅自扩展。
- `_normalize_condition`、`_condition_kinds` 和 `formats._logical_value` 通过共享 helper 一致处理；嵌套、600／1000 层、三 purpose 与三 no_resolve 模式均完整保留或按目标整条跳过。

完成条件：public parse 和直接合法 native logical Rule 的 render 均保留必要包装，实际 YAML source 及非空磁盘依赖可回读，ordinary 行为和非法 native arity 不回归。

### R7. native item 解码后拒绝 `@@`

`payload:`／`rules:` 的 item 在 YAML 标量解码后，只要以 `@@` 开头就拒绝并给出原物理行 warning。`payload:\n  - "@@||safe.example.org^"` 不得产生 `allow=True` 的 Rule，不得删除合法路由或生成 DNS `@@`。

- 判定仅针对解码后的 native item，覆盖 single-quoted、double-quoted、支持的 plain 及 YAML escape 解码结果；以实际解码值为准。
- 保留 native 中已有 hosts、bare domain、bare CIDR、普通 block ABP 及 HOST alias 兼容，不整体关闭 mixed-format shortcut。
- 普通顶层 `@@||safe.example.org^`、公开 `Rule(allow=True)`、正常外部白名单和其目标局部能力保持。未知或 conditional ABP 的原诊断不因该修正放松。
- source 与 white 分别经过真实公开入口。只有非法 native item 的本地来源维持无可用规则错误／旧产物保护；带合法邻行时拒绝该 item 并继续生成。不得用人工 allow fixture 代替该负例。

完成条件：原最小错误被公开 parse／parse_whitelist 和真实 generate／publish 回归覆盖，邻行、行号、static 和旧文件保持，原 allow 与 mixed-format 正例通过。

### R8. QX 非 ASCII 比较保留未证明等价的 matcher

`domain_source='qx'` 的 `DOMAIN-KEYWORD`／`DOMAIN-WILDCARD` 不得用 Python full lowercase 合并不同的非 ASCII payload，或依据未证明的跨值包含关系删除规则。公开 `HOST-KEYWORD,ΟΣ`／`HOST-KEYWORD,ος`、literal 及含星号的 `HOST-WILDCARD` 均可读入，Python `lower()` 将两值合为 `ος`，已有 Mihomo native matcher 按 Go simple lowercase 分别使用 `οσ`／`ος`。`HOST-KEYWORD,İ`／`HOST-KEYWORD,i̇` 的第二个 payload 为 `i` 加 U+0307；Python 得到同 key，Go 分别得到 `i`／`i̇`。来源归约后，ASCII `RuleHost() == 'i.example'` 的第一条 keyword 命中可能消失。

依据为固定 [Mihomo keyword constructor 与匹配](https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/rules/common/domain_keyword.go#L19-L35)、[wildcard constructor 与匹配](https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/rules/common/domain_wildcard.go#L20-L35)、[Go `strings.ToLower`](https://github.com/golang/go/blob/c293dd49cbe25e1fe8d97d94a5cb618e7b6d831e/src/strings/strings.go#L727-L765)及 [Unicode 15 case table](https://github.com/golang/go/blob/c293dd49cbe25e1fe8d97d94a5cb618e7b6d831e/src/unicode/tables.go#L8753-L8759)。两份独立终报均确认公开 normalize、来源 white 和真实 generate／publish 的规则损失；客户端匹配差别由固定源码推导，未运行客户端。

- 共享 `_domain_comparison_value` 对 QX 非 ASCII keyword／wildcard 返回完整原文，包括其中的 ASCII 字符；Rule 原值不改写。ASCII-only QX、Mihomo 和普通 Surge 原比较保持，不增加 Unicode 表、依赖或闭源 QX 全域语义假设。
- `normalize` 同时保留不同非 ASCII QX payload 的 unique identity，并限制未证明的 keyword 跨值 contains 归约。`ΑΟΣ`／`ος` 的错误包含须消除；`Σ`／`ΟΣ` 的现有保留须保持。仅改 key 会使 `Σ` 成为 `ΟΣ` 的字面子串并新增误删，不能单独交付该修改。
- `exclude_covered` 同时限制涉及非 ASCII QX white 或 candidate 的跨值覆盖，包括 keyword 子串、literal／wildcard 匹配和 suffix／segment 推导。保留同来源、相同 kind、相同原 payload 的身份覆盖；其余未证明关系保留规则。ASCII-only 的现有完整覆盖及 Mihomo／Surge 行为保持，不把 QX 非 ASCII 一律当作可删除白名单。
- keyword／wildcard 两种 kind，Greek／dotted-I 同 key 与 proper substring，两方向 white、literal／含星号 wildcard、重复／逆序／一次性 iterable、allow／options／literal_process／native_fields／domain_source 分组均用公开入口验证。相同 payload、ASCII case 去重／包含、混合来源及既有 native Greek 行为作为对照。
- 真实 source、raw／generated white、同轮 `fin-qx.txt` source＋white 和 publish 后非空 disk-only 依赖保留原 matcher；`fin.yaml` 重导入按 Mihomo 来源处理。三 purpose × 三 no_resolve、六格式正文及 diagnostics、static 和旧文件保护保持；不据产物少行推断闭源 QX 或 DNS 全域运行时语义。

完成条件：公开 parse -> normalize／exclude_covered -> render 和真实 generate／publish 不再丢失上述已证明不同的 Mihomo matcher，共享 helper 与两个 caller 的限制同时生效，身份覆盖和已证明 ASCII 归约继续通过。

### R9. 公开接口与真实 bytes 联动

每项使用所属新增回归文件从公开入口验证，私有 helper 断言只补充定位。每个行为按最小 red -> 最小 green -> 相邻回归推进，不能先批量写完全部测试再实现。

| 入口 | 必须核查 |
| --- | --- |
| `Rule`、`parse` | 七字段、原 matcher、ordinary／native 标量差别、合法邻行、物理行号和非法负例 |
| `parse_whitelist` | 可用 kind 与来源边界；合法 DOMAIN-REGEX 白名单；native `@@` 不变成 white；非 white kind 不新增支持 |
| `normalize`、`exclude_covered` | 重复／逆序／一次性 iterable、identity、来源覆盖与实际目标覆盖；不推断任意 regex 等价 |
| `render` | 六格式完整正文、诊断、allow／外部 white、scalar／AND／OR／NOT、整条 unsupported；三 purpose × 三 no_resolve |
| `generate`、`publish` | 临时 root 的真实 UTF-8 bytes、同轮 source＋white、publish 后移除 parent 配置的非空 disk-only 依赖、旧文件及 static 保持 |
| `load_config`、`resolve_source`、CLI | 使用真实配置和路径解析，不改变依赖顺序、严格 body 检查、alias 和 `generate.py --root` |
| `update_readme_counts.update`、`update.update`、workflow | README 实际计数、现有本地 bare Git 发布测试及最终 Ubuntu test／update 与远端产物 |

fixture 覆盖 BOM／CRLF、ordinary 字段引用及 native 两种 header／三种单行标量。合法规则单独可发布与带邻行两类均核查；非法单项、目标全部 unsupported、合法全覆盖清空及冻结旧组分别核对，不用邻行掩盖单项发布失败。600／1000 层测试保持迭代路径和既有资源阈值，不提高 timeout、recursionlimit 或弱化断言。

### R10. 组件与最终 exact tree 的 Linux 验收

每个 owner 连续完成实现、相关回归、规格／功能／简化审查、修正、复审和英文提交，再以最终提交 head 的完整 Git archive 在 Debian 原生 `/tmp` 运行完整 suite 后交付。失败由原 owner 修正并重新提交、重验，不能把未完成步骤转交主会话。主会话仅合并无所有权冲突的已完成提交，集成树另行完整验收。

精确 archive 不叠加未提交文件，使用 Python `-I -B` 并显式加入可信 snapshot root；记录 commit、tree、解释器、Git 版本和全部受控路径 mode／blob／bytes／SHA-256。测试前后清单相同，discovery 包含新测试，无 failure／error，十个既有 skips 保持。最终文件数和测试数按实际记录，不固定为基线 145／1503。任何受控修改均需重新提交并验证新的 exact tree，Debian 记录不冒充实际 Ubuntu。

### R11. 固定生产输入与 42 产物验收

只读复用本轮 OS 临时目录 `rconvert-upstreams-20261024-fvi4elkn` 的 manifest 及 body；主工作目录 `.tmp/functional-audit-20261024-5bebe430/audit-plan.md` 记录其实际绝对路径。manifest SHA-256 为 `380f242fcfb7332d64ada54c9c7f73312632ba01593781dde9cf90ae24623d34`。56 URL、72 配置角色、18,131,971 bytes 的全部 body 大小和 SHA-256 已逐项核对。

已有审查记录包含一次内存 generate 的 42 文件观察，不代表最终 publish 或两轮稳定性验收；尚待终态的旧背景生成不得记为成功。最终验收在新的专用证据目录保存可信脚本、日志、清单和产物，沿 manifest 实际 body 路径读取，不改写旧抓取身份、不覆盖旧证据。脚本和下载数据分开，读取外部材料的 Python 使用 `-I`。

- 对初始 baseline 和最终代码使用同一批 bytes，保存每角色 parse／white warnings 与 diagnostics；不声称本轮重新抓取。
- 在隔离 root 使用真实 generate／publish 和 README update，同 input、同固定 header 时钟连续两轮，42 文件全部 bytes、diagnostics 稳定，无意外冻组，20 份 static 和输入不变。
- 逐文件检查 UTF-8 LF、header／count、去重、完整排序、目的／来源 no-resolve、Surge full／split、路由 parse 回读、DNS 每行含 LF 不超过 65,536 UTF-8 bytes、单文件不超过 100 MiB、README 数量。ADB 不用路由 parser 的 warning 判失败。
- 与同输入 baseline 逐规则解释增加／删除正文、count、bytes 和 diagnostics 差别，ADB Version 独立记录；不以固定总数或比例阈值代替解释。记录真实耗时，不新增性能目标。

### R12. 本地集成、授权发布与清理

各 owner 的 clean commit、最终 head 完整 Linux 结果和审查证据收齐后正常合并，不整文件选边，不 reset 或丢弃用户修改。主会话已核对原始用户请求明确要求合并到本地 main、推送 GitHub、触发自动构建 workflow，并检查远程规则更新及数量、多格式、文件大小。最终树满足 R9-R11 后按该原始请求完成发布，无需再次询问 push 授权；委派文本与本计划不新增授权。仅普通 push，不 force、不跳过 hooks 或 signing。

核对实际 Ubuntu Actions 对事件 SHA 的 `test` 和依赖它的 `update` 终态，记录 run／attempt／job／SHA 与 published／unchanged 结果。`superseded` 需要继续核对替代 SHA。读取实际远端提交的 42 产物及 README，检查 R11 的格式约束、static 保持和限定发布路径；远端实时上游变化与本地固定输入差异分开解释。

仅清理本次已合并、clean、无未合并提交且已无用途的 worktree 和本地分支，先退出任务 worktree 返回原目录。保留用户 `.claude/`、历史 worktree、其他任务分支及所有未保存内容；非阻塞清理失败逐路径记录。

## 完成标准与不处理项

R1-R8 均有公开接口、负例及真实 bytes 回归。三组 owner 在核对实施前覆盖收据后，从同一文档 base 连续完成各 slice，最终 head 与集成 exact tree 通过 R10，固定输入、42 产物和实际获授权远程发布分别满足 R11、R12。审查覆盖终报收齐后才声明全面审查结束。

不启动客户端，不执行外部源码或二进制，不做网络安全扫描或修复，不调查本机适配、多平台或已有 Windows 故障，不修已知 suffix 大小写，不扩展独立 publish 的未知非 canonical leaf API，不增加未确认性能优化。当前文档任务仅修改本规格和配套计划，不运行实现测试、不改源码／测试／README／配置／static／产物、不 push 或合并 main。
