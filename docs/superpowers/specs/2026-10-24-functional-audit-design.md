# 功能审查修正设计

## 目标与证据边界

修正 R1-R8、R13-R18 的十四项已确认问题，包括规则归约与 regexp2 校验、SUBNET／native 解析、Unicode 比较与目标能力、quoted process 尾注释、native wildcard byte 覆盖、hosts ASCII 空白、合法 informational HTTP 响应及 ordinary／native Unicode 投影边界。保持公开转换接口、现有目标能力和严格生成依赖检查。

初始代码提交为 `00d20710af4ad62805ad63c609c4796711058de8`，tree 为 `b2d7894c9880471dc8b9e3922ba44d88e6c07f27`。该提交的完整 145 文件 Git archive 已在 Debian GNU/Linux 13、Python 3.13.5 的原生 `/tmp` 执行 1503 tests，结果为 0 failures、0 errors、10 个既有 Windows-only skips，耗时 1221.255 秒。该记录只证明基线状态；组件、最终集成树和实际 Ubuntu Actions 均须另行验收。

R1-R8、R13-R18 均已完成公开接口复现与独立复核；R8 的 equal-key／proper-substring DNS 输出完整性补充已按既有要求确认。覆盖闭合终报确认初始基线全部 145 个受控文件及生产源码行段均有阅读归属，包含 30 份历史文档、38 份测试、20 份 static、42 产物、35 项回读和 52 项 CI 测试等收据。阅读覆盖和基线测试已闭合，修复后的组件／集成、固定输入生成及远端验收仍须执行。主会话在最终集成前核对收据及独立结论；独立单元继续并行，尚未确认的候选不计入确定要求。

已完成复核中，native mixed-format shortcut 的整体禁用建议不采用。R7 的产品依据为 `docs/superpowers/specs/2026-10-11-functional-audit-design.md` U5D2 明确规定 native YAML 的 `@@` 输入拒绝；`tests/test_functional_audit_dns.py` 现有用例只覆盖 `@@DOMAIN`，未覆盖解码后合法 ABP 形状。当前代码和 hosts 回归同时要求保留其他 mixed-format 输入。

## 范围与接口

| owner | 生产修改范围 | 独立回归文件 |
| --- | --- | --- |
| A：R1、R8、R14、R17、R18 | `rules.py` 的已分配归约／覆盖和 `_surge_keyword_source_supported`；`formats._domain_value` 的 ordinary Unicode lowercase／native Surge 能力；复用共享 Go15 helper／case-variant 定义并同步 caller | `tests/test_wildcard_suffix_normalization_regressions.py`、`tests/test_qx_unicode_comparison_regressions.py`、`tests/test_native_wildcard_width_regressions.py`、`tests/test_surge_unicode_projection_regressions.py`、`tests/test_native_unicode_capability_regressions.py`；旧测试仅限下表 |
| B：R2、R3、R4 | `rules.py` 的 `_valid_regex` conditional 与 class 状态／probe，确需时同一 owner 修改捕获预扫描或 deep 校验 | `tests/test_regexp2_conditional_regressions.py`、`tests/test_regexp2_completed_range_regressions.py` |
| C：R5、R6、R7 | `rules.py` 的 `_valid_simple` SUBNET 分支、`_logical_children` native 分支、`parse` 解码后 native `@@` 判定；`formats._logical_value` 的 native NOT Surge 包装空白定向 hunk | `tests/test_subnet_legacy_regressions.py`、`tests/test_native_not_space_regressions.py`、`tests/test_native_allow_regressions.py` |
| D：R13 | `rules.py` 的 `_source_parts` 普通 process 分支，复用 `_literal_fields` | `tests/test_process_comment_regressions.py` |
| E：R15 | `rules.py` 的 hosts 注释后裁剪及 `host_parts` 分隔，复用既有 hostname validator | `tests/test_hosts_whitespace_regressions.py` |
| F：R16 | `generate.py` 的 `_HttpsOnlyRedirect`／`fetch_https` informational response 处理，复用标准库 HTTPResponse | `tests/test_informational_response_regressions.py` |

A、B、C 已从共同文档提交 `109ea30f83720178130a1db0c608937eaae86ef8` 的独立 worktree 并行实施，按各自确认范围吸收后续文档提交；D 从包含 R13 的文档提交独立实施，E 从包含 R15 的文档提交独立实施；E 的 hosts hunk 与 C 的 native `@@` hunk 分开，F 从包含 R16 的文档提交独立处理 generate 传输分支。A 连续完成 R1、R8、R14、R17、R18，B 连续完成 conditional 和 class，不并发修改同一 `_valid_regex` 的初始化、group 状态及收尾验证。每个行为完成测试、修正、审查和提交后再进入下一项，覆盖收据在最终集成前核对。A 的旧测试修改限于 R1 原两处 wildcard 期望及 R8／R18 下列已核实范围，其他 owner 只写独立新测试。除直接受已确认语义影响的期望外，ASCII／Surge／native／allow 对照、fixture、timeout 和资源条件不改；新增冲突先交主会话核实。

| A 可精确更新的旧测试 | 已确认修改边界 |
| --- | --- |
| `tests/test_keyword_normalization_performance.py` 的 `test_comparison_key_lengths_original_values_and_identity_groups_are_preserved` | 仅 QX `İ`／`xİ` pair 保留两条，按稳定排序为 `pair[::-1]`；Surge／Mihomo 期望保持 |
| `tests/test_rules.py` 的 `_check_complete_qx_literal_fields`、`test_qx_keyword_markers_preserve_complete_fields_and_whitelist_scope`、`test_keyword_whitelist_preserves_literal_range_allow_and_source_identity` | 仅非 ASCII QX white 不再跨值删除 longer；相同原文身份覆盖和其他来源／allow 保持 |
| `tests/test_rules.py` 的 `NativeWildcardWhitelistTests.test_coverage_preserves_source_flags_and_allow_rules`、`test_normalize_keeps_wildcard_predicates_and_source_groups` | 仅受 QX 非 ASCII candidate 保护影响的来源覆盖期望；保留 ASCII／Surge／Mihomo／flags／allow 对照 |
| `tests/test_functional_audit_coverage.py` 的 `NativeWildcardBoundaryAuditTests.test_native_short_wildcards_match_bytes_and_literal_brackets_without_cross_source_merging` | 仅原第 1187 行，`source in ('surge', 'qx')` 中 `DOMAIN,aé.example.org` 对 white `a?.example.org` 的期望改为 `[] if source == 'surge' else [blocker]`；其余 Surge／native 矩阵、fixture、资源条件及其他断言保持 |
| `tests/test_generate.py` 的 `NativeKeywordGenerateTests._qx_marker_products`、`_check_qx_keyword_marker_dependency`，及 white 调用测试 `test_qx_literal_whitelist_preserves_shorter_matcher_same_round_and_disk`、`test_qx_keyword_whitelist_keeps_short_keyword_same_round_and_disk_without_mock` | 同一原 fixture 下，仅更新非 ASCII QX 跨值保留所影响的六格式正文、count、diagnostics 与回读身份；不削弱 source／white、同轮／磁盘、旧产物保护断言 |

R18 另允许精确修改 `tests/test_generate.py` 的 `PublicGeneratedPipelineTests.expected`：只从 parent／child 的 `fin.txt`、`fin-surge.txt` 移除 native `DOMAIN-KEYWORD,ΟΣ` 正文，header 按实际数量计算；各组各增加对应两项 unsupported。YAML identity、QX、DNS Greek bytes、DOMAIN-SET、fixture 和 publish 断言保持。其他旧期望若实际受影响，先由主会话核查，不扩大授权。

`Rule` 七字段、公开 `parse`／`parse_whitelist`／`normalize`／`exclude_covered`／`render`／`generate`／`publish` 的签名、返回形状及导出不变。六个 `formats.FILES` 文件名、配置、依赖、`static/` 和受控生产产物不变。不添加框架、Unicode 表、provenance 字段、目标类型或客户端配置。

## Requirements

### R1. 归约保留普通 wildcard 已有的 Mihomo 投影

同组 `DOMAIN-SUFFIX,example.com` 与普通 Surge `DOMAIN-WILDCARD,*.example.com` 经 `normalize` 后，必须保留后者仍需生成的 Mihomo regex。已有投影为 `DOMAIN-REGEX,^.*\.example\.com\.?$`；它可匹配全小写 `ads.example.com.`，原生 suffix 无法替代该范围。`example.com.` 不作为此例见证，因为该 wildcard 本身不匹配 apex。

依据为 `normalize` 当前按固定尾段直接删除 wildcard 的分支、`formats._domain_value` 已有可选根点转换，以及固定 [Mihomo suffix matcher](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/rules/common/domain_suffix.go)和 [regex matcher](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/rules/common/domain_regex.go)。匹配差别由固定源码推导，未运行客户端。

- 只保留实际仍需要独立目标投影的普通 Surge wildcard。native／QX 的原安全归约、无法生成该投影时的安全归约、exact／suffix／keyword 与 CIDR 归约保持。
- R17 的 raw unique identity 与 suffix candidate 分开处理；candidate 复用既有 `_domain_comparison_value`，不改原 Rule、全局 comparison、普通 source white、QX 非 ASCII guard 或 projection guards。同组 suffix 对 `[İ]`／`[İ-J]`／`[ſ]`／`[ı]` 加大写、混合大小写或小写 tail 的原安全归约保持；`[İ].EXAMPLE.COM` 的六格式正文、count 和 diagnostics 须等于 suffix-only 对照。该已确认回归仅涉及冗余输出和 unsupported diagnostics，未证明客户端漏匹配，不增加需求编号。
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

- `_logical_children` 只修改 native 分支。普通 NOT 的单层兼容、普通 AND／OR 的最小 arity、普通空白行为保持。
- native `NOT,(DOMAIN,a.test)`、空 child、多个 child、额外包装、非法尾字段及无效叶子继续拒绝。native AND／OR 的既有空／单 child 语义保持。
- 保持字面括号平衡、native ASCII trim、regex 内部括号、ignored tail、方向和 no_resolve 语义；HTAB／非 ASCII 空白不按 ASCII space 擅自扩展。
- `_normalize_condition`、`_condition_kinds` 和 `formats._logical_value` 通过共享 helper 一致处理；嵌套、600／1000 层、三 purpose 与三 no_resolve 模式均完整保留或按目标整条跳过。
- 直接合法 native Rule 的 Surge NOT 投影复用现有 child ranges／edits，删除外层 list 与唯一 child 之间的 ASCII space；例如 `Rule('NOT', '( (NETWORK,tcp) )', native_fields=True)` 在 `keep` 模式的 full／non-DOMAIN-SET split 必须输出 `NOT,((PROTOCOL,TCP))` 并可由普通 parse 回读。Mihomo YAML `keep` 保留原包装空白；ordinary 分支、AND／OR 和其他 arity 保持。该定向 hunk 由 C 修改，与 A 的 `formats._domain_value` 不重叠，不新增 parser 或重构整个函数。

完成条件：public parse 和直接合法 native logical Rule 的 render 均保留必要包装，实际 YAML source 及非空磁盘依赖可回读，ordinary 行为和非法 native arity 不回归。

### R7. native item 解码后拒绝 `@@`

`payload:`／`rules:` 的 item 在 YAML 标量解码后，只要以 `@@` 开头就拒绝并给出原物理行 warning。`payload:\n  - "@@||safe.example.org^"` 不得产生 `allow=True` 的 Rule，不得删除合法路由或生成 DNS `@@`。

- 判定仅针对解码后的 native item，覆盖 single-quoted、double-quoted、支持的 plain 及 YAML escape 解码结果；以实际解码值为准。
- 保留 native 中已有 hosts、bare domain、bare CIDR、普通 block ABP 及 HOST alias 兼容，不整体关闭 mixed-format shortcut。
- 普通顶层 `@@||safe.example.org^`、公开 `Rule(allow=True)`、正常外部白名单和其目标局部能力保持。未知或 conditional ABP 的原诊断不因该修正放松。
- source 与 white 分别经过真实公开入口。只有非法 native item 的本地来源维持无可用规则错误／旧产物保护；带合法邻行时拒绝该 item 并继续生成。不得用人工 allow fixture 代替该负例。

完成条件：原最小错误被公开 parse／parse_whitelist 和真实 generate／publish 回归覆盖，邻行、行号、static 和旧文件保持，原 allow 与 mixed-format 正例通过。

### R8. Unicode 比较保留 matcher 与合法 keyword 输出能力

`domain_source='qx'` 的 `DOMAIN-KEYWORD`／`DOMAIN-WILDCARD` 不得用 Python full lowercase 合并不同的非 ASCII payload，或依据未证明的跨值包含关系删除规则。公开 `HOST-KEYWORD,ΟΣ`／`HOST-KEYWORD,ος`、literal 及含星号的 `HOST-WILDCARD` 均可读入，Python `lower()` 将两值合为 `ος`，已有 Mihomo native matcher 按 Go simple lowercase 分别使用 `οσ`／`ος`。`HOST-KEYWORD,İ`／`HOST-KEYWORD,i̇` 的第二个 payload 为 `i` 加 U+0307；Python 得到同 key，Go 分别得到 `i`／`i̇`。来源归约后，ASCII `RuleHost() == 'i.example'` 的第一条 keyword 命中可能消失。

依据为固定 [Mihomo keyword constructor 与匹配](https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/rules/common/domain_keyword.go#L19-L35)、[wildcard constructor 与匹配](https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/rules/common/domain_wildcard.go#L20-L35)、[Go `strings.ToLower`](https://github.com/golang/go/blob/c293dd49cbe25e1fe8d97d94a5cb618e7b6d831e/src/strings/strings.go#L727-L765)及 [Unicode 15 case table](https://github.com/golang/go/blob/c293dd49cbe25e1fe8d97d94a5cb618e7b6d831e/src/unicode/tables.go#L8753-L8759)。两份独立终报均确认公开 normalize、来源 white 和真实 generate／publish 的规则损失；客户端匹配差别由固定源码推导，未运行客户端。

- 共享 `_domain_comparison_value` 对 QX 非 ASCII keyword／wildcard 返回完整原文，包括其中的 ASCII 字符；Rule 原值不改写。ASCII-only QX、Mihomo 和普通 Surge 原来源比较及 source white 语义保持，R14 byte 覆盖和 R17 normalize-local wildcard identity 按各自要求处理，不增加 Unicode 表、依赖或闭源 QX 全域语义假设。
- `normalize` 同时保留不同非 ASCII QX payload 的 unique identity，并限制未证明的 keyword 跨值 contains 归约。`ΑΟΣ`／`ος` 的错误包含须消除；`Σ`／`ΟΣ` 的现有保留须保持。仅改 key 会使 `Σ` 成为 `ΟΣ` 的字面子串并新增误删，不能单独交付该修改。
- `normalize` 内非 native 的非 ASCII keyword 代表身份及候选索引保留原文，不能在目标能力 guard 前用相同转换 key 丢弃不同原文。对应 contains 候选须同时满足原文字面 substring、旧 source comparison 包含及全部原 target／root guards；QX 继续不作未证明的非 ASCII 跨值归约。保留 Surge `İ`／`xİ`、`中文`／`中文广告`、ASCII 正常归约及现有长度索引和资源限制，不全局改变 Surge 比较或 source white。Mihomo native 的原 comparison key、已证明 contains／root／target guards 和 Greek 期望保持；不将这两个 Surge／QX DNS 预算见证扩大到 native 归约。
- `exclude_covered` 同时限制涉及非 ASCII QX white 或 candidate 的跨值覆盖，包括 keyword 子串、literal／wildcard 匹配和 suffix／segment 推导。保留同来源、相同 kind、相同原 payload 的身份覆盖；其余未证明关系保留规则。ASCII-only 的现有完整覆盖及 Mihomo／Surge 行为保持，不把 QX 非 ASCII 一律当作可删除白名单。
- keyword／wildcard 两种 kind，Greek／dotted-I 同 key 与 proper substring，两方向 white、literal／含星号 wildcard、重复／逆序／一次性 iterable、allow／options／literal_process／native_fields／domain_source 分组均用公开入口验证。相同 payload、ASCII case 去重／包含、混合来源及既有 native Greek 行为作为对照。
- 真实 source、raw／generated white、同轮 `fin-qx.txt` source＋white 和 publish 后非空 disk-only 依赖保留原 matcher；`fin.yaml` 重导入按 Mihomo 来源处理。三 purpose × 三 no_resolve、六格式正文及 diagnostics、static 和旧文件保护保持；不据产物少行推断闭源 QX 或 DNS 全域运行时语义。

合法 DNS 输出完整性另有 equal-key／proper-substring 两例。令 `N = 21843`，`A = U+0130 * N`、`B = (i + U+0307) * N`，A 与 B 的 Python lowercase 同 key；普通 Surge 与 QX 均会只留下 B，使可表达的 43,695 bytes DNS 行消失，B 的行需要 65,538 bytes。另以 `short = B`、`long = x + A`，原文无 substring，转换 key 存在 proper substring，当前归约丢失 43,696 bytes 的合法 long 行。字节数包含 LF；allow 分别还须计入 `@@`，long 的 allow 行为 43,698 bytes，short 的 allow 行需要 65,540 bytes。

该补充依据 README 的完整可表达输出、keyword 目标能力要求及 `2026-10-23-functional-regressions-design.md` R6 的合法长值边界。验收同时覆盖 Surge／QX 的 unique 代表、keyword 索引和 contains，block／allow、raw／generated white 的 `@@`、真实 source／同轮／非空磁盘依赖；native DNS 保持 constructor lowercase 后的 presentation bytes 和原安全归约。保留 DNS renderer、65,536 bytes 限值、原 Rule 与来源 white 语义；超限项仍计 unsupported。此处确认受支持输出完整性丢失，未证明正常可达 DNS Host 漏匹配，不单列运行时缺陷。

完成条件：公开 parse -> normalize／exclude_covered -> render 和真实 generate／publish 保留已证明不同的 Mihomo matcher 及上述合法 DNS 行；共享 helper 与两个 caller、normalize 的 equality／索引／contains 均满足边界。身份覆盖、稳定排序、已证明 ASCII 和 Surge Unicode 安全归约及原性能条件继续通过。R8 的旧测试调整仅限范围表列明的非 ASCII QX 跨值删除与生成期望；其中 `NativeWildcardBoundaryAuditTests.test_native_short_wildcards_match_bytes_and_literal_brackets_without_cross_source_merging` 只将 `aé.example.org` 对 `a?.example.org` 的统一空列表期望改为 Surge 删除、QX 保留。该项属于既有 R8，不增加产品缺陷；A 精确修改、回归和提交后以新最终 head 完整验收，fixture、其他断言和资源条件不变。R18 另有明确的 native Surge 目标能力期望修正。

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

每个 owner 在各自获准的独立 worktree 连续完成实现、相关回归、规格／功能／简化审查、修正、复审和英文提交，再以最终提交 head 的完整 Git archive 在 Debian 原生 `/tmp` 运行完整 suite 后交付。失败仍由同一 unit 处理，不能把未完成步骤转交主会话；涉及产品修改时，owner 必须在有效独立编码 worktree 完成修正、重新提交和重验。主会话仅合并无所有权冲突的已完成提交，集成树另行完整验收。

D 已在独立 worktree 完成编码、提交及独立 review；同 D-unit 随后从当前获准仓库只读导出原完整提交 `5a25411fab3084c57a3f43affcab126ded477bbe`、tree `5a4b68b13983050e400ea42e5072793205f4026a`，在 Debian 原生 `/tmp` 完成本节验收：1513 tests、0 failures、0 errors、10 个原 skips，148 个受控路径前后清单相同，source／index 保持，临时 snapshot 已清理。证据为 `.tmp/u13-exact-acceptance-20261024-8d6383b2`。该历史验收未 checkout／合并 D、未写真实源码或 index，R13 及 D 的 R10 已完成；最终集成、固定输入和 Ubuntu 验收分别执行，不重跑 D 已通过的同一 head。

C 的 U6 接续修正使用当前已有效、从 main 分离的独立 worktree `audit-20261024-5bebe430-integration`，由同 C-unit worker 独占专用分支 `audit-20261024-5bebe430-C-current-review`。从 clean 文档 head `7fe72596e88b96ff844dc0e3228ec988d6427143` 建立该分支并正常合并原 C 完整 head `62757b30c109287bc8301500ddb7a63b1ece6a96`，保留最新文档及三个原实现提交；原 integration 分支保持原 tip。该 worker 连续完成文档提交、公开 red／green、编码、相关测试、规格／功能／简化审查、修正复审、英文提交及最终 actual HEAD 的本节完整 suite。交付前主会话不写该 checkout 或 index，不访问被拒旧路径、不另建 worktree、不修改 `.git`、权限或本机；完成后主会话切回原 integration 分支正常合并已验收结果。D 的历史只读方式不限制当前有效独立 worktree 的上述独占编码。新失败仍由原 unit 在有效独立 worktree 完成修正和新 head 重验，禁止在 main 编码或由主会话接收未完成步骤。

C 已完成 actual head `960721a7e7ff5367f7c0444262e8f4242f7b801e` 的审查及完整 suite 并释放 checkout／index。R1／R17 suffix candidate 接续由同 A-unit worker 独占当前有效独立 worktree 的 `audit-20261024-5bebe430-A-tail-current-review` 分支，从该 C head 正常合并原 A 完整历史 `6ce6c7e0d940ed21e76c54d7f4ce5f5b10fdf724`；原 C 分支和原 integration tip 保持。worker 连续完成两份文档提交、公开 red／green、最小修正、相邻及真实 bytes 回归、规格／功能／简化自审、英文提交、独立窄复审与必要修正复审，再对最终 actual head 运行唯一完整 suite 后交付。复用既有 `.tmp/functional-audit-verification-tools` 和 expected-skips，不重跑已完成 selfcheck 或旧 A／C head 全套；Windows 原生 Git 核 source clean，Linux 记录 source／index／mode／bytes 前后严格清单，不向测试导出 `GIT_DIR`／`GIT_WORK_TREE`。交付前主会话只读 Git 对象／证据、写 ignored 进度，不写受控树／index；worker 不访问被拒旧路径、不新建 worktree、不改 `.git`／权限／系统、不切回 integration、不执行 main／push，完整交付后明确释放 checkout／index，由主会话正常集成。

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

记录本次已创建的实现 worktree／分支及尝试创建的 recovery 路径，不把创建失败记为已创建；仅清理可核实存在、已合并、clean、无未合并提交且已无用途的项目，先退出任务 worktree 返回原目录。保留用户 `.claude/`、历史 worktree、其他任务分支及所有未保存内容；不为清理访问被拒旧路径或绕过隔离，不能核实的项目保留，非阻塞清理失败逐路径记录。

### R13. 普通 quoted process 字段后的尾注释

普通来源 `PROCESS-NAME,"Game" # tail` 必须解析为 `Rule.value == 'Game'`，与无注释对照相同。`PROCESS-NAME`、`PROCESS-PATH`、`PROCESS-NAME-WILDCARD`、`PROCESS-PATH-WILDCARD` 的字段以单／双引号开头且已闭合、随后在引号外由空白分隔 `#`／`;`／`//` 时，注释不进入 matcher；注释中的逗号、未闭合引号或括号不再污染字段或使合法规则被跳过。

[Surge Rules Overview](https://manual.nssurge.com/rules/overview.html)允许 quoted value 和行末三种 marker，[Profile Format](https://manual.nssurge.com/profile/format.html)规定 delimiter 前有空格，[External Rule Sets](https://manual.nssurge.com/rules/ruleset.html)规定无 policy 行；[Process Rules](https://manual.nssurge.com/rules/process.html)明确 PROCESS-NAME 匹配模式。其他三个 kind 按仓库既有兼容类型验证，不据此声称 Surge 官方支持。

- 只修改 `_source_parts` 普通 process 分支，复用 `_literal_fields` 读取已确认的引号外尾注释；不修改全局 lexer、logical／native 处理、Rule、renderer、配置或导出。
- 裸 process marker、quoted 字段内部 marker、明确表示字面引号的外层引用、`HOST-KEYWORD` literal 例外、policy 后注释及 logical 中 process 原行为保持。双引号 escape、尾反斜杠、逗号、空白和非法未闭合源字段沿用现有规则。
- 四 kind × 两种 quote × 三 marker × 三 purpose 的 72 组合，从 public parse 到六格式正文、Mihomo matcher 与无注释对照一致；按三 no_resolve 补回归，合法邻行与物理行号保留。process 不新增 white 支持，native 外层 YAML 注释和内部字面字段继续区分。
- 临时 root 的真实 source、同轮 `fin.txt`／`fin.yaml` 依赖、publish 后移除 parent 的非空 disk-only 依赖保留正确值；真实 bytes、diagnostics、static、输入和旧产物保护均按 R9 核查。

完成条件：最小公开 red -> green，72 组合与所有 literal／policy／logical／native 对照通过；generate／publish 的同轮和磁盘 bytes 保持正确 matcher，D 最终 head 满足 R10。

### R14. native wildcard 按 constructor lowercase 后的 bytes 判定覆盖

native source `ẞ.example`／`Ⱥ.example`／`Å.example` 与 native wildcard white `???.example`／`??.example`／`???.example` 均能公开读入；Go15 lowercase 分别得到 `ß.example`（首 label 2 bytes）、`ⱥ.example`（3 bytes）、`å.example`（2 bytes）。white 的 `?` 数量不匹配真实字节数，`exclude_covered` 和 render 的目标过滤必须保留 source；问号改成正确的 2／3／2 个时继续成立覆盖。

依据为固定 [Mihomo wildcard constructor](https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/rules/common/domain_wildcard.go)先调用 `strings.ToLower`、[wildcard matcher](https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/component/wildcard/wildcard.go)按 string bytes 消费 `?`，以及 [正常 Host 入口](https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/adapter/inbound/util.go)与 [Metadata.RuleHost](https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/constant/metadata.go)的原文路径。独立双视角确认公开来源过滤、raw render、generate 及同轮／磁盘依赖错误；客户端结论由源码推导，未运行客户端。

- 最窄修正只在 native wildcard 白名单 byte 比较前，对 white pattern 和 candidate 两侧使用完整既有 Go15 lowercase。保留 Rule 原文，不全面替换 comparison unique key，不扩大 native keyword 的 equality／contains 或其他 normalize 归约。
- 复用现有 `_go_lower` 和 `_unicode15.py` 数据。为无循环依赖的共享读取，可按最少可靠依赖选择迁移位置；若移动 helper 或其 regex 依赖，同步全部 caller 并清除旧实现，不新增 Unicode 表、依赖或通用投影层。
- 保持 source 分组、allow、native bracket literal、root-dot、ASCII／Greek 覆盖、QX 非 ASCII 保护及 known suffixcase 行为。三组 source／white 的错误 byte 数均保留、正确 byte 数均覆盖，并反向核对两侧转换。
- 公开 parse／parse_whitelist／exclude_covered／render、真实 generate／publish、source＋white 同轮和非空 disk-only 依赖均覆盖三 purpose × 三 no_resolve；核查六格式正文、诊断、输入／static、旧产物及冻结保护。

完成条件：三组字节宽度反例与正确数量对照均从公开入口和真实 bytes 验证，shared helper 所有 caller 及原 Unicode／process／DNS 回归保持；A 在 U8 后完成 U14，再连续完成 U17／U18，以最终 head 满足 R10。

### R15. hosts 仅按 ASCII SP／HTAB 分隔和裁剪

`0.0.0.0 good.example bad.example<NBSP>protected.example sibling.example` 中 `<NBSP>` 表示 U+00A0。非法 alias 必须保持为一个值交既有 hostname validator 拒绝，给出原物理行的 invalid hosts domain warning；继续保留 good／sibling 及后续合法行，不生成 bad／protected 两个独立 DOMAIN。相同 hosts 用作 white 不得删除正常 protected 规则或产生其 DNS 例外。

[hosts(5)](https://man7.org/linux/man-pages/man5/hosts.5.html)规定 blanks／tabs 分隔与 `#` 注释；固定 [urlfilter host parser](https://github.com/AdguardTeam/urlfilter/blob/dba702354cd6a5a0eed03b41da0b22dd46a42af0/rules/host.go)使用 SP／HTAB delimiter。初始 ordinary scan 与独立复核确认无参数 rstrip 和 split 会删除或拆分非标准空白；20 个非标准 isspace 字符 × 四地址 × LF／CRLF × 五位置及真实发布均复现。

- 只修改 `_source_records` 的 hosts 注释后裁剪及 parse 的 `host_parts`，使用现有 SP／HTAB 边缘 trim 与分隔。非标准字符保留给既有 hostname validator；不改全部字段的全局空白语义、不手写 parser、不扩展格式。
- 保留 native 解码后的前导 SP／HTAB 兼容，不能因切分产生空首字段。四个支持地址 `0.0.0.0`／`127.0.0.1`／`::`／`::1`、BOM／CRLF、`#` 注释、逐 alias 合法恢复和物理行拒绝／行号保持；direct／proxy 仍为 block-only。
- 回归覆盖 U+001C..U+001F、U+00A0、U+1680、U+2000..U+200A、U+202F、U+205F、U+3000 在内部、尾部、注释前、地址后及前导位置。source／white、ordinary／native mixed hosts、标准 SP／HTAB 对照均通过公开入口。
- 临时 root 真实 generate／publish，六格式正文与 diagnostics、raw／generated source／white 同轮及移除 parent 后非空 disk-only 依赖均验证；输入、static、旧文件和发布失败保护保持，不修改既有 `tests/test_hosts_comment_regressions.py`。

完成条件：最小 NBSP 公开 red -> green，完整位置矩阵和 native ASCII 前导兼容通过；不再误增域名／white／DNS 例外，E 独立最终 head 满足 R10。

### R16. HTTPS informational response 后继续读取最终响应

合法 HTTPS 响应流含一个或多个 102／103 等 informational response 后，`fetch_https` 须在同一连接继续读取最终响应，按既有最终状态和正文规则处理。`100 Continue` 保持标准库已有支持，`101 Switching Protocols` 保持失败；不重发 GET，不将提示字段视为最终状态／headers，不自行获取 hints 中资源。

[RFC 8297 §2](https://httpwg.org/specs/rfc8297.html#early-hints)允许多次 103，且提示字段不得代替最终响应。完成的初始 transport 独立反证已用真实 HTTPResponse、22 项本地 TLS 检查、108 组 source／white × purpose／no_resolve／编码／redirect 生成矩阵及进程内修正对照确认功能差异，另有 84 项既有测试通过。这些为修复前证据，不代替永久修正及最终验收；未核实当前生产上游实际发送 103。

- 仅调整 `generate.py` 的 `_HttpsOnlyRedirect`／`fetch_https`，在默认 HTTPErrorProcessor 前复用成熟 `HTTPResponse.begin()` 循环消费合法中间响应。每次继续前清除中间 headers，最终 status／headers 仅由最终响应确定，保持 urllib 的 `msg == reason` 约定。
- 读取最终响应发生错误时及时关闭 response 并传播，不返回中间 headers、残缺正文或 fallback。保留最终 200、HTTPS redirect／禁止降级、最终 404 缓存／跳过、429／5xx 中止、大小、Content-Length、chunked、gzip、空正文和原 cause／URL 诊断。
- 回归单／多 103、102、与 100 混合、redirect 前后、source／white 同 URL cache、plain／gzip／chunked／组合编码、最终错误／缺最终／截断及资源关闭。复用标准库 HTTP 处理，不手写 HTTP parser，不新增依赖，不改规则／renderer／配置／workflow／API。
- 真实 generate／publish 检查三 purpose × 三 no_resolve、六格式正文和 diagnostics 与去除 interim 的相同输入对照一致；旧六文件、static、输入及失败前不发布保持。线级 fixture 与本地 TLS 仅用于合法协议功能验证，不开展网络安全工作或本机适配。

完成条件：最小 103 -> 200 公开 red -> green，重复 GET、提示字段污染、错误关闭均有回归；真实生成发布和全部原传输边界通过，F 独立最终 head 满足 R10。重复独立复核已完成且确认同一缺陷，未发现反证；既定最小处理范围保持。

### R17. 普通 Surge 的 Unicode keyword／wildcard 保留自身字面命中

普通 `DOMAIN-KEYWORD,İ`／`DOMAIN-KEYWORD,ΟΣ`／`DOMAIN-KEYWORD,ΑΟΣ` 和对应含星号 wildcard 投影为 Mihomo regex 时，须按既有 Go15 simple lowercase 得到 `i`／`οσ`／`αοσ`，保留原字面 Host 的命中。Python full lowercase 的 combining dot／上下文 final sigma 不得改变 matcher；原 final sigma `ος` 继续保持。

[Surge Domain Rules](https://manual.nssurge.com/rules/domain.html)规定 keyword 字面 substring 与 wildcard literal；固定 [Mihomo regex constructor／Match](https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/rules/common/domain_regex.go)使用 regexp2 IgnoreCase 与 RuleHost。完成的独立报告已核对 regexp2 parser／runner 的逐 rune Go lowercase，公开 parse／normalize／render 及真实 YAML 同轮／磁盘依赖均复现。较早回读收据不能排除该 matcher 语义差别；未运行客户端，不以 Python re.I 作为 Unicode oracle。

- 只将 `formats._domain_value` 普通 Surge -> Mihomo keyword／wildcard 的两个 Python lower 复用现有共享 `_go_lower`。保留 keyword 尾点 lookahead、wildcard optional-root／boundary、ASCII 和其他来源／目标能力，不批量改 suffix regex 或已知 suffixcase。
- normalize-local 普通非 ASCII wildcard 的 unique identity 保留原文，不让 `*İ*`／`*i̇*`、`*ΟΣ*`／`*ος*` 在 renderer 前合并；keyword 复用 R8 已有原文代表及双重 contains 保护，不重复实现。不全面替换 `_domain_comparison_value`。
- raw unique key 不直接作为 suffix candidate；该 candidate 单独复用既有 comparison，保留 R1 无有效投影时的安全归约。`İ*.EXAMPLE.COM`、`*ΟΣ*.EXAMPLE.COM`、`中文*.EXAMPLE.COM`、`[ab]İ*.EXAMPLE.COM` 的有效投影及带匹配 suffix 的 dotted-I／Greek pair 原文身份和不同 regex 均保持，不一律删除非 ASCII wildcard。
- 保持旧字符类准入；`[İ]`／`[İ-J]` 等原 unsupported class 不因 simple lowercase 新增输出。复用既有 class 验证，不新增 parser。`İ`／`xİ`、中文／ASCII 安全归约、identity、根点和 class 正反例均保持。
- scalar、AND／OR／NOT、公开 allow、target white、六格式 diagnostics 与实际 generate／publish 验证三 purpose × 三 no_resolve；YAML source 同轮及 publish 后非空 disk-only 回读保留正确 matcher，正／逆序、重复和一次性 iterable 一致。
- 普通 Surge source white 的 Unicode 完整覆盖依据尚不足，本项不修改普通来源比较／white，不把观察到的目标差别扩成 Go 全局 key 或关闭全部 Unicode 归约。保持原白名单来源语义，target white 按实际投影核查。

完成条件：两类普通投影及原文 unique 的最小 red -> green 和真实 bytes 回归通过，原 class／root／identity／安全归约保持；A 在 U14 后独立提交 U17。

### R18. native Unicode keyword／wildcard 的 Surge 能力使用完整 case-variant 判定

native keyword／wildcard 含固定 Go15 case 变体字符时，只跳过 Surge full／non-DOMAIN-SET split 输出并计 unsupported；含此叶子的 AND／OR／NOT 对 Surge 整条跳过。`É`／`Σ`／`ẞ` 及 lowercase `é`／`σ`／`ß` 均须使用同一能力 guard，不能以 `value == _go_lower(value)` 代替 case-variant 检查。

依据为固定 Mihomo keyword／wildcard constructor 仅将 pattern lowercase、以原 RuleHost 做 contains／byte 比较，与 Surge 自身字面命中存在已证明差别。独立报告核对现有 `_PROCESS_CASE_VARIANTS` 与固定 Go15 全部 CaseRanges／caseOrbit 的 2,880 个 case 变体，无缺漏；只证明该固定集合，不承诺闭源全域 Unicode／IDNA 等价。

- `rules._surge_keyword_source_supported` 与 `formats._domain_value` 的 native wildcard guard 统一复用现有 `_PROCESS_CASE_VARIANTS`，沿用 R14 同一共享定义，不复制表或新增依赖。保留 helper 的全部 process／DNS caller。
- 只收紧 Surge 目标能力，不改 DOMAIN／DOMAIN-SUFFIX、native unique／keyword source comparison、普通来源 white 或已有 `_route_whitelist` 的更严格限制。原 Mihomo／QX／DNS、数字／中文／case-invariant 支持保持。
- 保留 keyword 末尾点、wildcard 尾星号／根点、问号 byte／字符和 bracket 条件；white／allow 不因此跨来源删除其他规则。scalar／logical、三 purpose × 三 no_resolve、六格式及真实 YAML 同轮／非空磁盘依赖均核查。
- 旧测试仅精确修改范围表列明的 `PublicGeneratedPipelineTests.expected` parent／child 两份 Surge 输出及其 header／unsupported；YAML、QX、DNS Greek bytes、DOMAIN-SET、fixture、发布和其余断言保持，新增回归使用 `tests/test_native_unicode_capability_regressions.py`。

完成条件：uppercase／lowercase case 变体只跳 Surge，logical 整条跳过及正对照均有公开 red -> green／真实发布证据；A 在 U17 后完成 U18，最终 head 满足 R10。

## 完成标准与不处理项

R1-R8 及 R13-R18 均有公开接口、负例及真实 bytes 回归。六组 owner 从各自确定文档范围连续完成 slice，最终集成前核对全部覆盖收据；各最终 head 与集成 exact tree 通过 R10，固定输入、42 产物和实际获授权远程发布分别满足 R11、R12。未确认候选不计入完成结论。

不启动客户端，不执行外部源码或二进制，不做网络安全扫描或修复，不调查本机适配、多平台或已有 Windows 故障，不修已知 suffix 大小写，不扩展独立 publish 的未知非 canonical leaf API，不增加未确认性能优化。当前文档任务仅修改本规格和配套计划，不运行实现测试、不改源码／测试／README／配置／static／产物、不 push 或合并 main。
