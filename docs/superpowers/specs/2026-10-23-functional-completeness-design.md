# 功能完整性扫描与修复规格

## 目标、基线与实施门槛

全面检查规则解析、来源白名单过滤、规范化、各目标投影、生成依赖及发布，复现并修复全部确认存在、可修且不破坏其他功能的问题。重点检查去重顺序与完整性、多客户端格式、`no_resolve` 和上游异常处理。

代码基线为 `ea67234ae739af33fd5f7ecfa197213183eaeb28`，tree 为 `752c5358aa961ed4ce74f80d245e23489426ee5b`。全部 scan 与 coverage-check 已完成，139 个受控文件均有检查记录。routing-formats 的空报告已由 coverage-check 补查全部 42 种 scalar、56 个 case、594 个 mode 组合，无剩余文件缺项。本规格包含独立复核后的 R1 至 R5。

Linux exact archive 基线已完成：WSL Debian Python 3.13.5，1416 tests，0 failures，0 errors，10 个既有 Windows-only skips；unittest 日志耗时 1346.911 秒，外层记录 1347.001 秒。139 个受控文件在测试前后 hash 不变。这些结果只证明初始基线；产品修复和最终 tree 验收尚未完成。

产品实施以包含全部五项要求的共同规格／[计划](../plans/2026-10-23-functional-completeness.md)提交为起点。新候选须完成复核，确认问题及变更范围须写入两份文档，再开始或恢复受影响的实施。

## 范围与约束

- 产品修改限定于 `rules.exclude_covered` 的 CIDR 索引、`rules._ordinary_field_supported` 的 ASN 能力判断、`formats.render` 的 Surge `no-resolve` guard、`formats._dns_regex` 的分支预算及调用内片段复用、`rules._delimiters`／`rules._valid_regex` 的 regexp2 class 扫描、capture slot 收集与引用校验及确需的共享短 helper、`rules._source_records` 的普通 hosts 分支。对应回归测试随修复更新。
- 保留公开入口、`Rule` 全部字段、配置键、`formats.FILES`、七组生成顺序及六种输出文件。`sources.py`、`generate.py`、`update.py`、`update_readme_counts.py`、`rulesets.json` 和 CI 配置均无已确认的修改需要。README 仅更新 CIDR white 完整并集与 native padded ASN 的必要行为说明，数量表保持。
- 不运行任何规则客户端，包括配置测试模式；外部实现仅阅读固定源码及文档。不开展网络安全扫描或修复，不处理 Windows／多平台适配，不处理已知 Mihomo suffix 大小写，不增加批量使用 regex 改写 suffix 规则的流程。
- `static/` 与用户现有修改保持原样。测试和生成使用独立 fixture root；生产产物由最终发布流程更新。

## 已核查的数据流及影响位置

| 路径 | 当前行为 | 本次影响 |
| --- | --- | --- |
| `rules.parse`、`_normalize_condition` | 普通 ASN 去除 `AS` 和前导零；native provider 保留 ASN 字符串。CIDR 校验、方向及 scope 拒绝在此处理 | 保持解析与输入校验 |
| `rules._source_records`、`parse` | 普通 hosts 先去 `#` 注释，当前仍进入通用 lexer；后续已有逐 alias validator | R5 使已识别 hosts 直接到逐 alias 校验，其他语法及 HTML／物理行检查保持 |
| `rules._delimiters`、`_valid_regex` | 普通字段／logical 扫描及 regexp2 validation probe 处理字符类边界；capture slot 须遵循固定预扫描，deep validator 消费 probe | R4 修正三种 regexp2 类型的完整 POSIX-looking token 边界及预扫描 capture slot／引用校验，原 matcher 与 URL-REGEX 保持 |
| `formats._dns_regex` | 三个 DNS 消费者共用分支构造、证书及 source／Go／最终行预算 | R3 重置当前 concat 计数并在单次调用内复用相同编码片段 |
| `rules.parse_whitelist` | 忽略 policy，移除 options／allow 标记，保留适用的 matcher 身份；不合并 CIDR | R1、R4、R5 同时覆盖真实 white 入口 |
| `generate.generate` | `exclude_covered(rules, whitelist + allowed)` -> `_apply_no_resolve` -> `normalize` -> `render(..., no_resolve="keep")` | 保持来源过滤先于规范化的顺序 |
| `rules.normalize` | 按 options、allow、来源等身份分组；已有 `collapse_addresses`；keyword 归约会调用目标能力 helper | 复用标准库方法，keyword 行为不变 |
| `formats._logical_value` | Surge 每个叶子调用 `_ordinary_field_supported(..., literal_field=True)`；不支持时整条目标 logical 跳过 | 自动取得 R2 判断 |
| `formats.render` | Surge 普通 scalar 使用共享 helper；带 `no-resolve` 的 scalar 分支目前绕过 helper；QX 经 `_qx_field_supported`；Mihomo 经 `_mihomo_rule` | 补齐 Surge 分支，保留 Mihomo 原值 |
| `formats._route_whitelist` | 先检查 options 及目标能力；Surge／QX 共用字段 helper；筛选后调用 `exclude_covered`；QX 另有 identical-only 路径 | R1 只合并已进入索引的网络，R2 同时保护目标白名单 |
| `generate.generate` 的依赖读取 | 读取实际格式 bytes；同轮空生成文件可作 source／white，disk-only 空本地输入严格拒绝 | 修复后的合法空产物沿用原处理 |
| `generate.publish`、CLI | 暂存后替换六种文件，替换失败恢复旧文件；CLI 调用真实 generate／publish | 回归核验磁盘 bytes 及输入不变 |
| `update.update` | 核对 tested SHA 与远端 main，生成、更新 README 数量，仅暂存配置产物及 README，普通 push | 用现有发布流程完成远端验收 |

生产 caller 已逐个核查：`exclude_covered` 由 `generate.generate` 和 `formats.render` 调用；`_ordinary_field_supported` 还被 `_qx_field_supported`、`normalize` 的 keyword 分支、Surge scalar／logical／white 使用。测试直接调用这些公开入口，不用替换内部算法证明修复。

## R1：有效白名单 CIDR 的完整并集覆盖

### 已确认现象与根因

source 为 `IP-CIDR,192.0.2.0/24`，white 为 `IP-CIDR,192.0.2.0/25` 与 `IP-CIDR,192.0.2.128/25` 时，基线保留 source。两个 `/25` 的并集恰好等于 `/24`。white 经独立生成组规范化成 `/24` 后，同一 source 被删除。IPv6、来源方向、公开 render、真实 generate／publish／CLI 均有对应复现。

`exclude_covered` 只保存原始 white 网络，再查询 source 自身及祖先网络，无法命中更具体网络共同构成的父网络。`generate` 在来源过滤之后才规范化剩余规则，因此 caller 并未消除该差异。

### 修正要求

1. 收集通过现有调用方筛选及 `_reject_ip_scope` 校验的网络后，分别按 `src`／`dst`、IPv4／IPv6 执行 `ipaddress.collapse_addresses`，将结果放入原覆盖查询集合。原先的 source／祖先查询保持。
2. source 的整个地址集合包含于有效 white 并集时删除该条规则。部分覆盖、只覆盖一个子网、存在一个地址缺口、source 比并集更宽时，完整保留 source；不切割 source。
3. `IP-CIDR` 的 IPv6 写法与 `IP-CIDR6` 按实际地址族判断。`SRC-IP` host 可与同方向 host／CIDR 组成并集，IPv4 `/31`、IPv6 `/127` 均应覆盖。
4. white 重复、重叠、逆序和一次性 iterator 取得相同结果。`rules` 与 white 各按原接口消费，保留未删除 source 的原对象、顺序及 `allow=True` 对象。
5. 仅处理网络索引，不对整份 white 调用 `normalize`，不修改域名、regex、ASN、GEOIP、IP-SUFFIX 或 logical 的覆盖规则，不修改 logical 叶子。

### 必须保持的目标边界

直接 `exclude_covered` 继续按既有语义忽略 white options；`parse_whitelist` 继续移除 options。直接 `render` 的外部 white 则须先通过 `_route_whitelist` 的 options 及目标能力判断。有效半段与不支持 options 的另一半不能共同删除目标规则。输入 allow 仍按 `no_resolve` 及受支持接口参数清理后的 matcher 参与路由 white。

直接构造 `domain_source='mihomo'` 的目的 IP white 时，QX 现有 identical-only 路径不把这些网络交给 `exclude_covered`。两个这样的 `/25` 不得新增 QX `/24` 删除能力；相同 matcher 的既有删除保持。普通 parse／parse_whitelist 得到的 IP white 按其真实字段走原有路径。跨方向、跨地址族及相同整数值的不同地址族均不得混合。

## R2：前导零 ASN 的目标投影保真

### 已确认现象与外部依据

native `payload:`／`rules:` 中的 `IP-ASN,0013335` 当前可进入 Surge scalar、AND／OR／NOT 和 QX scalar。实际生成的 `parent/fin.txt` 再作为 child source 时，普通 parser 将它规范化为 `13335`，child YAML 丢失原字符串身份。读取 parent YAML 则保留 `0013335`。这项回读差异已由公开 CLI 复现。

固定 Mihomo commit `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8` 的 [`NewIPASN`／`ASN.Match`](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/rules/common/ipasn.go)保存并比较原字符串；其 [GeoLite2 reader](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/component/mmdb/reader.go)把 `uint32` 通过 `fmt.Sprint` 转成数字字符串，[NOT](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/rules/logic/logic.go)直接否定子规则结果。对数据库返回 `13335` 的有效 IP，`0013335` 与 `13335` 的 scalar 匹配及对应 NOT 结果不同。[Surge IP 文档](https://manual.nssurge.com/rules/ip.html)定义 decimal ASN，未规定前导零的具体接受方式。闭源 Surge／QX 的实际接受及运行结果未验证，本修正依据已确认的文件回读差异和目标投影证明边界。

### 修正要求

1. 在共享 `_ordinary_field_supported` 中，将多字符且以 `0` 开头的 `IP-ASN` 判为目标不支持。此判断也适用于 `literal_field=True`，不能被 logical 的 literal-field 例外绕过。
2. `formats.render` 的 Surge `no-resolve` scalar 分支调用同一 helper。无 options scalar、logical 叶子、Surge white、QX scalar／white 继续通过已有 caller 共用判断，不复制多份 ASN 判定。
3. Surge `fin.txt`／`fin-surge.txt` 跳过对应 scalar 或包含该叶子的完整 logical；QX 跳过对应 scalar，logical 保持原有整条不支持行为。诊断沿用 `<file>:<kind>` 计数，不把不支持投影计作 `whitelist-covered`。
4. native `00`、`0013335`、长零字符串及其 logical 在 `fin.yaml` 保留原字符串、方向和适用的 `no-resolve`。不删除 logical 叶子，不把规则编译为恒 true／false。
5. 不用 `domain_source` 或 `native_fields` 识别 ASN 的 native 来源。当前 native scalar 可能为 `domain_source='surge'`、`native_fields=False`；能力判断应检查最终字段本身。

### 必须保持的身份与支持范围

- 普通来源 `00 -> 0`、`0013335 -> 13335`、`AS0013335 -> 13335` 的现有规范化保持，包括 logical。
- canonical `0`、正整数、`4294967295` 保持现有支持；无效输入及 `4294967296` 继续由原校验处理。有效但数据库无记录的 IP 可在 GeoLite2 路径得到 `0`，不能将 canonical `0` 视为恒不匹配。其他数据库路径也不能用于推断 padded matcher 恒值。
- `SRC-IP-ASN`、native `src`、普通来源方向以及现有 `UNKNOWN` 边界不变。目的 ASN 的新增判定不扩大 source ASN 的 Surge／QX 支持。
- source／white／allow 的相同 padded 值可按已有身份关系覆盖；padded white 不能通过十进制重写删除 canonical ASN。输出与目标 white 使用同一字段能力边界。
- 仅含 padded ASN 的 parent 可产生非空 YAML 与合法空 Surge／QX 正文。同轮 child 读取空 `fin.txt` 时正常清空，读取 YAML 时保留原字符串；不得从其他格式补回。移除 parent 配置后，disk-only 空 source／white 仍按原规则拒绝。

## R3：DNS alternation 的分支预算与调用内复用

### 已确认现象与根因

公开 parse 接受 `\w` 和 `\w|\w|\w|\w`，后者却在 DNS block、public allow、真实 `parse_whitelist` 三个消费者中丢失 regex／`@@`，并增加 DNS unsupported。单个 `\w` 的最终 block 行含 LF 为 32,390 bytes，allow／white 为 32,392 bytes；重复分支具有相同布尔匹配集合。`\p{L}`、`\w\w` 及交错重复 `\w|\p{L}` 同样受影响，其他目标仍保留各自原有投影。

`_dns_regex` 在 alternation 结束时清空当前 concat 的 `nodes`，却保留 `dns_sizes[-1]`，使后续分支提前得到无正文证书。分支去重发生在此之后。仅重置计数能修正输出，但仍为每个分支重复编码并分别持有正文，512 轮实验超过原 8 秒限制且内存增长。

### 修正要求与保留边界

1. 在既有 `|` 分支清空 `nodes` 后同步重置 `dns_sizes[-1]`。保持 `dns_choices` 的去重位置；不同分支按最终唯一编码正文及实际包装扣预算，不忽略失败证书，不输出半条规则。
2. 只给 `_dns_regex` 内的 `lower_preimage`、`dns_runes`、`dns_concat` 添加调用内 `@cache`；`dns_concat` 的两个 caller 传入 `tuple(nodes)`。key 使用原有不可变 interval tuple 或完整七字段证书；单次调用内的 budget 与 empty 固定。相同 atom 和 concat 复用编码正文，避免每个重复分支持有独立展开全文。使用现有 `cache`，不新增 helper、依赖、公共 API、全局 cache 或分支数量阈值。
3. 缓存不跳过完整输入验证、source／Go 量词与 compiled-size、结构扫描、case／root 证明和最终 UTF-8 行限。不缓存未解析的完整 regex，不扩大未知语法支持，不提高递归或整数长度限制。nullable、空分支及 universal 的原归约保持。
4. block、public allow 和真实 external white 共用此修复。native、普通 typed 与 quoted 输入分别核对；重复输出须与独立单分支／单轮对照逐字节相同，相同输入的其他五类产物保持原行为。allow 仅使用现有 `Rule.allow` seam，不发明文件 allow 语法。
5. 真实 source、raw white、同轮与非空 disk YAML source／white 的 generate／publish 均保留可表达的重复 regex／例外，输入及原 source YAML 不变。邻居继续输出；DNS 局部 unsupported 的合法超限或未知结构不改变其他目标及原发布边界。
6. 单分支及四重复 anchored `a`／`\w` 在最终实际 `@@`、`/.../`、LF 合计恰好 65,536 UTF-8 bytes 时保留，增加一个 byte 时只跳过 DNS。两个不同大分支保留、三个拒绝；4,096 个不同小分支保留、8,192 个按真实预算局部跳过。
7. 512 轮 `\w`、`\p{L}`、`\w\w`、交错 `\w|\p{L}` 各在一个原 `timeout=8` 子进程中完成三消费者，交错输入实际含 1,024 分支。另用 tracemalloc 分开检查 64／256／512 轮三消费者的分配峰值增长，保留原每新增分支一份完整正文的增长阈值。保留既有高 rune 八秒、wildcard 内存及深层结构 guards；不将有限实验表述为任意 regex 的固定耗时／RSS 保证。
8. 在 512 个已识别分支后追加未知 header／property／interval、非 ASCII hex、根点敏感分支或超限量词，仍须检查并拒绝；未知项位于 universal／`{0}` 内也不能被复用绕过。600／1,000 层 neutral group、既有 F3／UTF-8／Go 边界均须保留。

调用内复用加 reset 的局部设计已经内存实验验证，产品代码及受控回归尚未实施。实验中的 512 轮四类输入完整进程耗时分别为 1.468、1.244、1.256、2.026 秒；只复用 `lower_preimage`／`dns_runes` 仍会持有重复 concat 正文，完整方案包含 `dns_concat`。实验与原资源反证均保留为审查证据，实施仍须独立 TDD。

## R4：regexp2 POSIX-looking 字符类边界

### 已确认现象与固定语义

`DOMAIN-REGEX`、`PROCESS-NAME-REGEX`、`PROCESS-PATH-REGEX` 的两个 scanner 提前把 POSIX-looking token 内的 `]` 当作外层 class 结束，错误接受 `^[[:alpha:]()]\1$`、`^[[:alpha:]-!]$`，并丢弃合法 scalar `^[[:alpha:](]$`。前者没有 capture 1，后者形成字面 `[` 至 `!` 的逆序 range。非法 matcher 可进入实际父／子 YAML；该现象不等于客户端整份 provider 必然加载失败。

依据为 regexp2 v1.12.0、commit `3d5df45b703801b3fe51eb3f5c0dd302e8b0d676` 的 `syntax/parser.go:1538-1590`。固定 Mihomo 对三种类型只启用 `IgnoreCase`，未启用 ECMAScript 或 RE2。非 RE2 的 `scanCharSet` 消费完整 POSIX-looking token 后，仍把当前 `[` 当作 literal；不按 POSIX 名称展开集合。

捕获预扫描与完整 class 扫描的差异也是固定语义。`syntax/parser.go:151-165,304-417` 先通过 `countCaptures` 和 `scanCharSet(false, true)` 建立 capture slot 表，再 reset 并完整扫描；reset 不重建 slot 表。候选 `^[a-\-[][:alpha:](?n)]](a)\1$` 长度为 29，只有索引 4、26 两个反斜杠，分别组成 `\-`、`\1`。escaped hyphen 保留 pending range；预扫描不递归 subtraction，在索引 7 的 `]` 结束第一个 class，随后在类外读取 `(?n)`，使 `(a)` 不登记 slot 1。完整扫描递归 subtraction，首个 `]` 为 literal，消费完整 POSIX-looking token 后将 `(?n)` 留在类内；后续 capture node 不补建 slot，`\1` 最终按原 slot 表得到 `ErrUndefinedBackRef`。该真值由固定源码的 `841,1256-1270,1522-1609,1939-1945` 行推导，未运行外部实现。

独立公开复核确认 commit `da0b38a5fe76ab7629777cdc17621ec45f210e0f` 在三种类型的普通 quoted 与 native scalar 共六种组合中接受该候选并写入 `fin.yaml`，属于回归。删除 `(?n)` 后的对照及 `^[a-\-[:alpha:]]$` 均须保留，不能通过拒绝全部 pending-range subtraction 消除误接受。

捕获预扫描按固定 `parser.go:369-397,1663-1684` 读取 `scanOptions` 前缀并立即应用 options 状态，即使下一个字符不是 `)` 或 `:`。完整扫描的 `_scan_regex_options` 继续只接受完整合法 header。按 `countCaptures:334-397`，消费 `(?#...)` 后清除 `ignoreNextParen`，使条件头的暂时抑制不延续至后面的真实 capture。固定源码 `posix-source-proof-xykhfxtq/data-regexp2/parser.go` 的 SHA-256 为 `915ca8a3a48179570a0dcdde9ff35ff88afe349b976c42ad418a5a366a6b5605`；以下均为实际 matcher，反斜杠为单个字符。

| 实际 matcher | 固定真值及 capture 依据 |
| --- | --- |
| `^[a-\-[][:alpha:](?n)(?-n]](a)\1$` | 合法，`-n` 前缀即时关闭 `n`，`(a)` 登记 slot 1 |
| `^[a-\-[][:alpha:](?(?#x)]](a)\1$` | 合法，comment 消费后清除 `ignoreNextParen`，`(a)` 登记 slot 1 |
| `^[a-\-[][:alpha:](?n(a))]](b)\2$` | 非法，`n` 前缀使 `(a)` 不登记，状态恢复后 `(b)` 仅登记 slot 1，`\2` 未定义 |
| `^[a-\-[][:alpha:](?n(a))]](b)\1$` | 合法，引用 `(b)` 的 slot 1 |
| `^[a-\-[][:alpha:](?n]](a)\1$` | 非法，`n` 前缀生效后 `(a)` 不登记 slot 1，与完整 `(?n)` 候选的拒绝结果一致 |

### 修正要求与保留边界

1. 产品修改限于 `_delimiters`／`_valid_regex` 的 class 扫描、capture slot 收集与引用校验及确需的共享短 helper。在非转义、非 pending-range 的内部 `[` 处识别完整 `[:`、可选 `^`、零个或多个固定 Go `IsWordChar`、`:]`。空名、未知名、数字开头和 Unicode 名均按同一规则消费；不完整、转义或含非 word 字符的片段恢复原逐字符扫描。可复用 `_regexp2_word_char`，不得误用带 numeric 分支的 `_scan_capture_name`。
2. 消费完整 token 后外层 class 继续打开，validation probe 用 `\[` 表示原 literal 并继续原 range／capture 检查。原 Rule matcher 不改，输出沿用各目标既有编码，probe 不写入 Rule 或产物；deep validator 继续消费修正后的 probe，不新增 parser。
3. 完整扫描中 subtraction 与 pending range 优先于 token 消费，包括 escaped hyphen 保留 pending range 的情况；不能仅凭 `class_hyphen` 决定。合法 subtraction 及必须最后出现的限制、首个 literal `]`、外层 negation、escaped `[` 和不完整 token 的既有边界保持。捕获预扫描须遵循固定 `scanOnly` 的 class 边界及 option 作用域，capture slot／引用校验不得直接沿用完整扫描结果。上述 29 字符候选及上表非法 matcher 须按固定真值拒绝，全部合法对照继续接受。本轮新增预扫描边界的产品修改仅限既有 `_regexp2_capture_slots` 与 `_valid_regex` 必要元数据使用及对应回归测试；已有其他 class／deep 函数保持。禁止按候选文本特征硬编码拒绝、全拒 subtraction、运行外部实现或新增通用 parser。
4. `_delimiters` 只对三种 regexp2 类型使用此规则。`URL-REGEX` 的 Python 词法、validator 及合法输入 `URL-REGEX,^[[:alpha:]()$` 保持，不用 regexp2 class 规则改变其字段边界。
5. capture 编号、named backreference、x-mode／类内 `#`、未知 escape、原 anchor／量词及 600／1,000 层深度继续校验。公开 parse／white、直接 Rule render 和真实 generate／publish／同轮及 disk YAML 依赖均须验证合法保留、非法拒绝及健康邻居。
6. native logical 保留原有字面括号平衡限制，不要求未编码的单边 `(` matcher 进入 native logical。使用 balanced 合法见证 `^[[:alpha:](][)]$` 验证 AND／OR／NOT；普通 logical 沿用现有必要编码，非法叶子使整条拒绝。DNS 继续 unsupported，不增加 Surge／QX／DNS 支持或 PROCESS white 能力。
7. 深层回归兼容声明的 Python 3.11+ 与现有 CI，使用标准库 `cProfile.Profile`，在原 600／1,000 层子进程内断言存在 `entry.code is rules._valid_deep_regex.__code__` 且 `entry.callcount > 0`。保留实际调用观察、原 `timeout=8`、recursionlimit=1000、int_max_str_digits=4300 及既有测试；不修改 `_valid_deep_regex`，不增加 skip、fallback 或依赖，不提高最低版本或修改 CI。D 必须实际验证最终实现并记录运行版本；未实际运行 Python 3.11 时明确记录该限制。D 在原 owner worktree 对每个新增根因分别完成真实 red -> 最小 green -> 全部边界 -> 自审修正与规格／功能／简化复审，再运行新 exact tree 完整 Linux suite 并创建 clean 英文新提交；主会话独立复审确认有效问题均已修正后才合并。扩大 owner 范围须先说明证据并更新共同规格／计划。

## R5：普通 hosts 的逐 alias 恢复

### 已确认现象与根因

输入 `127.0.0.1 good.example bad(,x sibling.example` 后接 `DOMAIN,neighbor.example` 时，当前仅保留 neighbor 并报告整行 `unbalanced delimiters`。期望保留 good、sibling、neighbor，并按该物理行报告 `invalid hosts domain bad(,x`。`bad,'x`、`bad,"x` 同样使整行 lexer 失败。`parse_whitelist`、真实 source／white 及生成依赖继承丢失结果。

`_source_records` 已识别 hosts 并删除首个 `#` 后的注释，却仍无条件调用 `_source_parts`，在到达现有逐 alias validator 前失败。逐 alias 恢复是 `2026-10-23-functional-regressions-design.md:34` 及 `tests/test_rules.py:750-760` 已有要求。

### 修正要求与保留边界

1. 仅调整 `_source_records`：四个原地址 `0.0.0.0`、`127.0.0.1`、`::`、`::1` 后接 SP／HTAB 时，删除首个 `#` 至物理行末并设 `parts = [line]`；仅其他行调用 `_source_parts` 并按 `end` 裁剪。继续使用现有逐 alias hostname validator，不新增 lexer 或扩大地址识别。
2. 首个 `#` 前全部合法 alias 保留，非法 alias 逐项按原物理行号 warning；后续 alias／物理行继续处理。覆盖四地址、SP／HTAB、BOM、LF／CRLF、非法逗号加括号／引号及多个非法 alias。`;`、`//` 在 hosts alias 中不成为注释，按现有 hostname 校验报告并继续后续合法 alias。
3. unsupported physical separator 检查仍在前面执行，后续 HTML document／真实 markup 继续拒绝。普通 typed、native provider、regex、ABP、其他地址及非 hosts 分隔保持原行为；注释中的 markup 和不平衡符号不影响合法邻行。
4. direct／proxy 对已识别 hosts 只给原 `hosts entry is block-only` 诊断；不逐 alias 接受其 hostname。block 与真实 parse_whitelist 保留合法 alias 的身份、顺序、规范化及覆盖关系。
5. 真实 generate／publish 的 raw source／white、同轮和非空 disk source／white 均核对六格式完整 bytes、DNS 例外及行号。含合法 alias 的输入不能因非法邻项成为全无效来源；真正全无效远端来源仍冻结及传播，健康组继续，本地 source／white 严格失败，旧六文件及 static 保持。白名单混合坏 alias 的既有 warning 容许范围不扩大到其他坏行。

## 共同的不变条件

来源白名单过滤 -> `no_resolve` -> 规范化 -> 目标投影及目标 white 过滤的顺序保持。`no_resolve` 的 `add`／`strip`／`keep` 只影响适用的目的 IP 规则，不把来源方向变为目的方向。

来源已完整覆盖，或每条剩余规范规则至少存在有效路由投影且全部有效投影均被 white 覆盖时，可以发布空正文。完全 unsupported、无可路由规则且存在不可用来源等既有冻结条件保持，冻结依赖传播至六种旧产物；健康组继续更新。缺少完整旧产物、本地 white 损坏、生成依赖存在正文解析 warning 等错误仍在发布前终止。`publish` 的替换失败恢复及 `static/` 保护保持。

上游 404 的缓存与跳过、429／5xx／超时／传输不完整的中止、gzip 与 chunked 读取、远端混合坏行的诊断、本地严格读取均须回归检查。本次没有据此增加新 fallback、重试、配置或依赖。

## 证据与验收依据

完整 scan／coverage-check 报告为 `woehc102q`；复核报告为 R1 的 `wxol2ntbu`、R2 的 `w6zj74dcc`、R3 的 `w3c6mecwg`、R4／R5 的 `wsfbdcf9c`，均保存在本次会话的 tasks 目录。DNS 以 R3 复核及后续内存设计实验为准。R2 的已确认范围是文件回读差异和固定 Mihomo 字符串匹配差异，闭源客户端运行结果仍未验证。

可复用的本地复现材料在主 checkout 的已忽略 `.tmp/functional-scan-20261023/` 下：

- `cidr-generate-verify-d_0gqrb1/minimal_regression.py` 与 `verify_generation.py` 检查 R1 的真实生成、发布及依赖边界；`cidr-options-counterproof-wrqjq911/` 保存 options、allow 及 QX identical-only 的对照。
- `asn-refutation-4htk_04c/probe_asn.py`、`asn-independent-036p7h_y/repro_asn.py` 与 `test_projection_contract.py` 保存 R2 的源格式、公开入口及依赖反例。
- `dns-memo-plan-8243301ff9724759ba7e9b2039fb1011/` 下的 `results/conclusion.json`、`results/manifest.json`、`complete/data/shadow-change.diff` 和 `scripts/probe.py` 保存 R3 的六处局部设计、全部输入输出、命令及资源结果。conclusion 与 manifest 的 SHA-256 分别为 `5bdd550157526e43901e790b9f55164f6a4f1db03f92f41867f7fd22f242a42f`、`51eaaa74345468975ab0a73be150d164e36f00f3f2d5c7d3edd57480001d1371`，本次已核对其值及 manifest 的 3,164 个文件。此证据只批准局部设计实验，不替代产品 TDD 或最终 suite。
- `posix-source-proof-xykhfxtq/`、`posix-independent-ywt60hh1/`、`posix-independent-xe929lvx/` 保存 R4 的固定源码及 hash、输入矩阵、deep probe、URL／range／capture 对照及真实发布记录。
- `hosts-counterproof-7yjtb8ee/`、`hosts-independent-uf46t53w/` 保存 R5 的非法 alias、诊断、source／white／发布与冻结对照。
- `baseline-suite-xwi2l7n0/` 下的 `suite-result.json`、`final-integrity.json`、`logs/unittest-linux.log` 保存完整 Linux 基线、10 个原 skips 及 139 文件完整性证据，旧证据只读保留。
- `generation-upstreams-wacea8ew/manifest.json` 及 `raw/` 保存 56 个唯一 URL、18,116,304 bytes；83 个配置角色中含 72 个远端角色和 11 个本地／生成角色。body 大小与 SHA-256 已核对。旧 manifest 只有耗时 `seconds`，没有逐 URL 绝对开始时刻，不补造该信息。
- `generation-gf9t9asj/acceptance-_ky64k6k/fixed-input-results.json` 记录基线固定输入生成 42 个产物、78,317,013 bytes、数量与 README 相同、无冻结及 static／主目录生产输出不变。fmz200 的两条既有 `invalid domain` warning 在 a3／a4 各出现一份。此结果按原报告环境解释，不能作为最终 Linux 或最终代码验收。

最终验收须使用 exact Git archive 在 Linux 原生 `/tmp` 完成完整 unittest，记录基线及最终 SHA／tree、archive、解释器和文件 manifest。原 139 文件及本次新增受控文件在各自测试前后 hash 不变，保留原 8 秒／内存阈值、recursionlimit 与整数长度限制，不新增 skip。固定上游输入必须在同一 Linux 解释器、相同 static／配置及固定 header 时钟下重放 `ea67234` baseline，再运行最终 tree 两轮；42 文件 bytes 和 diagnostics 必须稳定。mapped IPv6 的解释器表示差别先由同环境重放消除，不要求旧环境的 78,317,013 bytes 固定不变。

逐项检查格式、文件头、数量、排序、去重、Surge 完整文件与拆分文件、noresolve、README、static、单文件小于 100 MiB，以及 DNS 每行含 LF 不超过 65,536 UTF-8 bytes。ADB 使用其输出语法、`@@`、计数、排序及行限验收，不要求通用 parse 接受全部生成 regex。生产差异逐规则对应 R1 至 R5，不使用比例阈值。

远端完成条件为最终推送的代码 main SHA 对应 Ubuntu test 成功及有效 update 成功。`published` 时记录新增的实际发布 commit，检查其 diff 属于 42 产物及 README 的 43 个允许路径，并从该不可变 commit 核验真实 bytes。`unchanged` 时记录没有新增发布 commit，保留 update 日志，从受测事件 SHA 的不可变快照核验 42 文件、README 及与本轮目标 bytes 一致性，不把代码 commit 当作产物发布 commit 检查 diff。`superseded` 仅表示旧事件退出，继续追踪最终实际代码 SHA 的测试与有效 update，再按真实状态验收。具体执行、分工与清理步骤见实施计划。
