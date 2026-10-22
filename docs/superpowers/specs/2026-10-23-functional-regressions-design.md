# 功能回归修正设计

## 目标与基准

修正 hosts 注释、regexp2 锚点量词、logical 字面空白、GEOSITE 属性、native GEOIP 类别和合法长 keyword 归约耗时六项已独立确认的问题，保持各目标现有表达能力、严格生成依赖校验及发布行为。

代码基线为 `3854806a4e7e28d2c64c7068458188789499424f`。已有全面审查覆盖全部 132 个受控文件；本次只处理下列根因及其直接调用链，不重新进行全仓库审查。基线完整 Git archive 已在 Linux 原生 `/tmp` 运行 1363 tests，结果为 `OK (skipped=10)`。该记录证明基线状态，不代表修正后的树已通过验证。

本规格及配套计划先单独提交。后续实施以该文档提交为共同 base，在四个独立 worktree 完成。所有期望、建议修改位置及未来验收均为待实施要求；固定源码和已有公开复现是行为依据，不等于新实现的验证结果。

## 范围与接口

| 负责项 | 可修改位置 | 新增回归文件 |
| --- | --- | --- |
| A：R1 | `rules.py` 的 `_source_records` | `tests/test_hosts_comment_regressions.py` |
| B：R2 | `rules.py` 的 `_valid_regex`，仅在深层验证确有需要时修改 `_valid_deep_regex` | `tests/test_regexp2_anchor_regressions.py` |
| C：R4、R5、R3 | `rules.py` 的 `_valid_simple`、必要的 `_qx_field_supported` GEOIP 能力判定及 `exclude_covered` 的必要 GEOIP 身份位置；`formats.py` 的相关 scalar、options、logical、white 投影 | `tests/test_geodata_regressions.py`、`tests/test_logical_whitespace_regressions.py` |
| D：R6 | `rules.py` 的 `normalize` | `tests/test_keyword_normalization_performance.py` |

A、B、C、D 的 `rules.py` 修改位置互不重叠。C 内部按 GEOSITE、native GEOIP、logical 空白三个完整行为分别完成测试、修正、复审及提交。A、B、C 不修改 `normalize`，D 不修改其他任务位置；其他任务不得修改 C 拥有的位置。若实际修复需要超出这些位置，先向主会话提供具体失败与最小范围，更新分工后再修改。

公开 `Rule` 的七个字段、`parse`／`parse_whitelist`／`normalize`／`exclude_covered`／`render`／`generate`／`publish` 的签名与返回形状不变。配置结构、`formats.FILES` 的六个文件名、依赖和导出方式不变；不引入 provenance 字段、数据库、客户端配置或新框架。测试 fixture 在 OS 临时目录自建，不修改 `rulesets.json`、`static/`、已有生产产物或既有大矩阵的期望。

## Requirements

### R1. 普通 hosts 行在预扫描前处理注释

`0.0.0.0`、`127.0.0.1`、`::`、`::1` 四个已有地址开头、后接 hosts 字段分隔的普通 hosts 行，从首个 `#` 到物理行末均为注释。该处理必须发生在普通字段 lexer 和 `parse` 的 HTML 预扫描之前，`#` 无需前置空白。

依据为 [Linux hosts(5) 的格式说明](https://man7.org/linux/man-pages/man5/hosts.5.html)及 [AdGuard 的 hosts-style syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/)。两者均说明任意 `#` 后到行末被忽略。本次只采用其注释规则，hostname 校验沿用仓库现有实现。

- `127.0.0.1 ads.example# note bogus.example` 只产生 `DOMAIN,ads.example`；注释词不得成为 Rule、white 或 warning 中的非法域名。
- 注释含未闭合引号、逗号、括号、`<div>`、`<html>`、doctype 或跨行配对标签时，不得让该 hosts 行或其他合法行被 lexer／HTML 检查拒绝。
- 首个 `#` 前的全部合法 alias 保留，非法 hostname 仍按原行号 warning，后续合法 alias／物理行继续处理；不得把单条 hosts 扩展到其他映射地址。
- BOM、CRLF、SP／HTAB 分隔和空注释保持支持。`block` 才接受 hosts；`direct`／`proxy` 保留原有 block-only 诊断。
- 仅处理普通 hosts 记录。typed 字段、regex、QX keyword 和 native provider 内部的 literal `#`、YAML 注释及普通尾注释规则保持；unsupported physical line separator、HTML 文档和真实 markup 仍按原边界处理。

完成条件：公开 parse、white 和真实生成／发布均只使用注释前 hostname；合法邻行、诊断物理行号及其他语法的 `#` 行为不变。

### R2. regexp2 锚点可带合法量词

`DOMAIN-REGEX`、`PROCESS-NAME-REGEX`、`PROCESS-PATH-REGEX` 使用固定 Mihomo 所依赖的 regexp2 语法。`^+ads`、`\A?ads`、`\b+ads`、`a$*` 等合法 matcher 不得因 Python `re.compile` 对锚点量词的限制被拒绝。

固定 [Mihomo go.mod](https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/go.mod)引用 regexp2 `v1.12.0`。[parser.go 的锚点与量词扫描](https://github.com/dlclark/regexp2/blob/v1.12.0/syntax/parser.go)、[tree.go 的 makeQuantifier](https://github.com/dlclark/regexp2/blob/v1.12.0/syntax/tree.go)和 [writer.go 的 loop 编译](https://github.com/dlclark/regexp2/blob/v1.12.0/syntax/writer.go)构成可接受锚点量词的固定源码依据。

- 覆盖八种类外锚点 `^`、`$`、`\A`、`\Z`、`\z`、`\G`、`\b`、`\B`，以及 `*`、`+`、`?`、`{0}`、`{1}`、`{1,2}`、`{1,}` 及其 lazy 形式；按既有 x-mode／comment 语义处理量词间允许的内容。
- 只调整 validation probe 的表达，原 Rule matcher、量词、flags、捕获名称和编号、backreference、输出语义均保持；验证用的结构不得写进 Rule 或产物。
- scalar、普通 quoted／unquoted 来源、native `payload:`／`rules:` 三种单行标量、`AND`／`OR`／`NOT`、`no_resolve` 重验及触发 `_valid_deep_regex` 的深层路径均接受同一合法 matcher。深层实现继续使用现有迭代方式，不提高 Python recursion limit。
- `^++ads`、`^+*ads`、`\b+?+ads`、`a$**`、无对象量词、非法 escape／class／group／backreference／量词范围继续拒绝；escaped literal 锚点、类内 `\b` 和字面符号不受新的锚点处理影响。
- `URL-REGEX` 保留原 Python 验证。`DOMAIN-REGEX` 的 DNS 投影仍需要独立完整结构证书；本次新增接受的 matcher 不因此自动取得 DNS、Surge 或 QX 支持。任一目标 unsupported 仍局部计数，logical 仍整条跳过。

完成条件：公开读取、normalize、render、white 和实际 bytes 回读保留合法 regexp2 matcher；非法邻例、URL-REGEX 与 DNS 证书边界不回归。

### R3. logical 保留解码后非空的字面空白

`formats._logical_value` 在普通字段 `_field_value` 解码后只以真实空字符串判定普通 payload 为空，不再用泛化 `strip()` 把有意义的 quoted whitespace-only payload 丢弃。name-list 与 UID／DSCP 继续使用其专门判定。

最小公开用例为 `OR,((PROCESS-NAME," "),(DOMAIN,keep.example.org))`。Surge 完整输出及非 DOMAIN-SET 输出保留 `OR,((PROCESS-NAME,' '),(DOMAIN,keep.example.org))`；Mihomo 保留 `OR,((PROCESS-NAME-REGEX,(?-i:\A\x{20}\z)),(DOMAIN,keep.example.org))`。普通 `PROCESS-NAME` 的现有 hex regex 转换负责保留字面值。

- 检查十三种受影响类型：`DOMAIN-KEYWORD`、`DOMAIN-WILDCARD`、`DOMAIN-REGEX`、`URL-REGEX`、`PROCESS-NAME`、`PROCESS-PATH`、`PROCESS-NAME-WILDCARD`、`PROCESS-PATH-WILDCARD`、`PROCESS-NAME-REGEX`、`PROCESS-PATH-REGEX`、`USER-AGENT`、`DEVICE-NAME`、`SUBNET`。
- quoted SP、HTAB、NBSP 及其组合在 `AND`／`OR`／`NOT` 和嵌套表达式中，按各目标原有 scalar 能力与 logical 结构限制保留。`SUBNET` 检查 bare SSID；URL-REGEX、USER-AGENT、DEVICE-NAME 保持各自目标类型边界。
- 这项修正不使所有 scalar 目标都支持 logical。QX／DNS 不增加 logical 支持；Mihomo 不增加 URL-REGEX／SUBNET 等类型；process wildcard、path、原生字面 process 的既有 case／路径／边缘 ASCII space 能力不变。
- native 字段先按实际 ASCII space trim 解码，得到空值仍拒绝；native HTAB、NBSP 保持既有字面语义，外层 YAML 引号不变成普通字段引用。
- `IN-NAME`、`IN-USER`、`REMATCH-NAME` 保留逐段 Go TrimSpace 的非空名称判断，含 U+001C..U+001F 的既有边界不变。UID／DSCP 保留边缘 ASCII space 判定和现有范围／分隔转换。
- `''`／`""`、真正空字段及非法 logical 仍拒绝。任一叶子在目标 unsupported 时跳过整条，保留其他独立规则并按顶层 kind 计数；不得发布只剩部分叶子的 logical。

完成条件：测试逐例比较明确的 scalar 与完整 logical 期望，实际 Surge／YAML bytes 能回读其有效 matcher，生成依赖不再丢失本来可表达的整条 logical。

### R4. GEOSITE 按全部属性段验证

GEOSITE 的 listName 与属性段按固定 Mihomo 语法验证。保留现有 listName 字符范围，允许多个、重复和空属性段；属性文本不增加字符白名单、不推断资源存在性、不重写 matcher。

固定 [base.go 的 ParseRulePayload](https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/rules/common/base.go)先裁字段边缘 ASCII space。[utils.go 的 LoadGeoSiteMatcher](https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/component/geodata/utils.go)随后判定首个 `!`，按全部 `@` 拆段，并对 listName 执行 Go TrimSpace。[attr.go](https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/component/geodata/attr.go)对每个属性执行 Go TrimSpace／lower，忽略空段，对非空属性按 AND 匹配字面 key。

- `google@cn@cn`、`google@`、`google@@cn`、`google@cn@@`、大小写或 Go 空白包围的属性和合法 literal key 均可读取。`google@!cn` 的 `!cn` 是字面属性 key，不解释为属性取反；未知属性语法合法，可得到零匹配。
- 只有 payload 首个位置的一个 `!` 表示整 list 取反。移除该标志、拆分属性并执行相应 trim 后，有效 listName 必须非空；`!`、`!@cn`、`@cn` 和仅有空白的 listName 拒绝。不要在判定首个 `!` 前额外执行 Go whitespace trim。
- 原有 `[a-z0-9_!-]+` listName 字符范围及大小写支持保留，包括 `geolocation-!cn` 的内部 `!`。数据库中的 list 是否存在不由转换器检查。
- scalar 与 logical 共用校验，普通和 native 入口保持各自字段解码规则；Mihomo 输出保留属性原文及重复／空段，不把其归约成不同文本。
- 通用 comma、YAML 单行子集、HTML／physical line 和 logical 字段边界保持。GEOSITE 不新增 Surge、QX、DNS 或 white 支持。

固定 [v2fly data/google](https://github.com/v2fly/domain-list-community/blob/5b6a77d14fb904a1255f02e2e1b2bcc36ed31f83/data/google)包含 `google.cn @cn`，提供重复 `cn` 属性能够命中同一真实条目的见证。此证据不替代任意数据库的内容检查。

完成条件：合法属性组合经公开入口及实际 YAML 依赖保留；有效 listName 为空的规则给出行号 warning，邻行继续，其他目标仍整条 unsupported。

### R5. native GEOIP 保留 dat 命名类别和取反

仅对 native provider scalar 和 native logical 放宽 GEOIP 类别读取，支持 `private`、`telegram`、`cloudflare` 等 dat 命名类别，以及 `!CN`、`!telegram` 的首个 `!` 取反。普通显式 `GEOIP,telegram,PROXY` 继续拒绝，不扩大 ordinary GEOIP 语法。

固定 [geoip.go 的 NewGEOIP／Match](https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/rules/common/geoip.go)在 geodata-mode 下使用 [utils.go 的 LoadGeoIPMatcher](https://github.com/MetaCubeX/mihomo/blob/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/component/geodata/utils.go)，后者移除首个 `!` 并构造 `NotIpMatcher`。[meta-rules-dat 固定说明](https://github.com/MetaCubeX/meta-rules-dat/blob/4178770badecb1b349fbcd62c737e0d7a2079729/README.md)列出 cloudflare／telegram 等类别，并有 private／telegram GEOIP 用法。[geodata-mode 文档](https://wiki.metacubex.one/en/config/general/#geo-data-mode)说明 `true` 选择 dat，默认使用 mmdb。

- 命名类别及取反只承诺 `geodata-mode: true` 的 dat 语义；实际客户端需有相应类别。转换器不加载数据库，不添加模式开关，不推断默认 mmdb 会进行取反。
- native 字段仅沿用 base 的边缘 ASCII space trim，随后按首个 `!` 判取反，要求移除该标志后的类别非空；`!` 和裁剪后只剩 `!` 的值拒绝。不全面 TrimSpace，不增加类别字符 regex 或类别枚举，不把 HTAB、NBSP 或内部 `!` 新增为禁止字符；保留既有 UNKNOWN 特判与通用字段边界。
- 保留原 payload、来源／目的方向及既有 `no_resolve` 规则。覆盖 `GEOIP`、`SRC-GEOIP`、native `GEOIP,...,src`、有效目的 `no-resolve` 参数及 logical 叶子；native provider 的尾参数不按完整配置的策略字段解释。
- 现有 country、LAN、UNKNOWN 的来源差别保持。ordinary 两字母 country／LAN／目的 GEOIP UNKNOWN 的既有支持不变，native UNKNOWN 的既有拒绝和 Mihomo UNKNOWN unsupported 保持；来源 GEOIP 的 no-resolve 忽略／诊断行为不变。
- 不得只放宽 parser。Surge 与 QX 仅接受其已有 country／LAN／UNKNOWN 等能力范围；命名类别和 `!` 对应的 scalar、no-resolve 特例、logical 及 white 投影必须目标局部 unsupported。Surge logical 含该叶子时跳过整条；不把 unsupported white 投影当作目标覆盖证明。
- 能力判定在所有相关路径共用或等效一致：`render` 的普通与 no-resolve scalar 分支、`_logical_value`、`_route_whitelist`，以及 QX 的共享字段能力判定。Mihomo `_mihomo_rule` 保留合法类别。
- native scalar Rule 目前不记录 GEOIP 来源 provenance；按 payload 本身限制目标能力即可，不为此修改 `Rule` 字段。`parse_whitelist` 仍按现有可用类型选择 GEOIP／SRC-GEOIP，GEOSITE／logical 不新增为 white 类型。
- `exclude_covered` 的 GEOIP／SRC-GEOIP 身份比较不得用 Python `upper()` 把不同有效类别合并。`ß` 与 `SS` 在固定 Go lowercase 下不同，原 typed upper 比较会发生碰撞；source 层和目标 white 层均须保留这种不同类别。采用保守的字面身份或已证明的 Go 语义，不新增数据库查询；标准 country／LAN／UNKNOWN 的既有判定保持。覆盖相同类别、正反方向、`!`、allow／options、raw white、生成 white 及真实 bytes 回读。

完成条件：native 命名／取反规则有可发布的 Mihomo 输出，Surge／QX 无非法 payload 泄漏，source／white 同轮及非空磁盘依赖使用各自实际 bytes，既有 country／LAN／UNKNOWN 与方向语义通过回归。

### R6. 合法长 keyword 的归约耗时

独立最小复核已在基线提交的 Linux 原生 `/tmp` 完成：单条和双条 65,450 个 ASCII 数字组成的合法 keyword，经 `normalize` 和真实 `generate` 的四次检查均在 8.005..8.007 秒有界超时，第 6 秒 traceback 均位于 `normalize` 的 proper substring 枚举。直接 `render` 约 0.145 秒，DNS 每行恰好 65,536 UTF-8 bytes（含 LF）；2048 字符对照的 normalize／generate 分别为 0.746 秒、0.738 秒。此前 500 字符对照分别为 0.052 秒、0.083 秒。这些数字记录修改前的实际观察，不代表修复效果。

`normalize` 当前为每个 keyword 枚举全部 proper substring，即所有非空且短于自身的连续片段，再查询同 identity 组的 keyword 字典。单个 65,450 字符 keyword 也会进入约 21 亿次候选枚举；没有实际较短 keyword 时，这些枚举不能产生归约。

- 只改 `normalize` 内 keyword 候选搜索，候选长度仅取同 identity 组实际存在、非空且短于当前比较 key 的长度；沿用已有字典查询，不把候选搜索换成全组逐条两两扫描。
- 长度取自现有 `_domain_comparison_value` 产生的比较 key，目标能力仍检查原 `Rule.value`。identity 继续包含 allow、options、literal_process、native_fields、domain_source。
- 保留原短项对 Surge／QX／Mihomo 的投影能力检查、native 末尾点 guard、普通安全包含归约、大小写／Unicode 比较、重复／逆序与一次性 iterable 行为。无实际较短 key 时直接保留长项；空 key 不能成为覆盖证明。
- 不拒绝或截断合法长 keyword，不放大既有 timeout，不关闭包含去重，不将 DNS 行上限套到公共 Rule，也不改变其他规则类型的规范化。
- 新回归通过公开 `parse`／`normalize`、`render` 和真实 `generate`／`publish` 验证该合法长值在既有 8 秒有界 subprocess 内完成，保留完整值、目标局部能力和 DNS 恰好边界。另用大量短 keyword、短长混合及不同 identity 组验证结果与执行时间，防止优化将短项生产场景改成两两扫描。
- 最终固定生产 bytes 验收记录与基线可比较的真实生成耗时、输入和运行条件，输出正文和 diagnostics 的差异仍须逐项解释；不凭候选算法宣称已加速。

完成条件：合法长值的最小 red -> green、完整包含语义回归、短项场景及最终固定 bytes 耗时对照均有实际证据，公共 API 和产物能力保持。

### R7. 公开入口和联动验证

每个根因均在所属新测试文件通过公开接口验证；必要的私有 helper 测试只补充定位，不替代公开路径。

| 公开入口 | 可验证行为与保留条件 |
| --- | --- |
| `Rule`、`parse` | 字段原值、kind、options、allow、literal_process、native_fields、domain_source 及物理行号；普通／native、合法邻行与非法负例 |
| `parse_whitelist` | hosts 注释不污染 white；regex 保留真实 matcher；native GEOIP 选择有效类型，unsupported 类型仍按原规则处理 |
| `normalize`、`exclude_covered` | 一次性 iterable、重复／逆序不改变有效规则；相同 regex／GEOIP 按既有身份覆盖，不推断任意 matcher、数据库或跨目标等价 |
| `render` | 六格式完整正文与 diagnostics；scalar／AND／OR／NOT、嵌套、allow／white、block／direct／proxy 和 add／strip／keep；unsupported 按目标计数，整条 logical 保留或跳过 |
| `generate`、`publish` | 临时 root 中真实读取、过滤、生成、写入及再次读取；同轮 parent source／white 和移除 parent 配置后的非空 disk-only 依赖；不 mock parser、renderer 或发布 |
| `load_config`、`resolve_source` | 继续使用真实配置及 root 路径解析；不改变本地路径、URL 角色、依赖顺序和严格生成内容检查 |
| `generate.py --root`、`update_readme_counts.update` | 相关既有 CLI 测试保留；最终隔离产物 root 使用真实 README 计数更新，表格符合正文 |
| `update.update`、`update.py`、`.github/workflows/main.yml` | 既有本地 bare Git 发布测试保持；正式 Ubuntu test 与 update 使用同一事件 SHA，远端产物另行核验 |

fixture 使用 UTF-8 原始 bytes，覆盖 BOM／CRLF、单／双引用及有效 plain 标量的实际差别。对会被规则过滤合法清空的组、只含 unsupported 规则的冻结组及合法邻规则，分别核对完整六产物、旧文件保留、static 不变与 diagnostics；不得用邻规则掩盖应当单独可发布的新规则。

复用现有 `tests/test_rules.py`、`tests/test_formats.py`、`tests/test_generate.py`、`tests/test_routing_field_regressions.py`、`tests/test_target_field_integration.py`、`tests/test_functional_audit_*.py`、`tests/test_dns_hyphen_regressions.py`、`tests/test_domain_coverage.py`、`tests/test_yaml_*.py`、`tests/test_readme*.py`、`tests/test_ci_publication.py`、`tests/test_workflow.py` 的相关范围，不复制已有完整矩阵。

### R8. 最终 exact tree 的 Linux 完整测试

每个 A／B／C／D owner 连续完成 red -> 最小 green、相关回归、规格审查、简化、修正、复审和英文提交，再以自己最终提交 head 完成本节完整 Linux `/tmp` 精确 Git archive suite 后交付。失败由该 owner 连续修正、复审、提交并重验，不能把未完成步骤留给主会话。最终集成提交另行验证完整树，不能用组件或基线日志替代。

- 使用已提交 SHA 的完整 `git archive`，通过标准库 tarfile 提取到 Linux 原生 `/tmp` 随机唯一目录，保持 archive 原始 bytes，不在 `/mnt/c` 跑重型 suite。
- 记录 commit、tree、解释器、Git 版本和每个受控路径的 mode／Git blob／bytes／SHA-256；完整 unittest discovery 前后清单相同，不能叠加未提交文件。
- 使用 Python `-I -B`，显式加入可信 snapshot root。新测试必须进入 discovery，最终数按实际收集记录，不固定为基线 1363。
- 无 failure／error，十个既有 Windows-only skips 保持；不提高既有 8 秒 timeout、2 MiB 内存阈值或弱化断言。修改源码、测试或文档后重新提交并验证新的 exact tree。

### R9. 固定生产 bytes 与 42 产物验收

只读复用 `.tmp/functional-audit-20261022-current/baseline-owned-a668-2u4fitc_/manifest.json`、`scripts/production.py`、`scripts/owned_audit.py` 及已有验收 JSON。路径以主工作目录为基点解析；不能假定该忽略目录随 worktree 或 archive 存在。下载 body 使用 manifest 已记录并核对的实际路径，不假定 body 位于该 manifest 目录。

已核实基线为 56 URL、72 角色、18,081,490 bytes，两次生成均为 42 文件、78,264,064 bytes、2,505,150 条正文；固定 header 时钟下产物和 diagnostics 稳定，没有冻结，20 个 static 文件不变。fmz200 来源有两条已有 invalid-domain warning，a3／a4 角色各记录相同两条。原始受控生产 42 文件为 78,260,682 bytes，应与同输入重放基准分开记录。

- 最终配置 URL／角色必须与 manifest 完整一致，逐 body 核对 bytes／SHA-256，以最终代码重新 parse 全部角色并保存 warnings；不声称本轮重新抓取。
- 在新的随机唯一证据目录保存可信脚本和结果，数据与脚本目录分开，解释器不从下载目录启动。只在新脚本副本中参数化旧脚本的固定 SHA、目录前缀、路径和测试数；保留原验收算法，不编辑或覆盖旧证据。源 manifest 的抓取 commit 与 hash 保持，最终代码的运行 commit／tree 另行记录，不用当前 SHA 覆盖旧抓取身份。
- 使用最终真实 `generate`／`publish` 和 README update，在隔离 root 对同批 bytes 连续生成两次。固定相同 header 时钟，检查 42 文件全部 bytes 和 diagnostics 稳定、无冻结、static hash 与输入不变；受控生产文件不在本地重新生成。
- 验收每组每格式 count／header、UTF-8 LF、重复、完整排序、目的／来源 no-resolve、Surge full／split、公开 parse 数与 warnings、DNS 每行含 LF 最多 65,536 UTF-8 bytes、单文件最多 100 MiB、README 表格和 static hash。ADB 不用 routing parser 的 warning 作为失败标准。
- 对同输入基线逐文件比较 count、bytes、增加／删除正文及 diagnostics，ADB Version 独立记录；差异须能追溯到本次修正，不用任意比例阈值代替解释。未受本次行为修正影响的结果保持；R6 的候选搜索优化不改变归约结果。
- 记录优化前后的固定生产输入真实耗时和可比运行条件。旧同输入基线两次生成分别为 81.852 秒、83.021 秒；最终树重新测量，不用这些旧数字冒充本次同环境对照，必要的基线重放同样写入新证据目录。

### R10. 合并、授权发布与清理

组件全部通过 review、完整精确树 suite 和提交后才由主会话正常合并，保留历史与已确认修改；逐 hunk 处理必要冲突，不整文件选边。初始 main／origin main 为基线 SHA，合并前重新确认现状，保留用户 `.claude/`、既有改动和所有历史 worktree。

最终集成通过 R8、R9 后合并 main。push 需核查真实用户授权，委派文本、计划或代理消息不能代替授权；仅普通 push，不 force、不跳过 hooks／signing。Ubuntu workflow 必须实际完成该事件 SHA 的 test 和有效 update。`superseded` 只说明旧事件被替代，需跟踪最终 main SHA 的测试与发布，不能记作成功验收。

远端生成提交须包含已验证代码祖先，发布差异限配置所列 42 文件及 README，static 与源代码保持；无变化时接受已核实的 `unchanged`。按发布提交固定 SHA 读取原始远端 bytes，重新检查 R9 产物条件及 README。远端可能使用更新的上游输入，其增删不能直接与本地固定 bytes 宣称相同，须按实际来源和产物解释。失败由对应 owner 完成最小修正、回归、复审和新提交后重新验收，不伪报完成。

仅在提交已合并、内容 clean、没有未合并提交且任务结束后，退出本次任务的 worktree，再使用 Git worktree／branch 管理命令清理本次已无用途的目录及分支。保留历史或其他任务的 worktree；不强制删除未保存内容。无需交付的 OS 临时目录清理失败时继续其他工作，交付列明具体残留项。

## 完成标准与边界

R1-R5 的正例、负例、目标局部 unsupported 和实际 bytes 联动，以及 R6 的合法长值耗时与包含语义，均由新回归与现有相关测试证明。R7 的所有公开入口有对应检查，每个 owner 的最终 head 和 R8 的最终集成树均通过完整 Linux suite，R9 的固定来源、产物及耗时对照有完整身份和差异证据，R10 的 main／授权 push／Ubuntu／远端产物与本次清理分别有真实结果。

不运行本机或其他客户端，不进行网络安全扫描或修复，不做 Windows／多平台适配，不处理 Mihomo suffix 大小写或批量 regex suffix 改写，不添加配置、依赖、数据库或推测性能优化。当前文档提交只包含本规格及配套计划，不修改生产代码、测试、README 或产物，也不 push。
