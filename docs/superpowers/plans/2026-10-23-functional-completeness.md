# 功能完整性扫描、TDD 修复与发布计划

## 目标与执行边界

依据[功能完整性规格](../specs/2026-10-23-functional-completeness-design.md)，完成五项确认问题的 TDD 修复、Linux 与固定输入验收，再合并本地 main、普通 push 并核查远端实际发布。五项为 R1 CIDR white 完整并集、R2 native padded ASN 目标投影、R3 DNS alternation 预算及资源、R4 regexp2 POSIX-looking class 边界、R5 hosts 逐 alias 恢复。新增确认问题须先补充规格和计划。

产品基线为 `ea67234ae739af33fd5f7ecfa197213183eaeb28`，tree 为 `752c5358aa961ed4ce74f80d245e23489426ee5b`。全部 scan、coverage-check 及五项独立复核已完成；139 文件无剩余缺项。Linux 基线为 1416 tests、0 failures、0 errors、10 个既有 Windows-only skips，日志 1346.911 秒、外层 1347.001 秒，139 文件前后 hash 不变。文档提交只完成规格和规划，产品实施、最终 tree 验收及远端发布尚未完成。

沿用规格的禁止项、公开接口、配置和 static 保护，不增加批量使用 regex 改写 suffix 规则的流程。当前不新增依赖、配置、exports、来源标记、通用抽象或解析器，不增加 fallback。README 的两处必要说明由文档 owner 在共同文档提交中完成，五个修复 owner 均不编辑 README；数量表保留，最终产物计数由原发布流程处理。

## U0：扫描覆盖与实施依据

**已完成证据：** `woehc102q` 的 completeness 逐项覆盖下表及全部 139 受控文件；routing-formats 的空报告已由 coverage-check 补查 42 种 scalar、56 case、594 mode 组合。R1／R2／R3／R4-R5 分别由 `wxol2ntbu`／`w6zj74dcc`／`w3c6mecwg`／`wsfbdcf9c` 复核。DNS 资源与最小设计以规格列出的后续 `dns-memo-plan-8243301ff9724759ba7e9b2039fb1011` 完整证据为准。

| 全部检查范围 | 对应代码、测试与输入 | 必须核对的行为 |
| --- | --- | --- |
| 输入语法与数据身份 | `rules.py`；`tests/test_rules.py`、`tests/test_native_domains.py`、`tests/test_functional_audit_rules.py` | 普通混合输入、hosts、DNS、DOMAIN-SET、native payload／rules、外层引用、policy／options、无效行诊断、全部受支持 kind |
| 域名及 regex | `rules.py`、`formats.py`、`_unicode15.py`；domain／wildcard／regex／keyword／geodata 相关测试 | Unicode／byte／root／case、目标可表达范围、结构证书、深层表达式及原有限时、R3／R4；排除已知 suffix 大小写，不增加批量使用 regex 改写 suffix 规则的流程 |
| 去重与 white | `exclude_covered`、`normalize`、`_route_whitelist`；`test_domain_coverage.py`、`test_yaml_coverage.py`、`test_functional_audit_coverage.py` | 来源过滤顺序、完整覆盖和反例、allow／options／来源身份、IP 方向与地址族、最终 matcher 去重、R1 与 R2 |
| 多客户端输出 | `formats.py`；`test_formats.py`、`test_yaml_output.py`、`test_functional_audit_projection.py`、DNS／routing／target-field 回归 | 六格式各自类型、logical 整条处理、noresolve、排序、完整／拆分 Surge、DNS 例外与行限、实际 bytes 回读 |
| 配置与来源选择 | `sources.py`、`rulesets.json`；`test_sources.py`、`test_generator_alias_regressions.py` | 七组、sources／white 全部角色、路径与格式选择、缓存、依赖先后、配置字段不变 |
| 上游读取与异常 | `generate.fetch_https` 及 `generate` 的读取路径；`test_generate.py`、`test_functional_audit_transport.py`、`test_chunked_ows_regressions.py` | 404 缓存／跳过、429／5xx／超时／不完整响应中止、gzip／chunked、空／HTML／坏编码、远端混合坏行、本地严格失败 |
| 生成与文件发布 | `generate.py`／CLI；`test_functional_audit_integration.py`、`test_target_field_integration.py`、static／生成依赖相关测试 | 同轮／disk source 与 white、合法空正文、冻结传播、健康组继续、缺少旧产物报错、替换失败恢复、输入 hash 不变 |
| README、入口及 CI | `README.md`、`index.html`、`update_readme_counts.py`、`update.py`、`.github/workflows/main.yml`；readme／workflow／CI publication 测试 | 下载路径与用途、42 数量、43 发布路径集合、事件 SHA、superseded／unchanged／published、普通 push 竞争及失败可见性 |
| 生产输入与规模 | 配置中的 83 个角色、56 URL 固定 body、全部 static、42 文件 | 每个角色均解析及生成、诊断归因、格式／数量／大小／去重／排序／稳定性、实际 static 不变 |

文件级覆盖已按实际清单核对：7 个核心 Python 文件、34 个测试、2 个配置／workflow、2 个 README／入口、28 个历史规格／计划／性能记录、20 个 static、42 产物、1 个忽略规则及 3 个许可文件，合计 139。许可文本已阅读，未作法律合规判断。全部生产 caller、fixture helper 及输出均有检查记录，无需重复全仓扫描。

候选证据保留实际输入、独立期望、结果、公开调用路径及反例。五项修复范围以最终规格为准；R2 不把闭源 padded ASN 接受方式写成实测，R3 设计实验不替代产品回归。发现新候选时复核后由文档 owner 更新两份文档，再按依赖及范围追加工作单元。

**实施起点检查：** 核对最终共同文档 commit、上述报告和规格中的证据路径，以及 `baseline-suite-xwi2l7n0/suite-result.json`、`final-integrity.json`、完整日志。确认五项均已写入共同提交后启动并行 owner；不重跑初始完整 suite，不覆盖旧证据。

## 工作所有权与共同检查流程

共同文档提交确定后，从该同一提交并行创建 A 至 E 的五个独立 worktree，使用可用的带 `[1m]` 后缀模型。各 owner 开始时记录 worktree、branch、HEAD／tree、初始 status 及与共同 base 的关系。不得编辑主 checkout、旧 worktree 或其他任务文件。

| owner | 唯一写入范围 | 所有权说明 |
| --- | --- | --- |
| A，CIDR | `rules.py` 的 `exclude_covered`；新增 `tests/test_cidr_whitelist_union.py` | 不修改其他 helper、formats、旧测试或 README |
| B，ASN | `rules.py` 的 `_ordinary_field_supported`；`formats.py` 的 Surge noresolve guard；新增 `tests/test_asn_projection_regressions.py`；三份旧测试的准确 padded 投影预期 | 旧测试为 `test_functional_audit_rules.py`、`test_generate.py`、`test_functional_audit_coverage.py`，不改 parser 或生成依赖校验 |
| C，DNS | `formats.py` 的 `_dns_regex`；新增 `tests/test_dns_alternation_budget.py` | 仅调用内三处 cache、两个 tuple caller 和分支 reset，不修改巨型旧 DNS 测试或 render |
| D，POSIX-looking class | `rules.py` 的 `_delimiters`／`_valid_regex` 及确需的共享短 helper；新增 `tests/test_regexp2_posix_class_regressions.py` | 可复用 `_regexp2_word_char`，不改 `_valid_deep_regex`、DNS 或其他 owner 的位置 |
| E，hosts | `rules.py` 的 `_source_records`；增补 `tests/test_hosts_comment_regressions.py` | 不修改通用 lexer、其他测试或 hostname validator |
| 文档 owner | 两份规格计划、README 两处必要行为说明 | 先完成共同文档 commit，五个修复 owner 不改文档 |
| 集成 owner／主会话 | 合并已完成提交、集成验证及发布证据 | 不代替 owner 完成未完成修复；生产发布沿用 update 的路径范围 |

`rules.py` 与 `formats.py` 中各 owner 的产品修改位置互不重叠。禁止修改其他 owner 的 hunk 或 tests；实际需要扩大范围时先汇报证据、更新 plan 及所有权，再继续。

每个 owner 按 vertical TDD 连续完成：一次增加一个失败回归 -> 确认因目标缺陷判红 -> 最小修复判绿 -> 增加并通过保护边界 -> 规格／功能／简化审查 -> 修正与复审 -> 相关测试及自己最终 exact tree 的完整 Linux suite -> 英文 commit 和 tree 身份核对。不得把未完成的测试、修复、审查或 suite 交还主会话。返回可合并 clean 提交及最终 SHA／tree／日志／manifest；若提交后修改，重新提交并重验新的 exact tree。

后台 workflow 完成后主动报告；阻塞后续步骤时等待通知，不通过 sleep、读取输出文件或反复状态查询轮询。遇到新的独立且不冲突任务时按依赖新增 workflow，不让其等待无关任务。

## U1：CIDR white 完整并集覆盖

**依赖：** U0 与共同规格／计划提交。依据规格 R1，owner A。

**修改与复用：** 只在 `exclude_covered` 收集网络后按方向及实际地址族使用 `ipaddress.collapse_addresses`，保留原查询及非 IP 分支。参考 `normalize` 现有标准库调用，不把 `normalize` 应用于整份 white。所有新增 fixture 由测试在临时 root 中创建，复用现有 unittest／固定时钟／六格式检查方式。

**先取得失败证据：** 在新增测试中通过真实 `parse`、`parse_whitelist`、`exclude_covered` 调用断言 `/24` 被两个 `/25` 完整覆盖时删除。使用独立的地址范围／小网段集合断言说明覆盖成立，不能用被测算法产生期望。基线必须因保留 `/24` 而失败，不能因 fixture 或导入错误失败。

**回归场景：**

1. IPv4 `/24` 的两个 `/25`、IPv6 `2001:db8::/32` 的两个 `/33`，目的与来源方向分别删除；generic IPv6 `IP-CIDR`／`IP-CIDR6` 别名互通。
2. 两个 `SRC-IP` host 覆盖 `/31` 或 `/127`；重复、重叠、相邻多级网段、逆序及一次性 iterator 结果一致，检查 `/0` 与 `/32`／`/128` 边界。
3. 只覆盖一半、不相邻、恰好缺一个地址、source 更宽时保留完整 source；跨方向、两半分属不同方向、跨地址族及相同整数值的异族网络不合并。
4. 未删除 source 的对象身份和顺序、`allow=True`、空 white、scope 拒绝、ASN／GEOIP／域名／regex／IP-SUFFIX 及 logical 不变；不删除或重写 logical 叶子。
5. 用真实 render 检查 `block/direct/proxy × add/strip/keep`，目的规则分别含／不含 `no-resolve`，来源 IP 不增加 QX／DNS 能力。核对受影响文件正文和 `whitelist-covered` 诊断。
6. 外部 white 一半有效、一半带 unsupported／接口 options 时不新增目标覆盖；直接 API 忽略 options、parse_whitelist 移除 options、输入 allow 清理受支持接口参数的原语义保持。
7. 直接构造 `domain_source='mihomo'` 的 IP white 时，Surge／Mihomo 可按各自筛选结果求并集，QX 继续 identical-only，两个 `/25` 不删除 QX `/24`；真正相同 matcher 的原行为保持。
8. 真实 generate／publish 比较 raw white、生成后 white、相同非空 bytes 的 disk white；合法范围内表示等价时过滤一致，磁盘 bytes 与 generate 返回值一致。至少一个代表性 fixture 再通过公开 `generate.py --root` CLI 核对实际发布及退出码。
9. 完整覆盖后正常替换旧六文件，同轮空 source／white 可继续生成；移除父组后 disk-only 空输入仍拒绝。混入完全 unsupported 或不可用来源时保持既有冻结判定、依赖冻结及健康组发布，缺少旧文件仍终止。

**验证与提交：** 新文件及相关 `WhitelistTests`、`IPv6ScopeAuditTests`、formats CIDR／options／allow、generate 合法空／冻结用例全部通过；按 U4 方法在 Linux 原生 `/tmp` 运行本 owner exact archive 的完整 suite，检查 diff 与规格一致且无整体 white normalize，英文提交后返回 SHA／tree／clean status 及证据。

## U2：padded ASN 的共享目标能力判断

**依赖：** U0 与共同规格／计划提交，可与 U1 并行。依据规格 R2，owner B。

**修改与复用：** 在 `_ordinary_field_supported` 拒绝多字符首位为 `0` 的 `IP-ASN`；Surge `no-resolve` 分支补同一 helper 调用。保留函数现有 HTML／process／regex 条件；`literal_field=True` 只延续其原用途。现有 `_logical_value`、`_qx_field_supported`、`_route_whitelist` 通过 caller 自动共享规则。`normalize` 的 helper 调用只用于 keyword，不改变 keyword 去重。

**先取得失败证据：** 新增公开 parse／render 回归，native `0013335` scalar 与 NOT 在 YAML 保留原值，Surge／QX 相应投影为空并计 unsupported。基线必须因泄漏 padded 投影而失败。另用真实 generate／publish 证明 `parent/fin.txt -> child/fin.yaml` 的旧数值改写路径，修复后改为合法空依赖。

**回归场景：**

1. native `payload:`／`rules:`，plain／single-quoted／double-quoted 标量，`00`、`0013335`、长全零和长前导零正数；scalar、AND／OR／NOT、嵌套 logical 在 YAML 原样保留。
2. 所有 purpose／mode 组合，已有／没有 `no-resolve`，裸 scalar 与 Surge noresolve 特例均被同一 helper 限制；logical 任一 padded 叶子使 Surge 整条跳过，其他叶子不单独输出，QX logical 不新增支持。
3. 直接 `Rule` 构造的不同 `domain_source`／`native_fields` 组合得到同一字段能力判断；特别保护 native scalar 实际为 `surge`／false 的情况。
4. 普通 `00`、`0013335`、`AS0013335` 及其 logical 仍规范化；canonical `0`、正整数和 uint32 上界保留，超界、内层引号及原无效输入校验不变。
5. `SRC-IP-ASN`、`src`、方向、来源 noresolve 警告、`UNKNOWN` 及 allow 身份不变；同值 native white 可删除 padded source，不同 padded／canonical 值不互相覆盖。
6. 通过 render 的外部 white 与输入 allow 检查 Surge／QX 不借 padded white 删除 canonical source，Mihomo 保留原有相同字符串覆盖。不用 mock helper 代替真实调用。
7. parent 仅含 padded scalar 或 logical 时，YAML 非空，Surge／QX 正文合法为空；child 读取本轮 `fin.txt` 清空，读取 YAML 保留原值。发布后非空 YAML disk source／white 保持身份，disk-only 空 Surge source／white 仍严格拒绝，不从 YAML 补回。至少一个 parent／child fixture 再通过公开 `generate.py --root` CLI 核对发布 bytes、diagnostics 及成功／拒绝退出码。
8. 有 canonical 邻居时只删除不支持投影，输出 count／unsupported count 相应变化；没有有效路由投影的规则不计完整 white 覆盖。真实 publish 仍保持 static 和输入 bytes。
9. 保持深层 logical 的原 timeout、递归／整数长度限制及全 unsupported／坏本地 white／不可用来源的发布边界。

**精确更新旧测试：**

- `tests/test_functional_audit_rules.py` 的 `DecimalASNAuditTests.test_generate_decimal_white_native_identity_six_products_and_same_round_disk_dependencies`，当前约 2525 行。只从 Surge／QX 正文移除 native `00`／`0013335`，调整其 headers 与相关诊断；YAML、普通 canonical `13335`、source ASN、邻居和 DNS 预期保留。
- `tests/test_generate.py` 的 `ConstructorGenerateTests.test_constructor_generated_whitelist_and_disk_keep_direction_and_literal_asn`，当前约 1664 行。修正三种路由投影及 unsupported 诊断，保留 YAML 和 DOMAIN-SET 的现有身份。
- `tests/test_functional_audit_coverage.py` 的 `test_generate_raw_white_preserves_six_outputs_neighbors_and_actual_dependency_bytes`，当前约 199 行。修正 bodies、headers 和 `supported`／diagnostics 中 padded ASN 的目标集合；其 YAML 回读及 raw white 断言保留。

全仓检索 padded ASN 的其他断言并核对实际用途。已查到 `tests/test_rules.py`、`tests/test_formats.py`、`tests/test_functional_audit_projection.py` 及上述旧测试文件中的其他位置主要保护 parse／normalize／YAML 身份，不能机械替换其 `00` 或修改 fixture 使测试绕过问题。若发现额外错误投影预期，先记录证据并更新所有权范围，再精确修改。

**验证与提交：** 新文件、全部 `DecimalASNAuditTests`、三份旧测试相关类、constructor／logical／white／依赖及关键词字段回归通过；完成本 owner exact archive 的完整 Linux suite、规格／功能／简化复审后英文提交，返回 SHA／tree／clean status。只改 helper 与 guard，禁止改 Rule 字段、parser 或生成依赖验证。

## U3：DNS、regexp2、hosts 及五项集成

### U3.1：DNS alternation 预算与调用内复用

**依赖与 owner：** U0 及共同文档提交，owner C；与 U1、U2、U3.2、U3.3 并行，依据规格 R3。

**修改与复用：** 只在现有 `_dns_regex` 中给 `lower_preimage`、`dns_runes`、`dns_concat` 添加局部 `@cache`，两个 `dns_concat` caller 传入 `tuple(nodes)`，`|` 分支清空 nodes 后重置 `dns_sizes[-1]`。不移动 `dns_choices` 去重，不缓存完整未解析 regex，不新增 helper／全局 cache／分支阈值，不修改三消费者的 caller。复用现有 `cache`、证书和预算检查。写入前核对规格中的设计 diff、conclusion／manifest hash 和真实实验结果；实验脚本只作只读参考，产品测试运行实际实现。

**先取得失败证据：** 在 `tests/test_dns_alternation_budget.py` 经 parse／render 检查 `\w` 单分支与四重复分支的 DNS 正文逐字节相同；分别增加 block、public allow、真实 `parse_whitelist` 的回归。基线因重复分支 DNS 丢失而判红。逐条加入测试并使其通过，随后加入原八秒及内存增长回归，不能以 reset-only 的功能通过结束任务。

**回归及资源检查：**

1. native payload／rules、typed、quoted 输入覆盖 `\w`、`\p{L}`、`\w\w`、交错 `\w|\p{L}` 的单分支／单轮、四重复及嵌套／量词形式。用独立单分支／单轮对照核对 DNS bytes，检查相同输入其余五格式原 matcher、count 和 unsupported，不用被测组合算法计算期望。
2. block、现有 `Rule.allow=True` seam 和真实 parse_whitelist 共享结果；保留普通 `ads.test` 邻居及适用的 `@@`。direct／proxy 继续只有原 DNS 说明。不得伪造 allow 文件语法。
3. 真实 generate／publish 检查 raw source、raw white、同轮 parent YAML source／white、非空 disk YAML source／white 的发布 bytes、diagnostics 和原输入 hash。至少一个 fixture 通过公开 CLI 复核；公开 allow 另用 render／publish 检查。保持合法空／冻结、严格本地输入和其他目标行为。
4. 用最终字面包装及独立 padding 构造 anchored `a`／`\w`：单分支与四重复在 block／allow／white 下实际含 `@@`、`/.../`、LF 恰好 65,536 bytes 保留，增加一个 byte 局部跳过。两个不同大分支保留、三个拒绝；4,096 个不同小分支保留、8,192 个因真实预算跳过，不设置分支数量限制。
5. 在 512 个已识别分支后分别追加未知 header／property／interval、非 ASCII hex、根点敏感分支、Go 或 source 量词超限，整条 DNS 仍拒绝。未知项包在 universal／`{0}` 中也必须校验；nullable、空分支、universal、600／1,000 层 neutral group 保持。
6. 对四类输入各启一个原 `timeout=8` 子进程，每个进程完成 512 轮、全部三消费者及 bytes 断言，mixed 实际含 1,024 分支。测试实际产品代码，不注入只在父进程有效的内存修复，不放宽原八秒要求。
7. tracemalloc 与计时分开运行。四类输入、三消费者分别测 64／256／512 轮，保留同一输入及 source hash，验证正确正文。对区间 64..256、256..512、64..512，分配峰值增长须小于 `(right - left) * line_bytes`，`line_bytes` 是对应消费者单分支／单轮的完整输出 regex 行含 LF 大小。沿用原阈值，不能只量 `\w` 而遗漏重复 concat `\w\w`；不宣称测得 RSS 或任意规模固定上限。
8. 运行既有 `test_functional_audit_dns.py`、`test_dns_hyphen_regressions.py`、`test_ordinary_wildcard_dns.py` 及相关深层／quantifier tests，保留 F3／UTF-8／实际 `@@`／LF、source／Go repeat、compiled-size、root／case、原高 rune 8 秒和 wildcard 内存 guards。recursionlimit=1000、int_max_str_digits=4300 不变。

**验证与提交：** 新测试与相关调用链回归、规格／功能／简化复审、自己最终 exact archive 完整 Linux suite 全部完成后提交，只包含 `_dns_regex` 和新测试，返回 clean SHA／tree 及资源日志。若资源回归失败，继续在同一 owner 中修正、复审、重验，不交由主会话补做。

### U3.2：regexp2 POSIX-looking class 边界

**依赖与 owner：** U0 及共同文档提交，owner D；依据规格 R4，与其他四项并行。

**修改与复用：** 限于 `_delimiters`／`_valid_regex` 的 class 分支及确需的共享短 helper，两个 scanner 可复用 `_regexp2_word_char`。按固定 regexp2 v1.12.0／`3d5df45b703801b3fe51eb3f5c0dd302e8b0d676` `syntax/parser.go:1538-1590` 的非 RE2、非 pending-range 消费规则识别完整 token；不复用 numeric 模式不同的 `_scan_capture_name`。probe 使用 `\[` 并保留原 class／capture 检查，原 matcher 不变；deep validator 消费 probe，无须修改。

**先取得失败证据：** 新增 `tests/test_regexp2_posix_class_regressions.py`，经真实公开 parse 断言两个非法 matcher `^[[:alpha:]()]\1$`、`^[[:alpha:]-!]$` 被拒绝，合法 scalar `^[[:alpha:](]$` 保留；基线分别因错误接受／拒绝而判红。期望来自固定源代码，不以 Python re 的结果充当 regexp2 真值。

**回归场景：**

1. 三种 regexp2 类型、普通裸／单／双引号字段、native payload／rules 的 plain／single／double scalar，depth 0／600／1,000，邻行、warning 行号及实际 YAML matcher 保持。deep 用例确认进入原 deep validator，限制及原 timeout 不变。
2. 完整 token 含已知／未知／空／数字开头／Unicode word 名、可选 `^`；不按名字展开或新增拒绝。不完整、escaped `[`、非 word 名恢复逐字符处理，内层 `]` 按实际词法决定是否关闭 class。
3. subtraction 及必须最后出现、pending range、escaped hyphen、首个 literal `]`、外层 negation。至少保护 `^[a-[:alpha:]]$`、`^[a-\-[:alpha:]()]\1$` 及 `^[[:alpha:]-[x]y]$` 的固定真值，不能只用 `class_hyphen` 判断 pending range。
4. capture 编号、named backreference、类内数字 escape／量词字面内容、x-mode 的类内 `#` 及类外非法 `\q`、原 anchor 量词和 conditional 保护。普通 logical 沿用现有必要括号编码，native logical 用 balanced `^[[:alpha:](][)]$` 覆盖 AND／OR／NOT；未编码单边括号限制保留，非法叶子整条拒绝。
5. 明确 `_delimiters` 只对 `DOMAIN-REGEX`／`PROCESS-NAME-REGEX`／`PROCESS-PATH-REGEX` 启用该扫描，合法 `URL-REGEX,^[[:alpha:]()$` 及其 Python validator 不变；不增加其他目标或 PROCESS white 支持，DNS 对 POSIX-looking class 继续 unsupported。
6. parse_whitelist、直接 Rule render、真实 generate／publish、同轮与非空 disk YAML source／white 均核对合法保留、非法拒绝及旧文件保护。两种 PROCESS regex 的 white 按既有不支持边界检查，不将其当作 `DOMAIN-REGEX` white。

**验证与提交：** 新测试、既有 class／subtraction／capture／named-reference／x-mode／deep／URL／regexp2 anchor 及 logical 回归通过，检查原 matcher 未被 probe 覆盖；完成规格／功能／简化复审及自己最终 exact archive 完整 Linux suite，英文提交并返回 clean SHA／tree／证据。

### U3.3：hosts 逐 alias 恢复

**依赖与 owner：** U0 及共同文档提交，owner E；依据规格 R5，与其他四项并行。

**修改与复用：** 只在 `_source_records` 中让已识别的四地址加 SP／HTAB hosts 去除首个 `#` 注释后设 `parts = [line]`；其他行保留 `_source_parts` 与按 `end` 裁剪。使用现有 parse 逐 alias validator，前置 physical separator 和后续 HTML 检查不移动。不新增 parser、地址、helper 或 callers。

**先取得失败证据：** 在现有 `tests/test_hosts_comment_regressions.py` 增补 `127.0.0.1 good.example bad(,x sibling.example` 与合法邻行，断言 good／sibling／neighbor 保留并报告该物理行 `invalid hosts domain bad(,x`；基线因整行丢失判红。随后逐条补 `bad,'x`、`bad,"x` 及 white 回归。

**回归场景：**

1. 四地址、SP／HTAB、BOM、LF／CRLF、前置空行／注释、多个非法 alias，检查合法前后 alias 的顺序和准确物理行号；`;`／`//` 仍为 hosts alias，不作注释并保留后续合法项。
2. `#` 后含未闭合引号、逗号、括号、markup 或跨行配对 HTML 标签不污染合法内容；真实 markup／HTML document 和七种 unsupported physical separator 继续拒绝。其他地址、typed 逗号行、native、regex、ABP 及普通尾注释行为保持。
3. direct／proxy 对 hosts 仅报告 block-only，合法普通邻行继续。block、parse_whitelist、normalize、exclude_covered 和 render 使用真实公共入口，不替换内部 lexer 或 validator。
4. 真实 generate／publish 检查 raw source／white、同轮及非空 disk source／white 的六格式 bytes、DNS 例外和行号；覆盖三种 no_resolve，并至少用一个公开 CLI fixture 核对磁盘结果及退出码。输入、static 和 parent bytes 保持。
5. 含合法 alias 的 mixed 输入正常生成，真正全无效远端来源继续冻结 source／white 依赖，健康组继续；本地 source／white 严格失败、发布前旧产物不变，保留混合 hosts white 原 warning 容许范围，不放宽其他坏行。

**验证与提交：** 现有 HostsCommentTests、test_rules 的 hosts／物理行／HTML、native／ABP 与真实生成／依赖回归通过，完成规格／功能／简化复审及自己最终 exact archive 完整 Linux suite，英文提交只含 `_source_records` 与指定旧测试增量，返回 clean SHA／tree／证据。

### U3.4：五项集成与 README 一致性

**依赖：** A 至 E 均已连续完成编码、TDD、保护边界、复审、最终 exact tree 完整 Linux suite 及英文提交，返回 clean 状态和证据。

主会话核对五个提交实际修改路径、hunk 和测试所有权，仅合并已完成且互不冲突的提交。共享文件逐 hunk 核对，不能用整文件 ours／theirs 覆盖其他修复。集成后运行四份新测试、hosts 增量及调用链相关回归，组织独立规格／功能／测试 review。发现问题交对应 owner 在其 worktree 连续完成修正、复审、修正 commit 及新 exact tree 重验后再合并；主会话不接收未完成步骤。集成 tree 再执行 U4。

README 的共同文档提交仅改 CIDR white 完整并集句子及 native padded ASN 的 YAML 保留／Surge-QX 局部 unsupported 说明，数量表、下载路径和其他段落保持。R3／R4／R5 恢复已有承诺，无新增用户操作说明，不添加五段修复历史。文档提交前运行 `test_readme`、`test_readme_counts` 和 diff 检查；集成后复跑。若新事实确需改说明或旧测试，先更新文档 owner 范围，不由产品 owner 顺手修改。

集成检查 fixtures／config／exports：新增 fixture 全部属于独立临时 root；生产 `rulesets.json` 和 `formats.FILES` 不变；`Rule` 的七字段、render 的 `(outputs, diagnostics)`、generate 的路径到文本返回值及公开函数接口不变；无需 migration、额外导出或来源身份字段。

**完成条件：** 集成 tree 同时满足 R1 至 R5、共同不变条件，README 与行为一致，独立 review 的有效问题全部修正复验。各 owner 的通过记录不替代集成最终 tree 验收。

## U4：Linux exact tree 与固定生产输入验收

### Linux 完整测试

初始 `ea67234` 完整 suite 复用 U0 已核对的 exact archive 证据。每个 owner 最终 tree 及集成最终 tree 均须独立从 Git 导出 exact archive，记录 HEAD／commit、tree、archive hash、文件 manifest 与各文件 SHA-256。可先验证待提交的 index tree，再提交并核对 commit 的 tree 完全相同；已提交版本同时记录 commit SHA。将每份 archive 解压到 Linux 原生 `/tmp` 的独立目录，脚本与下载数据分开；不在 `/mnt/c` 运行重型 suite。保存 Python 完整版本、Linux 环境、开始／结束时刻、退出码和完整日志。

使用 `-I -B` 并显式加入可信 archive root，运行全部 unittest。下面的 `$ARCHIVE_ROOT` 是本轮已核实的 Linux 原生目录，shell 当前目录也使用该目录；此命令不运行任何规则客户端。

```sh
python3 -I -B -c 'import sys, unittest; from pathlib import Path; root = Path(sys.argv[1]).resolve(); sys.path.insert(0, str(root)); suite = unittest.defaultTestLoader.discover(str(root / "tests")); result = unittest.TextTestRunner(verbosity=2).run(suite); raise SystemExit(not result.wasSuccessful())' "$ARCHIVE_ROOT"
```

与原 baseline 的 1416 tests、0 failures、0 errors、10 个既有 Windows-only skips 对照，记录新增测试及实际 discovery 清单。不得放宽原 8 秒 timeout／内存阈值、提高 recursionlimit=1000／int_max_str_digits=4300、新增 skip、修改预期为错误行为或修复本机系统。最终 suite 必须在实际最终 tree 上完成；测试前后核对原 139 文件及全部新增受控文件的 manifest／hash 不变，记录 HEAD／tree／status 无意外变化。已有 fixture 内部临时写入不属于受控文件修改。

### 固定输入与差异归因

证据采用规格列出的主 checkout `.tmp/functional-scan-20261023/`，旧目录只读。复用前逐条核对 manifest 的 body hash／bytes、56 URL 与当前配置的对应关系及 83 角色覆盖。每次执行创建新的证据目录，验证脚本在独立 scripts 目录并以 `python -I -B` 加载可信产品 root，结果与输入分开保存。

已有 `generation-gf9t9asj/scripts/check_fixed_inputs.py` 可作为公开 generate／publish 验收起点，实际使用前读其内容。它已覆盖 body hash、角色解析、六格式生成、DNS 专用语法、数量、完整／拆分 Surge 及 static；最终验收还须补固定时钟、所有格式排序、单文件大小、两轮稳定性和 README 对照。新增可复用脚本须保存为脚本文件，不把内部算法 mock 成正确答案。

必须使用同一 Linux 解释器、相同 static／配置／56 body 和同一固定 header 时钟重放 `ea67234` baseline，再运行最终 tree 两轮。fetch stub 仅返回逐 hash 核对过的真实 body；`formats.datetime` mock 仅固定文件头时间。mock 不替代 parse、normalize、exclude_covered、render、generate 或 publish。比较 baseline／final 及 final／final 的 42 文件和 diagnostics，记录每文件 hash、bytes、规则数、最大行长与诊断；最终两轮必须逐字节和逐条诊断一致。

本机基线记录为 42 文件、78,317,013 bytes、数量与 README 相同；该数值不作为最终必须相等的目标。不同 Python 的 mapped IPv6 打印可不同，先在同环境复核，再判断是否为产品差异。fmz200 的两条既有 invalid-domain warning 在 a3／a4 各一份，分别记录来源和行号；出现其他差异逐项说明。

每条生产规则的新增、删除、文本改写和 diagnostics 变化均对应 R1 至 R5 或后续已写入规格的确认修复。不能以变化比例小、总数接近、只看摘要或抽样来接受差异。没有变化时记录实际零差异。

### 42 文件统一检查

| 检查项 | 验收方式与完成条件 |
| --- | --- |
| 路径与用途 | 七组 `cdn/a3/a4/big-data/tg/proxy/dirt` 各有 `formats.FILES` 六文件，无额外生产输出；非 block 的 ADB 仅原说明正文 |
| 编码与行结构 | 全部 UTF-8、LF、结尾 LF；逐文件核对可输出字段、有效语法及 header／body 边界，不把原生 matcher 反向猜测成其他类型 |
| 格式回读 | 路由／YAML／DOMAIN-SET 用真实公开 parse 和正确格式上下文，无新增 warning；QX 保留 LIST 占位，YAML payload 正确 |
| DNS 独立校验 | 使用已有 DNS 输出语法检查域名、例外和 regex，不要求通用 parse 接受所有生成 regex；检查结构证书、`@@` 全部在普通规则之前，含 LF 每行不超过 65,536 UTF-8 bytes，包含 header |
| 计数与去重 | header 计数等于实际正文数，ADB Total count 包含例外；所有最终规则行无重复，README 数量表与 42 个正文数逐格一致 |
| 排序 | 路由类型连续分组，IP 类末尾且无族／IPv4／IPv6 顺序，每类按最终行字符数及完整字典序；DOMAIN-SET 全体排序，DNS 例外／普通两区独立排序 |
| Surge 完整与拆分 | `fin.txt` 等于非域名文件与 DOMAIN-SET 还原的集合并集，两部分不重复；支持范围和 count 一致 |
| noresolve 与白名单 | 适用的路由输出检查目的 IP 的 add／strip／keep，来源方向保持；R1、R2 的受影响规则、white 和合法空／冻结 diagnostics 与规格一致 |
| 大小与稳定性 | 每文件严格小于 100 MiB；固定时钟下最终两轮文件 bytes 及 diagnostics 相同 |
| README 与 static | 用真实 `update_readme_counts.update` 验证表格，标记外文字不被数量更新改写；生产 static 和 fixture 输入前后 hash 不变 |

### update 集成

沿用 `tests/test_ci_publication.py` 的临时 bare origin 与真实 Git fixture，运行现有 `update.update`、生成、README 更新和发布，检查 published／unchanged、tested SHA、superseded、推送竞争、权限／网络失败及 43 路径限制。fetch／time／system Git 的 mock 只隔离明确外部边界，已有真实 Git 集成测试仍须运行。当前没有修改 update 的依据，不增加发布机制。

**完成条件：** 最终 exact tree 的完整 Linux suite、固定输入两轮及全部逐文件检查通过，受控输入 hash 不变，生产差异已逐项归因，完整证据返回集成 owner。

## U5：本地 main、GitHub Actions 与远端发布

**依赖：** U0 至 U4 全部完成。此阶段由主会话执行，文档 owner 不在本子任务中合并或推送。

1. 合并 main 前重新记录本地 main、工作区修改、已有 worktree／branch 及远端 main。保留用户变更，不 reset、不覆盖未提交内容、不清旧 worktree；远端前进时重新核对共同祖先和集成范围，必要时重新验证新的 final tree。
2. 仅合并已完成 clean 提交。合并造成的最终代码 tree 与已验收 tree 不同或加入新代码时，按 U4 重验；英文提交仅包含对应任务内容，保留 hooks 和签名。
3. 普通 push 最终 main，不 force、不跳过 hook。随后核查该 main SHA 触发的 Ubuntu test 和依赖其成功的 update，优先使用 `gh run watch --exit-status` 的阻塞等待或后台完成通知。不得用本地任务输出文件或 sleep 轮询进度。
4. workflow 记录 `superseded` 时继续追踪最终实际代码 SHA 的 test 与有效 update，不据旧 run 的绿色结论宣称发布完成。每轮保留受测事件 SHA、run ID、真实状态与日志；CI 失败由对应 owner 在其 worktree 完成修正、复审及新 tree 重验后再合并。未完成的远端运行不写为成功。
5. 有效结果为 `published` 时，记录新增的实际产物发布 commit，核对其与受测代码 SHA、远端 tip 的祖先关系。检查该新增 commit 的实际 diff 是配置六文件及 README 共 43 个允许路径的子集，不要求无变化文件出现在 diff；从该不可变 commit 读取七组 42 文件与 README 的真实 bytes。
6. 有效结果为 `unchanged` 时，明确记录没有新增发布 commit，保留 `unchanged: no generated changes to publish` 日志及本轮生成 bytes 核验依据。从受测事件 SHA 的不可变快照读取 42 文件与 README，核对其与本轮目标及远端已有 bytes 一致。不得把含源码／测试的受测代码 commit 当作产物 commit 检查 43 路径 diff。
7. 对上述各自确定的不可变 SHA，重新执行 U4 的路径、格式、header、计数、排序、去重、完整／拆分、noresolve、大小、ADB 专用语法及含 LF 行限检查，核对 README／static 与已合并输入。不用最新分支网页或总数摘要替代真实 bytes；若期间被新代码替代，继续追踪并验收最终实际 SHA。
8. 记录最终代码 SHA／tree、test／update run ID 与结论、published 的实际发布 SHA 或 unchanged 的无新增 commit 状态、42 文件结果及限制。任务成功合并后退出各任务 worktree、返回原工作目录；确认 clean 且无未合并提交，再用正常 Git worktree／branch 命令仅清理本次创建且已无用途的资源，不强删、不清旧 worktree／原有 `.claude/`／其他任务资源。保留需要复用的证据，清理本次无需保留的临时内容；本机清理失败继续交付并列明残留路径，不专门修复系统。

## 完成条件

交付结果必须逐项对应规格 R1 至 R5、共同不变条件和后续新增的确认问题。五个 owner 各自完成真实失败回归、最小实现、保护边界、规格／功能／简化复审、最终 exact tree 完整 Linux suite 和 clean 英文提交；集成后独立 review、最终 Linux／同环境固定输入／远端实际 bytes 验收证据齐全。

最终报告明确区分文档、产品实现、本地验证、CI 与实际发布状态，包含绝对路径、SHA／tree／branch／worktree、验证结果及残留项。没有客户端运行结果，不宣称闭源 ASN 行为已经实测；DNS 局部设计实验不表示产品实施已完成，未完成的测试或发布如实列明。
