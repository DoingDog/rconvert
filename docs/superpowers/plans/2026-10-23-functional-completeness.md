# 功能完整性扫描、TDD 修复与发布计划

## 目标与执行边界

依据[功能完整性规格](../specs/2026-10-23-functional-completeness-design.md)，完成全面功能扫描、确认问题的 TDD 修复、Linux 与固定输入验收，再合并本地 main、普通 push 并核查远端实际发布。当前已确认 R1 CIDR white 并集遗漏和 R2 padded ASN 目标投影；本文覆盖两项修复及完整交付流程，新增确认问题须先补充规格和计划。

基线为 `ea67234ae739af33fd5f7ecfa197213183eaeb28`，tree 为 `752c5358aa961ed4ce74f80d245e23489426ee5b`。全面 scan／coverage-check 尚未最终结束，独立 Linux 基线仍在收集中。文档提交只完成规划，不解除规格中的产品代码实施门槛。

沿用规格的禁止项、公开接口、配置和 static 保护。当前不新增依赖、配置、exports、来源标记、通用抽象或解析器；不增加 fallback，不修改客户端支持边界之外的规则。README 的必要说明归集成 owner 单独修改，两个修复 owner 均不编辑 README。

## U0：收齐扫描结果并核对覆盖

**依赖与产出：** 复用现有 scan workflow，由主会话收集最终报告与 coverage-check，形成每个范围、证据及候选结论的对应关系。全部完成前仅允许文档、只读调查和基线取证。

| 全部检查范围 | 对应代码、测试与输入 | 必须核对的行为 |
| --- | --- | --- |
| 输入语法与数据身份 | `rules.py`；`tests/test_rules.py`、`tests/test_native_domains.py`、`tests/test_functional_audit_rules.py` | 普通混合输入、hosts、DNS、DOMAIN-SET、native payload／rules、外层引用、policy／options、无效行诊断、全部受支持 kind |
| 域名及 regex | `rules.py`、`formats.py`、`_unicode15.py`；domain／wildcard／regex／keyword／geodata 相关测试 | Unicode／byte／root／case 的既有差别、目标可表达范围、结构证书、深层表达式及原有限时；排除已知 suffix 大小写及批量 regex 改写 |
| 去重与 white | `exclude_covered`、`normalize`、`_route_whitelist`；`test_domain_coverage.py`、`test_yaml_coverage.py`、`test_functional_audit_coverage.py` | 来源过滤顺序、完整覆盖和反例、allow／options／来源身份、IP 方向与地址族、最终 matcher 去重、R1 与 R2 |
| 多客户端输出 | `formats.py`；`test_formats.py`、`test_yaml_output.py`、`test_functional_audit_projection.py`、DNS／routing／target-field 回归 | 六格式各自类型、logical 整条处理、noresolve、排序、完整／拆分 Surge、DNS 例外与行限、实际 bytes 回读 |
| 配置与来源选择 | `sources.py`、`rulesets.json`；`test_sources.py`、`test_generator_alias_regressions.py` | 七组、sources／white 全部角色、路径与格式选择、缓存、依赖先后、配置字段不变 |
| 上游读取与异常 | `generate.fetch_https` 及 `generate` 的读取路径；`test_generate.py`、`test_functional_audit_transport.py`、`test_chunked_ows_regressions.py` | 404 缓存／跳过、429／5xx／超时／不完整响应中止、gzip／chunked、空／HTML／坏编码、远端混合坏行、本地严格失败 |
| 生成与文件发布 | `generate.py`／CLI；`test_functional_audit_integration.py`、`test_target_field_integration.py`、static／生成依赖相关测试 | 同轮／disk source 与 white、合法空正文、冻结传播、健康组继续、缺少旧产物报错、替换失败恢复、输入 hash 不变 |
| README、入口及 CI | `README.md`、`index.html`、`update_readme_counts.py`、`update.py`、`.github/workflows/main.yml`；readme／workflow／CI publication 测试 | 下载路径与用途、42 数量、43 发布路径集合、事件 SHA、superseded／unchanged／published、普通 push 竞争及失败可见性 |
| 生产输入与规模 | 配置中的 83 个角色、56 URL 固定 body、全部 static、42 文件 | 每个角色均解析及生成、诊断归因、格式／数量／大小／去重／排序／稳定性、实际 static 不变 |

覆盖检查使用仓库实际文件清单，不能把表中的测试主题或 pattern 当作已存在的测试文件或已完成结果。核对全部生产模块、公开 caller、现有全部 tests、fixture helper、配置及输出，遗漏分配给独立 workflow 补查并等待完成通知。

每个候选保留复现输入、期望、实际结果、公开调用路径及反例。复核结论明确为确认、否定或证据不足；待复核或影响当前行为的未决候选阻止实施。若发现新确认问题，先由文档 owner 更新两份文档，再按依赖及文件范围追加工作单元。

**完成条件：** 全部报告和 coverage-check 收齐，范围无遗漏，候选均已复核，独立 Linux 基线证据可追溯，规格和计划包含全部待修问题。不得填写尚未返回的测试数目或宣称扫描已经完成。

## 工作所有权与共同检查流程

U0 完成且共同文档提交确定后，从该共同提交并行创建 A、B 的独立 worktree，使用可用的带 `[1m]` 后缀模型。各 owner 开始时记录 worktree、branch、HEAD／tree、初始 status 及与共同 base 的关系。不得编辑主 checkout、旧 worktree 或其他任务文件。

| owner | 唯一写入范围 | 所有权说明 |
| --- | --- | --- |
| A，CIDR | `rules.py` 的 `exclude_covered`；新增 `tests/test_cidr_whitelist_union.py` | 不修改 B 的 helper、formats、旧测试或 README |
| B，ASN | `rules.py` 的 `_ordinary_field_supported`；`formats.py` 的 Surge noresolve guard；新增 `tests/test_asn_projection_regressions.py`；三份旧测试的准确 padded 投影预期 | 旧测试为 `test_functional_audit_rules.py`、`test_generate.py`、`test_functional_audit_coverage.py`，不改 parser 或生成依赖校验 |
| 集成／文档 owner | 两份规格计划、必要 README 文字与集成验证材料 | 在修复提交完成后验证共同 tree；生产发布沿用 update 的路径范围 |

A、B 在 `rules.py` 的修改位置互不重叠。每个 owner 连续完成一个失败回归 -> 最小修复 -> 边界保护 -> 规格／功能／简化审查 -> 修正与复审 -> 相关测试及完整 Linux suite -> 英文 commit，返回可合并的 clean 提交。不得把未完成的测试、修复或审查交还主会话。提交后若修改内容，重新提交并验证新的 exact tree。

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

## U3：集成与说明

**依赖：** U1、U2 均已完成并提交，返回 clean 状态及其最终 tree 验证证据。

主会话核对两个提交的实际修改路径和 hunk，仅合并已完成且不冲突的内容。`rules.py` 的两个位置分别保留；若 Git 报告冲突，逐 hunk 核对，不能用整文件 ours／theirs 覆盖另一个修复。集成后运行两份新增测试及调用链相关测试，再进行 U4。

README 只补充必要事实：CIDR white 可按同方向同族有效并集证明完整覆盖；padded native ASN 保留 YAML、Surge／QX 跳过对应投影，logical 整条处理和空依赖沿用原行为。沿用 README 中文，不写闭源客户端实测结论，不改 static、来源、配置及输出路径。README 文字测试有明确旧预期时仅更新相应断言，数量表继续由 `update_readme_counts.update` 处理。

集成检查 fixtures／config／exports：新增 fixture 全部属于独立临时 root；生产 `rulesets.json` 和 `formats.FILES` 不变；`Rule` 的七字段、render 的 `(outputs, diagnostics)`、generate 的路径到文本返回值及各公开函数接口不变；无需 migration、额外导出或来源身份字段。

**完成条件：** 集成 tree 同时满足 R1、R2，README 与行为一致，全部变动可以对应已确认问题。集成后的任何修正均重新验证最终 tree，不把两个单独 owner 的通过记录替代集成验收。

## U4：Linux exact tree 与固定生产输入验收

### Linux 完整测试

对初始基线和每个待交付最终 tree 从 Git 导出 exact archive，记录 tree、archive hash、文件清单与受控文件 SHA-256。可先验证待提交的 index tree，再提交并核对 commit 的 tree 完全相同；已提交的版本同时记录 commit SHA。将每份 archive 解压到 Linux 原生 `/tmp` 的独立目录，脚本与下载数据分开；不在 `/mnt/c` 运行重型 suite。保存 Python 完整版本、Linux 环境、开始／结束时刻、退出码和完整日志。

使用 `-I -B` 并显式加入可信 archive root，运行全部 unittest。下面的 `$ARCHIVE_ROOT` 是本轮已核实的 Linux 原生目录，shell 当前目录也使用该目录；此命令不运行任何规则客户端。

```sh
python3 -I -B -c 'import sys, unittest; from pathlib import Path; root = Path(sys.argv[1]).resolve(); sys.path.insert(0, str(root)); suite = unittest.defaultTestLoader.discover(str(root / "tests")); result = unittest.TextTestRunner(verbosity=2).run(suite); raise SystemExit(not result.wasSuccessful())' "$ARCHIVE_ROOT"
```

独立 baseline 任务的结果返回前保持未知，不能预填通过数。基线存在失败时保留原日志并定位是否属于任务问题或环境差别；不得为通过测试放宽 timeout／内存阈值、新增 skip、修改预期为错误行为或修复本机系统。最终 suite 必须在实际最终 tree 上完成，测试前后 archive 中受控输入和生产文件 hash 不变。已有 fixture 内部的临时文件写入不属于受控文件修改。

### 固定输入与差异归因

证据采用规格列出的主 checkout `.tmp/functional-scan-20261023/`，旧目录只读。复用前逐条核对 manifest 的 body hash／bytes、56 URL 与当前配置的对应关系及 83 角色覆盖。每次执行创建新的证据目录，验证脚本在独立 scripts 目录并以 `python -I -B` 加载可信产品 root，结果与输入分开保存。

已有 `generation-gf9t9asj/scripts/check_fixed_inputs.py` 可作为公开 generate／publish 验收起点，实际使用前读其内容。它已覆盖 body hash、角色解析、六格式生成、DNS 专用语法、数量、完整／拆分 Surge 及 static；最终验收还须补固定时钟、所有格式排序、单文件大小、两轮稳定性和 README 对照。新增可复用脚本须保存为脚本文件，不把内部算法 mock 成正确答案。

使用同一 Linux 解释器、相同 static／配置／56 body 和相同 header 时钟，必要时重放基线，再运行最终 tree 两轮。fetch stub 仅返回逐 hash 核对过的真实 body；`formats.datetime` mock 仅固定文件头时间。mock 不替代 parse、normalize、exclude_covered、render、generate 或 publish。比较 baseline／final 及 final／final 的 42 文件和 diagnostics，并记录每个文件的 hash、bytes、规则数、最大行长与诊断。

本机基线记录为 42 文件、78,317,013 bytes、数量与 README 相同；该数值不作为最终必须相等的目标。不同 Python 的 mapped IPv6 打印可不同，先在同环境复核，再判断是否为产品差异。fmz200 的两条既有 invalid-domain warning 在 a3／a4 各一份，分别记录来源和行号；出现其他差异逐项说明。

每条生产规则的新增、删除、文本改写和 diagnostics 变化均对应 R1、R2 或新增确认修复。不能以变化比例小、总数接近、只看摘要或抽样来接受差异。没有变化时记录实际零差异。

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
4. workflow 记录 superseded 时继续跟踪当前应发布代码 SHA 的测试与有效 update，分别记录受测代码 SHA 和仅含产物／README 的发布 SHA，不能据旧 run 的绿色结论宣称发布完成。update 的 published、unchanged 与 superseded 分别按真实日志解释，CI 失败时定位失败步骤、修正任务问题并重新验证；未完成的远端运行不写为成功。
5. 确定实际发布 commit，按该不可变 commit 读取七组 42 文件和 README 的真实 bytes，不用最新分支网页摘要代替。重新执行 U4 的路径、格式、header、计数、排序、去重、完整／拆分、noresolve、大小及 DNS 行限检查，并核对 static 与已合并输入。
6. 检查发布 commit 的实际变更集是配置六文件与 README 共 43 个允许路径的子集，不能要求无变化文件也必须出现在 diff。published 核对远端 tip／祖先关系及产物；unchanged 核对远端已有 bytes 与本轮目标一致，并保留该状态的证据。
7. 记录最终代码 SHA／tree、test／update run ID 与结论、实际发布 SHA、42 文件结果、README／static 结论及未完成限制。回到原工作目录后，仅对本次创建、已合并、clean 且无未合并提交的 worktree／本地分支执行正常清理，不强删、不清其他任务资源。本机文件清理失败时继续交付，列出残留及路径，不专门修复系统。

## 完成条件

交付结果必须能逐项对应规格 R1、R2、共同不变条件和扫描后新增的确认问题。每项修复都有真实失败回归、最小实现、边界测试、规格／功能／简化复审和 clean 英文提交；全部 scan／coverage-check 与最终 Linux／固定输入／远端验收证据齐全。

最终报告明确区分文档、产品实现、本地验证、CI 与实际发布状态，包含绝对路径、SHA／tree、验证结果及残留项。没有客户端运行结果，不宣称闭源 ASN 行为已经实测；未完成的扫描、测试或发布如实列明。
