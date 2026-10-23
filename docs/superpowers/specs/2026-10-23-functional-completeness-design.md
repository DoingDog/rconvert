# 功能完整性扫描与修复规格

## 目标、基线与实施门槛

全面检查规则解析、来源白名单过滤、规范化、各目标投影、生成依赖及发布，复现并修复全部确认存在、可修且不破坏其他功能的问题。重点检查去重顺序与完整性、多客户端格式、`no_resolve` 和上游异常处理。

代码基线为 `ea67234ae739af33fd5f7ecfa197213183eaeb28`，tree 为 `752c5358aa961ed4ce74f80d245e23489426ee5b`。本规格记录当前已确认的 R1、R2；全面 scan／coverage-check 尚未最终结束，Linux 完整测试基线仍由独立任务收集。已有局部复现及固定输入生成结果不代表这两项检查已完成。

产品代码实施须同时满足：全部 scan 与 coverage-check 返回；检查范围逐项覆盖且遗漏已补查；每个候选均已复核并形成明确结论；新增确认问题已经写入本规格及[实施计划](../plans/2026-10-23-functional-completeness.md)。发现新候选时先完成复核及必要的文档更新，再开始或恢复受影响的实施。

## 范围与约束

- 当前最小产品修改范围为 `rules.exclude_covered` 的 CIDR 索引、`rules._ordinary_field_supported` 的 ASN 能力判断，以及 `formats.render` 的 Surge `no-resolve` 分支。测试及必要的 README 行为说明随修复更新。
- 保留公开入口、`Rule` 全部字段、配置键、`formats.FILES`、七组生成顺序及六种输出文件。`sources.py`、`generate.py`、`update.py`、`update_readme_counts.py`、`rulesets.json` 和 CI 配置目前均无已确认的修改需要。
- 不运行任何规则客户端，包括配置测试模式；外部实现仅阅读固定源码及文档。不开展网络安全扫描或修复，不处理 Windows／多平台适配，不处理已知 Mihomo suffix 大小写，也不批量把 regex 改写为 suffix。
- `static/` 与用户现有修改保持原样。测试和生成使用独立 fixture root；生产产物由最终发布流程更新。

## 已核查的数据流及影响位置

| 路径 | 当前行为 | 本次影响 |
| --- | --- | --- |
| `rules.parse`、`_normalize_condition` | 普通 ASN 去除 `AS` 和前导零；native provider 保留 ASN 字符串。CIDR 校验、方向及 scope 拒绝在此处理 | 保持解析与输入校验 |
| `rules.parse_whitelist` | 忽略 policy，移除 options／allow 标记，保留适用的 matcher 身份；不合并 CIDR | 原始白名单可直接触发 R1 |
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

本次完整性要求纳入可证明的 CIDR 并集覆盖。其适用行为明确扩展了 `docs/superpowers/specs/2026-09-28-json-whitelist-design.md` 中「某项白名单完全覆盖」的逐项描述；该历史描述不能用于省略本次并集要求。

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

## 共同的不变条件

来源白名单过滤 -> `no_resolve` -> 规范化 -> 目标投影及目标 white 过滤的顺序保持。`no_resolve` 的 `add`／`strip`／`keep` 只影响适用的目的 IP 规则，不把来源方向变为目的方向。

来源已完整覆盖，或每条剩余规范规则至少存在有效路由投影且全部有效投影均被 white 覆盖时，可以发布空正文。完全 unsupported、无可路由规则且存在不可用来源等既有冻结条件保持，冻结依赖传播至六种旧产物；健康组继续更新。缺少完整旧产物、本地 white 损坏、生成依赖存在正文解析 warning 等错误仍在发布前终止。`publish` 的替换失败恢复及 `static/` 保护保持。

上游 404 的缓存与跳过、429／5xx／超时／传输不完整的中止、gzip 与 chunked 读取、远端混合坏行的诊断、本地严格读取均须回归检查。本次没有据此增加新 fallback、重试、配置或依赖。

## 证据与验收依据

复核报告标识为 R1 的 `wxol2ntbu` 和 R2 的 `w6zj74dcc`。R1 三方均确认现象，其中一方提出历史逐项覆盖规格的差别，本规格已明确本次并集要求。R2 报告须按前述闭源运行限制解释，不能将静态依据写成客户端实测。

可复用的本地复现材料在主 checkout 的已忽略 `.tmp/functional-scan-20261023/` 下：

- `cidr-generate-verify-d_0gqrb1/minimal_regression.py` 与 `verify_generation.py` 检查 R1 的真实生成、发布及依赖边界；`cidr-options-counterproof-wrqjq911/` 保存 options、allow 及 QX identical-only 的对照。
- `asn-refutation-4htk_04c/probe_asn.py`、`asn-independent-036p7h_y/repro_asn.py` 与 `test_projection_contract.py` 保存 R2 的源格式、公开入口及依赖反例。
- `generation-upstreams-wacea8ew/manifest.json` 及 `raw/` 保存 56 个唯一 URL、18,116,304 bytes；83 个配置角色中含 72 个远端角色和 11 个本地／生成角色。body 大小与 SHA-256 已核对。旧 manifest 只有耗时 `seconds`，没有逐 URL 绝对开始时刻，不补造该信息。
- `generation-gf9t9asj/acceptance-_ky64k6k/fixed-input-results.json` 记录基线固定输入生成 42 个产物、78,317,013 bytes、数量与 README 相同、无冻结及 static／主目录生产输出不变。fmz200 的两条既有 `invalid domain` warning 在 a3／a4 各出现一份。此结果按原报告环境解释，不能作为最终 Linux 或最终代码验收。

最终验收须使用 exact Git archive 在 Linux 原生 `/tmp` 完成完整 unittest，记录基线及最终 SHA／tree、解释器、输入及受控文件 hash。固定上游输入在同一解释器与固定 header 时钟下比较，必要时重放基线；最终两轮 42 文件 bytes 和 diagnostics 必须稳定。逐项检查格式、文件头、数量、排序、去重、Surge 完整文件与拆分文件、noresolve、README、static、单文件小于 100 MiB，以及 DNS 每行含 LF 不超过 65,536 UTF-8 bytes。生产差异逐规则对应确认修复，不使用比例阈值。

远端完成条件为最终推送的代码 main SHA 对应的 Ubuntu test 成功及有效 update 成功，另记录仅更新产物与 README 的实际发布 commit，读取该 commit 的 42 文件 bytes 核验，并确认发布修改路径属于 42 个产物及 README 的 43 路径集合。`superseded` 仅表示旧事件退出，必须继续核查最终 main 的测试和发布。具体执行、分工与验收步骤见实施计划。
