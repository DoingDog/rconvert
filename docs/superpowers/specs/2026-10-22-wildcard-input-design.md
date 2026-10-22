# wildcard 输入与生成依赖闭合设计

## 目标和归属

基准为 `4c1f29d55e47f939b96cf87a5284f947938191ed`。修复普通 `DOMAIN-WILDCARD`／`HOST-WILDCARD` 把合法 pattern 当作 hostname 验证的问题，使已经输出的安全 wildcard 能按实际文件 bytes 重新导入。`DOMAIN`、`DOMAIN-SUFFIX`、hosts、裸域名和 DOMAIN-SET 的 hostname 校验保持。

wildcard 生产修改限于 `rules.py` 的 `_valid_domain` wildcard 分支，以及 `formats.py` 普通 `DOMAIN-WILDCARD` 的 DNS 投影与必要的既有 `_wildcard_regex` 连接和预算。新测试为 `tests/test_wildcard_dependency_regressions.py` 和普通 DNS 投影测试；旧测试仅更新 `tests/test_functional_audit_coverage.py`、`tests/test_functional_audit_projection.py` 已授权的普通 pattern 拒绝断言，以及 `tests/test_functional_audit_dns.py` 原 1011–1017 行的同类预期。README 仅补充 wildcard／DNS 支持说明，不修改 QX 字段段、Actions 或计数。

不修改 normalize、共享 QX helper、process／Mihomo／QX 字段 guard、logical、`_dns_regex` escaped-hyphen、配置、static 或已有 timeout。不增加依赖、生成专用入口、隐藏 Rule 缓存、来源 sidecar 或通用 parser／decoder。目标执行环境为 Ubuntu Actions，验收在现有 Debian WSL 的 Linux `/tmp` 可信完整 Git snapshot 执行；不在 `/mnt/c` 执行重型 suite。不开展网络安全扫描或修复，不处理 Mihomo suffix 大小写，不运行任何客户端，不调查 Windows 本机或多平台适配。

## 已核查的行为与调用方

已阅读实际 `_valid_domain`、全部生产调用及消费者、`parse`／logical／`parse_whitelist`、`exclude_covered`／normalize、`formats.render` 与 wildcard／DNS／目标 white 转换、`generate`／`publish`，以及 README 和四份历史设计规格。三视角复核记录 `wildcard-generated-readback` 的三个 checks 均确认缺陷。

native `*`、`*123*`、`*?123*`、`**123**` 当前可输出 Surge 完整／拆分及 QX 文本，但普通入口仍在替换通配符后执行要求含点的 `_DOMAIN`。同轮依赖因 warning 停止；单条磁盘依赖失败；混合磁盘 source／white 可在警告后遗漏 wildcard。更宽的已有输出包括 `1..2*`、254 个数字后接 `*` 和 Surge 正确引用的字面 `'123*`／`'123.456*`，仅允许 `*` 或给无点值补 `x.` 不足以覆盖。

共享 helper 的消费范围如下。

| 公共接口 seam | 核查内容 | 保持的边界 |
|---|---|---|
| `parse(text, purpose=...)` | ordinary Surge／QX、native scalar、AND／OR／NOT／嵌套及邻居 | 解码后 pattern、来源身份、行号 warning、IP 方向和选项 |
| `parse_whitelist(text)` | scalar white 独占／混合，实际文本 bytes | 不新增 logical white；非法独占 white 继续报错 |
| `normalize`／`exclude_covered`／`render` | 六目标、white／allow、完整拆分、输出回读 | byte／字符、case／root、native literal `[]` 与普通字符类分别处理 |
| `generate(root, fetch)`／`publish(outputs, root=...)` | 三文本及 YAML 的同轮／disk source／white、实际 UTF-8 bytes | 严格依赖、合法空产物、冻结、发布前异常保护及 static 不变 |

本任务已指定这些公开 seams，测试不直接调用私有 validator，不 mock parser、转换器或发布实现。仅在需要确定六文件 bytes 时固定时钟；离线 fixture 的 fetch 在意外调用时直接失败。

## 输入支持范围

wildcard 是非空、安全 scalar pattern，不继承 hostname 的点号、label 长度、总长度、IP 字面和 label 边缘 hyphen 限制。沿用 native wildcard 已有 scalar 安全检查，拒绝 NUL、不安全 C0／C1、surrogate、Unicode 行分隔符及已有非字符边界；tab 的既有允许保持。实际字段分隔、引号、HTML 与行范围继续由现有 parser 决定。

普通来源仍仅接受既有 `[a-z0-9-]+` 形状的字符类，大小写接受规则保持；裸 `[`／`]`、空类、否定类及未知类语法继续拒绝。已有 source 可保留、目标 converter 不支持的 range 继续按原目标局部 skip。native `[]` 始终为字面，不套用普通类验证。

`Rule` 的普通 ASCII lower 与单尾点规范化、native 原文、`domain_source`、`native_fields`、allow、目的 IP 的 `add`／`strip`／`keep`、来源 IP 不加 `no-resolve` 全部保留。GEOIP LAN 与手工 SRC-IP CIDR 排除不纳入修改。

## 目标与协作边界

安全 `*`、`*123*` 等经三个文本文件和 YAML 重新导入，普通 Surge wildcard 必要时继续转 Mihomo regex。Surge 字面引号输入／输出必须闭合。Surge full 与 split 保持一致，DOMAIN-SET 不承载 wildcard。含目标不支持叶子的 logical 继续整条 skip。

parser 的 pattern 合法性不构成其他目标的全域可表达性证书。普通 DNS 仅扩展已有 ASCII hostname literal 字符集及既有 Surge 字符类：`a-z`／`A-Z`、数字、underscore、hyphen、点和 `*`／`?`，不再要求含点或 hostname 长度。普通 `*ads*`、`*`、`a?`、`a??` 分别输出已知 body `/^.*ads.*$/`、`/^.*$/`、`/^a.$/`、`/^a..$/`，用 ASCII Host 见证核查匹配结果。Surge `[ab]` 保持可用，QX 未证明的 class 和 native literal `[]` 保持各自目标局部限制。

新接受的单引号、双引号、反斜杠、括号、空白、其他标点及非 ASCII literal，缺少普通来源与 DNS presentation 全域等价证据时，仅计该条 DNS unsupported，保留公共 Rule 和其他可表达目标。固定 miekg presentation 会对部分 literal 添加反斜杠或 decimal bytes，不能直接使用原 anchored regex，也不能把 Surge `?` 的字符语义替换为 native byte token。`*<ads>*` 保持普通 DNS 负例。普通 `DOMAIN-KEYWORD` 的特殊 Host 行为没有确认，本任务保持其现有 DNS 行为；native wildcard 的 byte／presentation encoder、case／root／bracket guards 和已证特殊 literal 支持保持。

DNS 最终每行上限为 65,536 UTF-8 bytes，含 LF、`@@` 和 `/.../`。恰好上限保留，增加一个 byte 仅跳过该 DNS 规则并计数；长 pattern 必须在分配扩展 DNS regex 之前使用有依据的早期预算或既有预算 helper，不先构造无界字符串。block、allow、external whitelist 使用同一普通 DNS 支持判定和预算。

QX 字面引号和 comment marker 的字段承载修复归另一任务。此分支仅验证 QX 已有可安全承载的 pattern，不修改、重复或伪造该实现。既有 Unicode／DNS raw regex 证书、native case／root／byte guards 仍作为回归保护。可合并已完成 H commit `fe34c69abe6695af86c796da003400d68ee7e12d`，保留其全部历史和 production 逻辑，仅将其新建 root plan 移至既有 `docs/superpowers/plans/`；最终完整 suite 同时验证两项修改。

## 验收

1. ordinary／native scalar 正例覆盖 `*`、`*123*`、`*?123*`、`**123**`、多点和长 pattern；普通引号字段解码后的 literal 和 Surge 输出回读保留。
2. 同一 scalar 的 source 与 white、单条与混合邻居、三种 purpose × 三种 no_resolve、三个文本及 YAML 产物均用公开入口检查，记录准确 matcher／来源及 warning。
3. logical source 覆盖 AND、OR、NOT 和嵌套，逐目标检查完整表达式、目的／来源 IP 方向和选项；logical 不新增 white 能力。
4. 真实 generate／publish 覆盖同轮与磁盘 source／white，比较相同实际 bytes 下子组全部六产物及诊断；发布前旧文件不变、发布后 bytes 等于返回文本，static fixture 不变。保留损坏 white、严格 disk 空文件、generated logical white 拒绝、冻结及事务回滚的既有完整 suite 保护。
5. 普通 DNS 正例和未证明 literal 的局部 skip 均覆盖 block／allow／external whitelist，核查字面 body、ASCII 见证、skip 计数及三种 purpose × 三种 no_resolve。验证 65,536 bytes 的恰好边界、一个 byte 超限和大 pattern，不修改任何旧 timeout。
6. 保留普通字符类有效／非法语法、native literal bracket、byte／字符和根点反例、未知 Unicode white 不跨来源删除、DNS raw regex 无证书 skip。相关模块和完整 Linux suite 均实际等待退出并记录结果。snapshot 包含所有受控文件及本任务新测试，逐文件核对 SHA-256，保留实际日志；suite 失败继续修正授权范围内的原因，不能更改 timeout 或 skip 掩盖。
7. 检查 diff 仅含拥有文件及已授权 H 合并，完成规格和简化复审，使用英语提交。最终列明 path／branch／base／head、commits、逐行为 red／green、完整 suite 终态及日志、协作未核范围、未清理项和环境限制，不冒称已在 GitHub runner 或客户端运行。保留干净 worktree 和 branch 供集成，不 push 或合并 main。
