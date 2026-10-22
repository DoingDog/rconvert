# wildcard 输入与生成依赖闭合设计

## 目标和归属

基准为 `4c1f29d55e47f939b96cf87a5284f947938191ed`。修复普通 `DOMAIN-WILDCARD`／`HOST-WILDCARD` 把合法 pattern 当作 hostname 验证的问题，使已经输出的安全 wildcard 能按实际文件 bytes 重新导入。`DOMAIN`、`DOMAIN-SUFFIX`、hosts、裸域名和 DOMAIN-SET 的 hostname 校验保持。

生产修改仅限 `rules.py` 的 `_valid_domain` wildcard 分支。新测试为 `tests/test_wildcard_dependency_regressions.py`；旧测试只更新 `tests/test_functional_audit_coverage.py` 的普通 pattern 拒绝断言，以及 `tests/test_functional_audit_projection.py` 的普通无点 wildcard 拒绝断言。实现不修改 normalize、formats、generate、README、配置、static 或已有 timeout，不增加依赖、生成专用入口、隐藏 Rule 缓存或来源 sidecar。目标执行环境为 Ubuntu Actions，验收在现有 Debian WSL 执行，测试 fixture 使用 Linux `/tmp`。不运行或下载执行客户端。

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

parser 的 pattern 合法性不构成其他目标的全域可表达性证书。新接受的引号、反斜杠、括号和非 ASCII literal 会到达 `_wildcard_regex`，普通 DNS builder 现有直写 regex 不具备 native presentation encoder 的保证。该格式层安全投影归 routing owner；本分支不改 formats，不以 parser 全局拒绝合法 Surge pattern 代替目标局部限制，也不把该部分现有输出作为已经证明的 DNS 等价。

QX 字面引号和 comment marker 的字段承载修复也归 routing owner。此分支只验证 QX 已有可安全承载的 pattern，不重复或伪造该实现；特殊 QX 字段及上述新输入的 DNS 安全性必须在 routing 完成后的集成中核验。既有 Unicode／DNS raw regex 证书、native case／root／byte guards 仍作为本分支回归保护。

## 验收

1. ordinary／native scalar 正例覆盖 `*`、`*123*`、`*?123*`、`**123**`、多点和长 pattern；普通引号字段解码后的 literal 和 Surge 输出回读保留。
2. 同一 scalar 的 source 与 white、单条与混合邻居、三种 purpose × 三种 no_resolve、三个文本及 YAML 产物均用公开入口检查，记录准确 matcher／来源及 warning。
3. logical source 覆盖 AND、OR、NOT 和嵌套，逐目标检查完整表达式、目的／来源 IP 方向和选项；logical 不新增 white 能力。
4. 真实 generate／publish 覆盖同轮与磁盘 source／white，比较相同实际 bytes 下子组全部六产物及诊断；发布前旧文件不变、发布后 bytes 等于返回文本，static fixture 不变。保留损坏 white、严格 disk 空文件、generated logical white 拒绝、冻结及事务回滚的既有完整 suite 保护。
5. 保留普通字符类有效／非法语法、native literal bracket、byte／字符和根点反例、未知 Unicode white 不跨来源删除、DNS raw regex 无证书 skip。运行所有相关模块及完整 Linux suite，不修改旧 timeout。
6. 检查 diff 仅含拥有文件，完成规格和简化复审，使用英语提交。最终分别列明本分支结果、格式协作未核范围和环境限制，不冒称已在 GitHub runner 或客户端运行。
