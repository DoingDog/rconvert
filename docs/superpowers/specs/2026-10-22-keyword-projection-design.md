# native keyword 去重的目标输出保留设计

## 目标与依据

修复 `keyword-projection-dedup`：同组 native `DOMAIN-KEYWORD,123.` 与 `DOMAIN-KEYWORD,123.45` 共存时，保留后者在 Surge 和 AdGuard DNS 中可表达的正文及适用的 `@@` 例外。
基准为 `4c1f29d55e47f939b96cf87a5284f947938191ed`。

固定 Mihomo `88dcbf7f1614a67c3b36b848ee3592dfa92ada36` 的 `rules/common/domain_keyword.go` 对 constructor payload 使用 `strings.ToLower`，对 `RuleHost()` 使用 `strings.Contains`。
`123.45` 的来源匹配集合属于 `123.`，但 `formats._domain_value` 与 `formats._dns_pattern` 已按目标拒绝以点结尾的 native keyword。
`generate` 在 `render` 前执行 `normalize`，因此只保留短规则会使可表达的长规则提前消失。
本设计遵循 `docs/superpowers/specs/2026-09-29-rule-preservation-design.md` 的目标局部 unsupported 要求和 `README.md` 的来源身份、DNS 例外、实际 bytes 依赖及冻结要求。

## 公共接口与影响范围

| 公共接口 seam | 本次验证的行为 | 不承担的证明 |
|---|---|---|
| `Rule`、`parse`、`normalize` | YAML scalar 解码、来源身份、分组及顶层 keyword 去重 | 客户端运行时接受未知字段 |
| `render` | 六文件正文、标题数量、Surge 拆分、DNS 例外和诊断 | 闭源 Unicode/QX 的完整语义 |
| `parse_whitelist`、`exclude_covered` | 外部 native 白名单仍保留可表达例外及既有来源覆盖 | 新白名单语法或新覆盖关系 |
| `generate` | 正常组、同轮 source/whitelist 依赖、实际 bytes 重导入及冻结 | 远程来源可用性 |
| `publish` | 在隔离临时 root 写入真实文件，输入和冻结旧产物保持原 bytes | GitHub Actions 远程运行状态 |

唯一生产调用方为 `generate.generate` 的 `normalize` 调用。
新增测试集中于 `tests/test_keyword_projection_regressions.py`，复用现有测试的已知 DNS 字面常量及标准库临时目录机制。
现有 normalize、native provenance、root-dot、DNS 和生成依赖测试纳入回归，不修改它们。
只修改 `rules.py` 中顶层 keyword 包含去重的判断及本任务新增测试、规格、计划。
配置、fixtures 和输出格式均保持现状，测试 fixture 在操作系统临时目录创建。
不修改 `formats.py`、`generate.py`、`README.md`、生产 `static/` 或生成产物。

## Requirements

- R1. 同组覆盖 keyword 来自 `mihomo`、以 `.` 结尾，而较长 keyword 不以 `.` 结尾时，前者不能作为删除后者的依据；包含关系适用于任意子串位置。
- R2. 其他已成立的包含归约保留，包括普通 Surge/QX、native 安全短 keyword、两个 native keyword 均以点结尾，以及额外安全 `123` 同时覆盖 `123.`、`123.45` 的情况。
- R3. 去重继续保留 `allow`、`options`、`literal_process`、`native_fields`、`domain_source` 分组，返回排序和一次性 iterable 支持不变。
- R4. `render` 保留各目标已有安全判断和计数规则，不将末尾点 native keyword 强行输出到 Surge/DNS，不从 logical 中删除 keyword leaf，不删除相邻其他类型。
- R5. `block/direct/proxy` 与 `add/strip/keep` 均保留有效的长 keyword 投影；非 block DNS 仍仅有说明，DOMAIN-SET 不承载 keyword。
- R6. 公共 `allow=True` 的同组 native keyword 保留有效 DNS `@@`。该入口是公共 Rule 构造，不声称 native YAML 提供 allow marker。
- R7. native keyword 对生成的 `fin.yaml` 用作 sources 或 whitelist 后，同轮及非空磁盘 bytes 重导入均保留相同可表达正文和 DNS 例外；外部 whitelist 原本不经过 normalize，其解析不修改。
- R8. 完全 unsupported 的组仍冻结旧六文件，存在有效投影的组仍发布，同轮空生成来源仍合法，disk-only 空来源仍严格拒绝；生成依赖正文校验不放宽。

## Acceptance Examples

| 场景 | 预期 |
|---|---|
| native `123.`、`123.45`，正序、逆序、重复输入 | normalize 保留两者；Surge full/split 各有 `DOMAIN-KEYWORD,123.45`，block DNS 有长 keyword 一行 |
| native `.` / `123.45`、`23.` / `123.45`、`45.` / `123.45.67` | 任意位置的末尾点短 keyword 均不提前删除可表达长规则 |
| native `123`、`123.`、`123.45` | 仅保留安全覆盖 keyword `123`，六目标继续按其支持范围输出 |
| 普通 Surge 或 QX `123.`、`123.45` | 保持已有短 keyword 包含去重，比较目标匹配范围，不要求冗余行数不变 |
| 两条 native keyword 都以点结尾 | 保持原有包含归约，Surge/DNS 仍局部 unsupported |
| 两条 public native allow 与普通 keyword `45` blocker | DNS 长 keyword 的 `@@` 在 blocker 前，拦截正文保留 |
| 生成 whiteparent/fin.yaml 再作为 whitelist | block DNS 保留长 keyword 的 `@@`，不把生成白名单当作隐藏 Rule 缓存 |

无白名单的两规则 block 案例诊断为 `fin.txt:DOMAIN-KEYWORD=1`、`fin-surge.txt:DOMAIN-KEYWORD=1`、`fin-adb.txt:DOMAIN-KEYWORD=1`、`fin-surge-ds.txt:DOMAIN-KEYWORD=2`，不出现 whitelist-covered。
Mihomo/QX 允许保留冗余长规则，测试不把来源冗余文本数量当作目标覆盖证明。

## 边界与验收

覆盖 `payload:` / `rules:`、plain / single-quoted / double-quoted scalar、输入逆序、重复输入、一次性 iterable。
字符回归区分字面引号、反斜杠、内部 ASCII space/tab、非 ASCII whitespace 和已解码控制字符，保留现有目标编码或局部 unsupported，不推断未知客户端语义。
native 字段逗号仍分隔 payload 与 params；控制字符 guard 保持。
顶层相邻 DOMAIN、DOMAIN-SUFFIX、DOMAIN-WILDCARD、DOMAIN-REGEX、IP 和 PROCESS 保留，AND/OR/NOT 及嵌套 leaf 顺序不变。

每个新增行为从公开 seam 的失败测试开始，使用已知正确的字面预期，随后完成最小实现与回归。
相关测试和完整 unittest 在 Debian WSL 的 Linux Python 执行，fixture 使用 Linux 临时目录，记录实际命令和终态。
提交前核对规格、代码范围、测试有效性、无循环依赖、`git diff --check` 和静态输入不变，再提交英文 commit。
不启动客户端，不执行生产远端下载，不新增依赖、配置、通用投影抽象或性能重构。
