# Target field integration design

## 目标与依据

保留公开 `Rule` 的 matcher，修复字段转换、包含去重和生成依赖之间已复现的正常功能差异。输入拒绝、HTML 检查及 generated readback 的严格校验保持。目标无法保真表达时仅计该目标 unsupported，logical 任一叶子失败时跳过完整规则。

基线由 keyword commit `6ff16a9bdbbf2c29530a6d5f51c5ff7f497459ed` 和 routing commit `30968e03c2acdc0f50dcbb42345284ed361fdc10` 顺序合并。三份独立公开接口反证均确认以下问题，实施中仍用本分支公开接口核实具体输入及正例。

| ID | 已确认的观察 | 当前调用位置 |
| --- | --- | --- |
| R1 | `IN-NAME`／`IN-USER`／`REMATCH-NAME` 的 U+001C..U+001F 名称经 parse 保留，logical renderer 的 Python `strip()` 将其判空 | `formats._logical_value`，`rules._valid_name_list` |
| R2 | QX `HOST-KEYWORD,' 123 ',LIST` 生成 raw Mihomo keyword 后，bytes 回读裁剪为 `123`，生成白名单改变删除结果 | `_domain_value`、`_mihomo_rule`、`_logical_value`、`_route_whitelist` |
| R3 | native keyword `<tag>`／`<!--123-->`、部分非 regex process／USER-AGENT／DEVICE-NAME 的 `<123>` 被写入普通目标后遭公开读取器拒绝 | Surge scalar／logical、QX scalar、route whitelist |
| R4 | native wildcard 的空白后 `#`／`;`／`//` 在 QX 回读被截短；奇数尾反斜杠吞入 `,LIST` | `_qx_field_supported`，QX output／whitelist |
| R5 | 起始引号或边缘空白的短 keyword 在 QX unsupported，normalize 仍删除可表达的长 keyword | `rules.normalize`、render、allow、生成父组 |

## 公共接口与调用方

- `parse`／`parse_whitelist`：确认真正可达的 ordinary／native 输入、值和 warning；不访问 parser 隐藏通道。
- `normalize`：一次性 iterable、逆序、重复、身份组以及 block／allow 的包含去重；不改变函数签名。
- `render`：检查六文件实际正文、原 `Rule`、目标局部 unsupported、顶层 logical 计数、白名单删除及 interface-option 诊断。
- `generate`：真实临时 root 的 source／whitelist 依赖、健康邻居、合法空产物、冻结边界及发布前旧 bytes。
- `publish` 后重新 `generate`／`parse`：核对真实 UTF-8 bytes 与返回文本相同，非空 disk-only 依赖使用同一读取器。

这些接口及其上述用途由任务明确指定。测试不调用私有 helper，不用 mock 提供转换结果，不从输出反推 expected。

## 行为要求

### R1. Go 名称列表判空

仅三个名称类型复用现有 `_valid_name_list`，保持每个 `/` 段的 Go Unicode White_Space 规则。U+001C..U+001F 为非空名称；Go whitespace-only 或空段仍无效。其余 kind、UID／DSCP、native ignored 参数及 no-resolve 的处理保持。

名称 scalar、AND／OR／NOT／嵌套、ordinary quoted 和安全 YAML Unicode escape 均保持公共值。Mihomo YAML 使用现有编码输出并可重新导入。Surge／QX 不新增名称类型支持；generated whitelist 含名称或 logical 仍按现有严格规则拒绝。

### R2. Mihomo raw 域名字段

最终 raw `DOMAIN`／`DOMAIN-SUFFIX`／`DOMAIN-KEYWORD`／`DOMAIN-WILDCARD` 若因字段边缘 ASCII space 裁剪而改变 matcher，仅该 Mihomo 目标 unsupported。scalar、logical 及 route whitelist 使用同一判定。普通 Surge keyword／wildcard 的既有 regex 转换继续保留字面空格；普通 PROCESS-NAME hex regex 不变。

不修改公共 value，不全局 strip，不改变内部空格、HTAB、非 ASCII whitespace、native 初次输入的 ASCII trim，或名称列表有意采用的 Go TrimSpace。QX logical 反例只使用公共 Rule，当前文本入口不支持 logical HOST-KEYWORD alias。

### R3. 普通目标字段可回读性

Surge scalar、Surge logical 叶子和 QX 字段只输出其普通读取器可接受的最终字段。复用现有 HTML markup 条件及非 regex process 类角括号限制；与 route whitelist 共享，不能发布后依靠生成依赖发现错误。

保留 `DOMAIN-KEYWORD,<123>`、`URL-REGEX` 的 literal-field 例外、native 原格式合法字段以及其他目标支持。Surge logical 的 HTML 检查沿用普通读取器的整行 literal-field 例外；含受支持 regex 叶子时仍保留可回读的 keyword markup，非 regex process 类角括号限制继续逐叶检查。native `USER-AGENT,<tag>`／`DEVICE-NAME,<tag>` scalar 不能通过当前 HTML 检查，相关扩展仅验证公共 Rule 或实际可达 native logical 组合。wildcard 的一般形状与 DNS 投影由独立 wildcard 任务及之后的联合任务负责，本任务不改 `_valid_domain` 或推断未知 Host 行为。

### R4. QX 字段边界

`DOMAIN-WILDCARD` 与 USER-AGENT 共用已确认的空白后 marker、奇数尾反斜杠保护。QX wildcard 的普通 lexer 遇到不平衡字面括号也会拒绝输出；复用该 lexer 判定目标 unsupported，不改变另一任务负责的 wildcard 形状验证。保留 HOST-KEYWORD 专用字面读取，内部引号、内部空白、keyword marker／一至三个尾反斜杠以及 USER-AGENT 偶数尾反斜杠正例。没有 QX 引用编码依据时局部 unsupported。

共享 QX guard 放在 `rules.py` 的非 validator 区域，供 renderer／white／normalize 使用；`rules.py` 不 import `formats.py`，不复制两套能力条件。

### R5. 尊重目标支持的 keyword 包含去重

仅当短 keyword 保留长 keyword 的已支持目标能力时，才允许包含归约。保持 native root-dot 资格条件；补齐 QX 起始引号／边缘空白等非单调限制，并考虑本次普通读取及 raw Mihomo 字段边界。共享已核实的字段判定，避免 normalize 与 renderer 分歧。

保持来源、allow、options、literal_process、native_fields 身份分组；ordinary／native／QX，反序、重复及一次性 iterable 均确定。`123`／`91238`、普通来源 `123.`／`123.45` 继续正确归约；不关闭全部 keyword 去重。block、公开 allow、预先 normalize 的 white 及生成父白名单都保留可表达长项。外部原始 whitelist 当前不自动 normalize，使用其真实流程作对照。

## 验收与范围

每个新行为先运行公开接口失败测试，再做最小修复及相邻回归，完成规格审查、简化和复审后英文提交。三种 purpose、三种 no_resolve、scalar／logical、外部／生成 white、同轮／disk-only source、实际 publish、输入保护、合法空依赖、原有严格 generated whitelist 均覆盖。

只修改 `formats.py`、`rules.py` 的共享字段判定及 normalize、README 对应支持段、新 `tests/test_target_field_integration.py`、本规格和计划。保留原有测试断言。不改 `_valid_domain` 及其相邻位置，不改 Actions／规则数量、generate 算法、配置、生产输出或 static。不新增依赖、Rule 字段、通用投影框架、配置或缓存。

完整 Linux suite 使用当前提交的 `git archive`，以标准库 tarfile 解压到 Linux `/tmp` 的新目录执行；测试无需客户端或远程来源。只清理本任务临时材料。所有已确认修正完成并通过完整 suite 后交付分支及提交，不 push，不改 main。

未执行范围：客户端、上游程序、远程 Actions、网络安全扫描或修复、Windows 适配、本机系统调查、Mihomo suffix 大小写及批量 regex 重写。QX 结论限转换器公开接口及实际 bytes，不推断闭源运行语义。
