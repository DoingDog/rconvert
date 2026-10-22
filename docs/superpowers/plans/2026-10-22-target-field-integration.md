# Target field integration plan

## 目标与完成条件

落实 [规格](../specs/2026-10-22-target-field-integration-design.md) R1-R5。保留 Rule 与已支持目标，仅跳过不能保真输出的投影；normalize 不删除其他目标仍需要的长 keyword。所有行为有公开接口 red -> green，真实 generate／publish／bytes 集成通过，完整 Linux suite 通过，授权文件全部提交且工作区干净。

## 基线与执行边界

工作目录 `.claude/worktrees/wf_a93219fd-057-4`，分支 `worktree-wf_a93219fd-057-4`，初始 HEAD `4c1f29d`；顺序合并 keyword `6ff16a9bdbbf2c29530a6d5f51c5ff7f497459ed` 和 routing `30968e03c2acdc0f50dcbb42345284ed361fdc10`，合并基线 `a809a1e`。初始及合并后工作区干净，既有提交全部保留。

当前子任务是外层 workflow 的独立工作单元。R1-R5 共用 formats／rules 字段能力，顺序执行以保持逐行为 TDD；独立 wildcard owner 只修改 `_valid_domain`，此处禁止触碰该区域或其他 worktree。只在本分支提交，不 push、不修改 main。外层 workflow 负责合并与最终 worktree 清理。

## 调用与验证路径

`parse` -> `normalize` -> `render`；`parse_whitelist`／公开 allow -> 同目标字段投影 -> coverage；临时 root `generate` -> 实际 `publish` -> UTF-8 bytes `parse`／移除父配置后的 `generate`。所有 expected 为规格确定的文本／matcher；不对私有 helper 写测试，不修改 parser 行为或 strict generated readback。

## Implementation Units

### U1. Go 名称判空

- 文件：`formats.py`，`tests/test_target_field_integration.py`，README 支持段。
- 一个 ordinary quoted U+001C 名称 logical 失败测试 -> 复用 `_valid_name_list` -> 相同测试 green。
- 扩展 U+001C..U+001F、三个名称、scalar／AND／OR／NOT／嵌套、ordinary／native escaped YAML、Go whitespace-only 拒绝和 `/` 列表正例。
- 核查：三 purpose／no_resolve；实际生成／发布／disk source；空 Surge 产物同轮 source／white 可用，disk-only 空产物严格拒绝；含名称／logical 的 generated whitelist 仍拒绝。
- 相关回归：routing fields、rules、native YAML、formats。

### U2. Raw Mihomo 域名 ASCII space

- 依赖 U1；文件同上。
- 先用 QX quoted keyword 的 `fin.yaml` 回读失败例 -> `_domain_value` 最终 raw 域名字段局部 guard -> green。
- 扩展公共 raw 四域名类型、首／尾／两端空格、qx logical AND／OR／NOT／嵌套、内部空格／HTAB／NBSP、普通 Surge regex／PROCESS hex 正例。
- 核查：route whitelist 相同判定，外部与生成 white 不产生裸 keyword 删除；实际同轮／disk generate／publish，三 purpose／no_resolve，健康邻居和旧 bytes。

### U3. 普通目标字段回读

- 依赖 U2；文件 `rules.py` 共享普通字段能力、`formats.py` 三处消费者、新测试、README。
- 先确认 native keyword `<tag>` QX 输出不应存在的 red -> 共享实际 markup 判定 -> green。
- 再单独确认 USER-AGENT `<123>` Surge／QX red -> 补已有非 regex process 角括号限制 -> green。
- 扩展 keyword `<!--123-->`／`<123>` 控制、DEVICE-NAME、四种 process、实际可达 logical／嵌套、URL-REGEX 正例、target-local diagnostics、公共 Rule、route white。
- 核查：source／white 同轮依赖不因输出坏行中止；真实发布及非空磁盘读回；来源 HTML 拒绝和 strict generated whitelist 不变。

### U4. QX wildcard 字段边界

- 依赖 U3；将现有 QX guard 移到 `rules.py` 明确远离 `_valid_domain` 的位置，formats 直接 import，共享给输出／white。
- 一个 native quoted wildcard 空白后 marker red -> 扩展现有 USER-AGENT 条件到 wildcard -> green。
- 奇数尾反斜杠单独 red -> 最小 green（若同一已确认条件覆盖，记录该测试在 U3 基线的真实 red，不回退工作区）。
- 核查三 marker、ASCII space／HTAB／NBSP、keyword literal 正例、USER-AGENT 偶数反斜杠、interface-option 精确计数、公共 allow／white、实际 source／white 同轮和 disk 依赖。一般 wildcard validator 与 DNS 联动留给指定联合任务。

### U5. Keyword 目标能力去重

- 依赖 U4；文件 `rules.py` normalize、新测试、README。
- 短 `'123`／长 `9'1238` native QX 丢失 red -> 复用同一 QX 字段能力补删除资格 -> green。
- 检查本次普通字段／Mihomo raw 边界的包含非单调性；仅有实际反例时补资格，不能复制 guard 或建立通用投影框架。
- 核查单双引号、ASCII（ordinary）／HTAB／NBSP／U+2003 边缘嵌入长项、三来源、root-dot 原有资格、安全短项归约、allow／options／来源身份组、逆序／重复／一次性 iterable。
- 实际外部 white 与生成 QX parent white 对照；source、allow、预先 normalize 的 white、三 purpose／no_resolve、publish 后 bytes 及 disk-only 重读。

### U6. 联合复审与完整验证

- 按规格 R1-R5 逐项检查覆盖；确认无重复能力判断、额外抽象、缓存、公共字段和无关改动。
- 所有新增测试、keyword／routing／YAML／formats／rules／generate 定向回归通过。
- 提交后的 HEAD 用 `git archive`，标准库 tarfile 解压到已有 Debian WSL Linux `/tmp` 的新临时目录，再用 `python3 -I -B` 执行完整 `unittest discover -s tests -v`；不修改 skip／timeout，不运行生产 generate 或客户端。
- 检查 `git diff --check`、修改范围、输入／产物 bytes、工作区干净。修正任何本任务问题后重新复审和全量验证。

## 提交与证据

先英文提交 spec／plan。每个完成行为簇通过相同 red 测试、相关回归、规格审查和简化后分别英文提交；不将失败代码留给外层会话。进展与真实 red／green 记录在执行输出及提交，计划只描述工作要求。最终返回绝对路径、branch／base／head、所有 commits、修改范围、实际命令与 suite 结果、审查结论、未检查项和剩余风险，不创建报告文件。
