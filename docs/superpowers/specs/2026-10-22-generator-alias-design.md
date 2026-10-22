# 生成器路径别名修复设计

## 目标与范围

基准为 `4c1f29d55e47f939b96cf87a5284f947938191ed`。修复 static 后代链接目标的写入保护，以及改名文件别名的 DOMAIN-SET 来源上下文。公开 `generate(root, fetch)`、`publish(outputs, root=...)`、CLI 参数和六种产物名称保持兼容。

仅修改 `generate.py`，新增 `tests/test_generator_alias_regressions.py`，交付本规格及 `docs/superpowers/plans/2026-10-22-generator-aliases.md`。不修改 parser、`sources.py`、其他既有测试、生产配置、static 输入、README、Actions 或已生成产物，不增加依赖。

## 已核查的行为与影响

`generate` 使用 `_output_path` 预检六种产物，将 canonical 路径映射到原生成路径。`publish` 对全部输出和 `.tmp` 预检，再写暂存文件、创建输出目录及替换文件。CLI 和 Ubuntu Actions 使用 `publish(generate(...))`。来源及 whitelist 均经 `resolve_source` 返回 root 内的 canonical 本地路径或 HTTPS URL。

当前 `_output_path` 保护 static 根及其自身的 resolved 目录，并检查输出路径经过的链接链。`static/main -> ../sample` 时直接写 `sample/fin*` 不经过该链，可改变 static 可见的旧文件。后代文件链接存在同类精确目标保护缺口。

当前 `is_domain_set` 只检查 resolved 文件名。`parent/fin-surge-ds.txt -> ../storage/saved-output.list` 失去格式上下文，父组合法正文 `localhost` 在同轮 source／whitelist 依赖中被拒绝；仅查询本轮生成路径映射仍不能解决移除父组配置后的磁盘读取。

影响调用方为 `generate` 的输出预检和五处格式判断、`publish` 的输出／staging 预检。`load_config`、`resolve_source`、`parse`、`parse_whitelist`、`render` 的接口不变。新测试采用现有 unittest、真实临时目录与相对 symlink；复用适用的六产物 fixture helper。配置、导出、部署和产物无需修改。使用别名的用户会得到明确的写入拒绝或可正常发布的 DOMAIN-SET 依赖；无冲突的普通构建行为保持。

## Requirements

### Static 保护

- R1. 每次公开调用依据当前文件系统计算 static 保护范围，保留 static 逻辑根和 resolved 根保护。static 可达后代目录 symlink 的 canonical 目标整棵子树受保护，后代文件 symlink 的 canonical 精确目标受保护。
- R2. 跟随目录别名继续检查其中的后代链接，按 canonical directory 去重，保证多层目录、重复别名和指回祖先的目录循环终止。自引用等无法解析的链接错误可直接显露，不能写入后继续处理。
- R3. `generate` 对全部生成目标、`publish` 对全部输出及 `.tmp` staging 应用共享预检。冲突须在任何暂存写入、建目录或替换前抛出 `ValueError("Output path targets static")`。健康邻组、冲突组全部六个旧文件、输入 bytes 和 symlink 保持不变，不留下新输出目录或暂存内容。
- R4. 文件目标保护只禁止精确目标，允许其同目录其他输出。保留可编辑 static 链接输入、无关输出、非 static root／directory／file／staging aliases、`static/../products`、无 static 场景，以及既有 root 边界和碰撞拒绝。两次调用之间链接变化必须重新生效，无跨调用缓存。

### DOMAIN-SET 上下文

- R5. 同轮生成路径优先使用 `paths` 映射中的实际生成文件格式，包括通过逻辑别名或 canonical 目标引用。物理目标名为 `saved-output.list`、`fin.yaml` 或 `fin-surge-ds.txt` 时均不能覆盖真实生成格式。
- R6. 非生成本地路径继续识别 resolved 文件名，并保留配置 entry 显式 `fin-surge-ds.txt` 的上下文；本地 entry 按既有约定支持反斜杠。移除 parent 配置后的非空 disk-only source 和 whitelist 均能读取同一 DOMAIN-SET bytes。
- R7. HTTPS 仍只按现有 URL path basename 解码后判断，不以 query、host、尾斜杠或编码路径分隔符扩大识别。逻辑和物理文件名均无 DOMAIN-SET 上下文的普通裸单标签仍拒绝。
- R8. localhost、x、123 单标签 exact、多标签 exact、前导点 suffix 和 IPv4 样式的合法域名对照（如 `01.2.3.4`、`256.1.1.1`）保留实际 bytes 语义。真正的 IP 地址 `192.0.2.1` 仍按既有域名校验拒绝，不恢复隐藏的上游 DOMAIN Rule；同轮与磁盘取得相同结果。
- R9. 本地 whitelist 的解析结果按实际来源上下文复用，两个不同 entry 指向同一文件时，普通 entry 不能继承另一个 entry 的 DOMAIN-SET 权限，顺序不影响该边界。

### 保留行为与执行条件

- R10. 六格式 alias、前向依赖拒绝、冻结传播、完整旧产物要求、空 disk-only 严格校验、生成正文严格校验、bytes 依赖、输出碰撞、root 边界及事务回滚保持。
- R11. 使用标准库和现有 parser，不新增 Rule 缓存、sidecar、配置项、通用别名框架、TOCTOU／并发安全扩展或外部客户端执行。错误按既有处理显露，不宽泛捕获或回退。
- R12. 各缺陷逐个行为测试执行 red -> 最小 green，随后相关回归、完整 suite、规格审查、简化、修正、复审和本地英文提交。规格先提交，详细计划随后提交，两个修复分别提交。

## 设计

static 保护范围在每次 `generate`／`publish` 开始时建立一次，供该次所有 `_output_path` 检查复用。遍历 static 可达目录时使用 canonical visited 集合，收集受保护目录及文件。保留既有输出祖先／链接链检查和 escape 检查，将新目录及精确文件保护应用于相同候选位置及最终 canonical 输出；不缓存到后续调用。

DOMAIN-SET 判断复用现有生成路径映射，私有 helper 同时接收 canonical source 和原 entry。生成映射有该路径时，其格式为唯一依据；非生成本地路径结合显式 entry 与 resolved 文件名；URL 分支保持。五个 parser 调用使用同一判断。本地 whitelist 结果按来源路径及格式上下文区分，避免不同 entry 共用错误解释。

## 公共接口验收

| 边界 | 输入与操作 | 可核查结果 |
|---|---|---|
| generate | static 后代目录目标直接等于 sample，或其他非 static alias 指向该目标 | 预检拒绝，全部旧 bytes 与链接不变，未 fetch，未建 staging |
| 独立 publish | 健康输出、新目录输出在前，static 后代目录或文件的物理目标在后 | 原子预检拒绝，不写前面的健康输出，不建新目录或 `.tmp` |
| staging | static 后代链接指向 `.tmp`，或 `.tmp` 指向受保护目标 | 暂存前拒绝，已有 staging 内容及链接不变 |
| 遍历 | static 多层目录链接、重复别名、可解析的祖先循环，以及深层文件链接 | 能发现实际目标且遍历终止；无关输出可成功 |
| 文件保护边界 | static 文件链接与普通产物在同一物理父目录 | 目标拒绝，相邻合法产物正常发布 |
| 调用间变化 | 首次无冲突，随后新增或移除 static 链接再调用 | 保护范围依据当次状态，不使用旧缓存 |
| 同轮依赖 | DOMAIN-SET 文件改名到 saved-output.list／fin.yaml，source 和 whitelist，逻辑或物理 entry | 单标签正常处理，六产物符合字面预期，父组新 bytes 生效 |
| disk-only | 先发布，删除父组配置及原输入，再通过显式 DOMAIN-SET entry 读取 | 非空 source／whitelist 的六产物与同轮一致，父文件及链接不变 |
| 实际格式优先级 | 非 DOMAIN-SET 生成文件的目标叫 fin-surge-ds.txt，entry 也可显式叫 fin-surge-ds.txt | 仍按实际生成格式，不能把 native YAML 单标签扩成普通 Surge 域名 |
| 严格边界 | 普通裸单标签、同文件混合上下文 whitelist、空 disk-only | 按现有本地严格校验拒绝，全部旧产物不变 |

单标签与改名 alias 交叉覆盖 `block/direct/proxy`、`add/strip/keep`；输出检查使用已知正确的字面正文，ADB 时间沿用既有测试的时钟隔离或 header 验证。文件系统与依赖 bytes 使用真实文件，不 mock 路径解析。

## 验证环境与完成条件

交付目标是 Ubuntu Actions。采用已有 Debian WSL 的 Linux Python 3.13.5 执行，新增 fixture 使用 Linux `/tmp`，使用真实相对 symlink，不启动外部客户端或二进制。相关回归包含 `StaticAliasPublishTests`、`DomainSetSingleLabelGenerateTests`、`GenerateTests` 的 alias／冻结／前向依赖／事务测试，以及 static maintenance、migration、sources 和生成 bytes integration；完整执行 `python3 -B -m unittest discover -s tests -v` 对应的 unittest discovery，不减少既有测试或新增 skip。

完成时记录每个 red 的实际异常、对应 green、两次修复后的完整 suite 终态和 Git diff 检查。修改仅限四个约定文件，未新增重复实现、无关选项、依赖或 module docstring。最终交付提交身份和未核验项，不以本地 Linux 通过冒充真实远程 Actions 执行。
