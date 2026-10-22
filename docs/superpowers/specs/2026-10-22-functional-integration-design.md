# 已完成功能组件集成设计

## 目标与基准

将已完成的生成路径、wildcard／HTTP 和 CI 发布组件整合到独立分支，核查它们共同使用的读取、转换及发布接口。保留最新生产规则及 README 数量，供后续字段联动任务合并。

初始基准为 `4c1f29d55e47f939b96cf87a5284f947938191ed`。本轮仅合并下列固定提交，使用正常 merge 保留各自历史。

| 输入 | 固定提交 | 内容 |
| --- | --- | --- |
| 生产更新 | `d9d2a0bab2fe7e2d2938967c28607f7caebb0564` | 包含 `966282ff34a9fb95e11aaaebd0886077f9dc0d1e`，仅生成文件及 README 数量 |
| 生成路径 | `bd58d31daad7de73618776c81d3502e6616497ae` | static 后代 alias 预检、DOMAIN-SET 来源上下文及 whitelist 缓存区分 |
| wildcard／HTTP | `94617628ba6b83d7cd44e8930f94f9dfee6b8280` | wildcard 输入、DNS 局部投影及预算，包含 HTTP `fe34c69abe6695af86c796da003400d68ee7e12d` 历史 |
| CI 发布 | `c6b1ec0a041ff89072eaa52b40e84cf92f96e6a9` | `update.py`、Actions 同 SHA 与 superseded 判定、已有文件保留 |

## 已核查的调用与文件范围

已从固定提交读取各组件规格、计划、生产差异及公开回归，核查 `generate`／`publish`／`fetch_https`、`resolve_source`／`load_config`、`parse`／`parse_whitelist`、`normalize`／`exclude_covered`、`render` 及 wildcard／DNS 消费者、`update` 和 README 数量更新。

生成路径和 HTTP 修改分别位于 `generate.py` 的路径／依赖部分与 fetch 部分；wildcard 修改位于 `rules.py` 和 `formats.py`；CI 使用上述真实接口，不复制生成逻辑。README 的计数、wildcard／DNS 和 Actions 段各有独立来源。公开签名、配置、六产物名称、static 输入和依赖保持。

本轮新增文档仅为本规格及 `docs/superpowers/plans/2026-10-22-functional-integration.md`。合并范围包括组件已有文档、六个新测试模块、三个既有功能测试的小范围预期修改、workflow 结构测试，以及固定生产更新。只有公开接口测试复现的真实集成缺陷可追加最小修正及对应测试。

## Requirements

### 历史与生产内容

- R1. 四个固定输入均成为最终 HEAD 的祖先，保留两个 bot 提交；不使用 reset、stash、force push 或整文件选边解决冲突。
- R2. 最终配置列出的全部 42 个生产规则文件，其 mode／blob 与固定生产更新完全相同；README 计数区也与该提交相同，同时保留组件 wildcard／DNS 和 Actions 段。
- R3. 合并后的生产实现只能来自固定组件或本轮先复现再修正的集成缺陷；不新增配置、依赖、parser、Rule 缓存或无关重构。

### 正常功能验收

- R4. 运行公开接口回归，确认单标签 DOMAIN-SET alias 的同轮／disk source／white、格式优先级、whitelist 上下文区分及已有 static symlink 输入 bytes 保持。
- R5. 确认 native wildcard 经 Surge／Quantumult X 实际生成 bytes 回读，safe pattern 保留，未证明 literal 只跳过 DNS；普通 DNS 预算、native 来源边界及原有 no_resolve 行为保持。
- R6. 确认 chunked ASCII OWS 的正常 source／remote white 与 canonical 输出一致；截断时整轮旧产物和 static bytes 保持，继续使用真实标准库 HTTPResponse 解码。
- R7. 确认 CI 的正常发布、无变化、superseded、tracked／untracked／ignored 已存允许路径及无关文件保留。测试使用真实临时 bare origin、runner 和 writer，不 mock Git 成功、生成器或 publish。

### 验证与交付

- R8. 使用最终提交的完整 git archive，经标准库 tarfile 解包到 Debian WSL 的 Linux `/tmp` 独立 snapshot；逐文件核对路径、mode、Git blob 和 SHA-256，并在测试前后确认受控 bytes 相同。
- R9. 先运行已有新模块和相关 suite，再完整运行 Linux unittest discovery，实际等待退出。不修改既有 timeout、skip 或异常处理掩盖失败；保留已有十个 Windows-only skip。
- R10. 完成规格与简化复审、diff 范围及历史检查，提交必要修改，保留 clean 集成分支及已忽略的 `.tmp/integration-verification` 日志／manifest，清理仅本轮创建的 OS 临时 fixture／snapshot。

## 验证依据

复用 `tests/test_generator_alias_regressions.py`、`tests/test_wildcard_dependency_regressions.py`、`tests/test_ordinary_wildcard_dns.py`、`tests/test_chunked_ows_regressions.py`、`tests/test_ci_publication.py` 和 `tests/test_workflow.py`。相关回归覆盖生成／字节依赖、static maintenance／migration、transport、来源及 README 数量。上述测试在合并树上使用共享生产实现，不另建重复矩阵或测试抽象。

若出现真实集成问题，先在公开入口添加能失败的最小回归，再修改唯一根因，重跑受影响测试及最终完整 suite。只允许隔离真实网络和时间边界；所有 fixture 写 Linux 临时目录，不写生产目录。

## 范围限制与后续依赖

字段联动分支仍在运行，本轮不读取或合并它，不把当前集成称为最终全部功能验收。待其完成并纳入最终树后，再进行真实全上游生成和 42 产物验收。

本轮不 fetch 真实全上游、不触发 GitHub、不 push、不合并 main、不清理其他 worktree／分支。不开展网络安全扫描、修复或加固，不运行客户端，不做 Windows／多平台适配，不调查本机系统，不处理已知 Mihomo suffix 大小写，也不批量改写 suffix regex。
