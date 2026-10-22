# 最终功能集成与本地验收设计

## 目标与固定输入

在独立 worktree 中整合全部已确认功能修正，验证共同使用的读取、转换、去重和发布接口，并用真实上游 bytes 生成、验收七组共 42 个文件。本阶段不修改 main，不 push，不触发远程 Actions。

初始基准为 `4c1f29d55e47f939b96cf87a5284f947938191ed`。正常 merge 以下两个固定 head，保留全部历史。

| 输入 | 固定提交 | 固定 tree | 包含内容 |
| --- | --- | --- | --- |
| wildcard 角括号字段 | `a00ad3b53a66b18a93a1de3550d871d045b80f55` | `5a3ead353e56e6d71d858c2b3f84228a1b1522cb` | ordinary 字段 guard 移除 wildcard 整体角括号拒绝，numeric-angle scalar／logical／实际 bytes 与 markup／process 回归 |
| native 多尾点 QX 回读 | `685399b4a485fbab9f0475cc401cb92d9a5fd542` | `66a8a81d2421f9874d7df80a185ce97eebbb3568` | QX wildcard 分支复用普通 `_valid_domain`，同轮及非空 disk-only source／white 回归 |

共同祖先 `8e4aa6e108cb41248bc46ad6e6b86ecf982edf38` 已包含十二根因修正及 QX lexer 去除 `,LIST` 尾字段复制的一行内存修复。其历史包含部分集成 `a66e7814caacbfb87f63979d497ff1e094c13c6d`、字段联动 `badfbfb60b7b55e95ab6f72a260088695f3c6afc`、生成路径 `bd58d31daad7de73618776c81d3502e6616497ae`、wildcard `94617628ba6b83d7cd44e8930f94f9dfee6b8280`、HTTP `fe34c69abe6695af86c796da003400d68ee7e12d`、CI `c6b1ec0a041ff89072eaa52b40e84cf92f96e6a9`、keyword `6ff16a9bdbbf2c29530a6d5f51c5ff7f497459ed` 和 routing `30968e03c2acdc0f50dcbb42345284ed361fdc10`。

本轮 fetch 后固定 `origin/main` 为生产 `d9d2a0bab2fe7e2d2938967c28607f7caebb0564`，包含 bot 提交 `966282ff34a9fb95e11aaaebd0886077f9dc0d1e`，且已是两个输入的祖先。工作分支中的 42 个受控产物及 README 数量保留该生产基准；真实新产物仅写入独立验收副本。

## 调用与修改范围

核查 `generate`／`publish`／`fetch_https`、`resolve_source`／`load_config`、`parse`／`parse_whitelist`、`normalize`／`exclude_covered`、`render`、`update` 和 README 数量更新。扩大后的 `_valid_domain` wildcard 校验与共享字段能力判定必须并存；ordinary DNS 和 escaped-hyphen 处理、raw／markup／QX／logical 投影必须同时保留。

本阶段直接修改这两份集成文档；必要的联合回归使用已有公开测试和 helper。只有已观察到失败的真实集成缺陷才追加最小实现修正。公开签名、配置、六产物名称、static、依赖和既有严格读取规则保持。

## Requirements

### 历史与范围

- R1. 两个固定 head、其组件提交和两个 bot 提交均成为最终 HEAD 祖先。正常 merge，逐 hunk 解决必要冲突，不整文件选边，不 reset、stash、force push 或跳过 hooks／signing。
- R2. 42 个受控产物的 mode／blob 及 README 计数区与 `d9d2a0b` 相同；各格式说明、wildcard／DNS／字段及 Actions 说明全部保留。初始 main、其他 worktree、用户 `.claude/` 和现有改动不变。
- R3. 实现只来自固定组件及本轮已复现的最小修正。不得增加 parser、Rule 缓存、provenance sidecar、配置、依赖或推测性功能；不得关闭全部 keyword 包含去重或放宽 strict generated readback／HTML 检测。

### 十二根因与联合行为

- R4. 以公开调用验证 static 后代 alias 输入保留、DOMAIN-SET alias 格式上下文和 white cache、keyword 多目标去重、Mihomo process 边缘 space、nonregex 逗号、QX 字段承载、Mihomo logical 逐叶括号、DNS escaped-hyphen 来源语义、wildcard 普通回读闭合、Go 名称 whitespace、chunked ASCII OWS、CI fixed-tested-SHA／superseded 及已有 untracked／ignored 内容保留。
- R5. 新 wildcard pattern 经 ordinary／Surge／QX／YAML 实际 bytes 回读。合法 `*<123>*`、`*<123`、`*123>*` 的 ordinary／QX／native scalar 和 Surge logical 按既有目标能力保留；真正 markup、非 regex process 角括号拒绝和 URL-REGEX literal-field 例外保持。native `*..`、`..`、`*123..`、`a...` 只补齐 QX 局部 unsupported，YAML 原值及其他目标既有判定保持，ordinary 继续拒绝；`*`、`*123*`、`1..2*` 不回归。marker、奇数尾反斜杠、引号、括号、非 ASCII 和 class 继续按目标局部支持。scalar／logical、source／white、同轮／非空 disk-only、三个 purpose／三个 no_resolve、目的／来源 IP、static／旧产物保留同时成立；跨来源白名单只能删除实际覆盖项。QX allow／white 的超长 wildcard 必须通过原 2 MiB 内存阈值；共享字段 lexer 保留 `8e4aa6e` 去除 `,LIST` 的一行修复，不复制策略尾字段。
- R6. 短 keyword 在某目标 unsupported 时不能删除该目标可表达的长项。实际 Rule Unicode 原值、native ignored-tail、root-dot、allow／options／来源身份、逆序和一次性 iterable 保持。普通安全包含仍归约，外部原始 white 与生成 parent white 使用各自真实流程。

### 最终代码验证

- R7. 使用最终提交完整 git archive，以标准库 tarfile 解包到 Debian WSL Linux `/tmp` 新目录。记录 commit、tree、所有受控路径／mode／Git blob／SHA-256；测试前后全部相同。Python 使用 `-I -B` 并显式加入可信 root，不在 `/mnt/c` 运行重型 suite。
- R8. 实际完成相关联合回归和完整离线 unittest discovery，无 failure／error；保留十个既有 Windows-only skips，不修改 timeout 或 skip。代码或测试变化后重新验证最终提交，不将旧组件日志算作最终树证据。

### 真实来源与产物

- R9. 复用 `wf_c9c6f81b-00e-1/.tmp/final-verification` 已真实获取并完整解析的 56 URL／72 角色、18,071,088 bytes；以 `real-sources.json`、`remote-bytes`、`parsed-roles` 和 `final-evidence.json` 核对全部来源 hash、角色及 warnings。本轮不重新联网抓取。真实 fetch 发生于 `068e527`，核对其 `fetch_https` 与 `8e4aa6e` 及最终提交实现 hash 相同，如实记录抓取与重放身份。最终配置角色须与该批一致；数据和可信脚本分开，Python `-I`，不执行下载内容、客户端或上游程序。
- R10. 用同批固定 bytes、最终 `generate`／`publish` 在独立可信代码副本生成 42 个原始 LF 文件并更新副本 README 数量，static 前后 hash 相同。保留全部生成诊断；受控生产文件不变。
- R11. 实际运行同一 `C:/Users/user/Downloads/rconvert/.tmp/functional-audit-2026-10-21/acceptance/accept_artifacts.py`，可信 `--root` 与独立原始 LF `--artifact-root` 分离，以已保存 `acceptance-final.json`（`8e4aa6e`）或 `acceptance-baseline-d9d.json` 作为 `--baseline-json`，不在无 Git 元数据的 snapshot 使用 `--baseline-commit`。完整检查路径／count／UTF-8 LF／排序／重复／no-resolve／Surge split／DNS 每行 65,536 bytes／单文件 100 MiB／README，不预处理 CRLF。逐组／六格式实际比较 count、bytes 和正文；`8e4aa6e` 同输入基准为 42 文件／78,223,345 bytes／2,503,812 正文／35 路由 2,048,959，ADB Version header 独立记录。保留原 d9d 生产 78,125,149 bytes／2,500,723 正文及已完成同输入对照，区分上游变化（a3 各五格式 +309、a4 各五格式 +308、dirt 四格式 +1）和本轮代码差异。
- R12. 规格、功能／回归、简化复审限两个已确认修复的组合及实际 range，不重新开启无边界审计。所有受控更改先英文提交，再对最终 exact commit 验收；不在测试后修改文档造成身份差异。`git diff --check` 通过且工作区 clean，merge 等于固定 hunk 并集；保存已忽略 `.tmp/final-complete-verification/` 的完整脚本、日志、manifest、产物与验收 JSON及原始批次路径，清理本轮无需保留的 OS 临时目录。

## 验证依据

复用 alias、wildcard dependency、ordinary wildcard DNS、chunked OWS、CI、keyword、routing、target field 及既有 generate／rules／formats／YAML／static／transport／README 公开测试。联合缺口才新增小型回归，不复制已有矩阵。新问题先具体 red，再最小修复及 green，随后完整回归和产物重验。

真实构建复用 `load_config`、`resolve_source`、`fetch_https`、`parse`、`parse_whitelist`、`generate`、`publish` 和 README update，不另写 HTTP 或规则 parser。测试 fixture 使用 OS 临时机制；需复用的证据保存在已忽略工作目录，运行解释器的 cwd 始终为可信代码或脚本目录。

## 范围限制

不启动客户端，不进行网络安全扫描或修复，不做本机／多平台适配，不调查本机已知系统问题，不处理 Mihomo YAML DOMAIN-SUFFIX 大小写，不增加批量 regex suffix 改写。不重新开启未确认的手工 SRC-IP canonical、GEOIP LAN 或普通 keyword 特殊 Host 结论。闭源运行语义不由转换器公开 bytes 测试推断。main 合并、push、远程 Actions 和远端产物验收由后续阶段执行。
