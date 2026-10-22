# 最终功能集成与本地验收设计

## 目标与固定输入

在独立 worktree 中整合全部已确认功能修正，验证共同使用的读取、转换、去重和发布接口，并用真实上游 bytes 生成、验收七组共 42 个文件。本阶段不修改 main，不 push，不触发远程 Actions。

初始基准为 `4c1f29d55e47f939b96cf87a5284f947938191ed`。正常 merge 以下两个固定 head，保留全部历史。

| 输入 | 固定提交 | 包含内容 |
| --- | --- | --- |
| 部分集成 | `a66e7814caacbfb87f63979d497ff1e094c13c6d` | 生产 `d9d2a0bab2fe7e2d2938967c28607f7caebb0564`、生成路径 `bd58d31daad7de73618776c81d3502e6616497ae`、wildcard `94617628ba6b83d7cd44e8930f94f9dfee6b8280`、HTTP `fe34c69abe6695af86c796da003400d68ee7e12d`、CI `c6b1ec0a041ff89072eaa52b40e84cf92f96e6a9` |
| 字段联动 | `badfbfb60b7b55e95ab6f72a260088695f3c6afc` | keyword `6ff16a9bdbbf2c29530a6d5f51c5ff7f497459ed`、routing `30968e03c2acdc0f50dcbb42345284ed361fdc10`、Go 名称空白、QX 字段边界、markup、raw Mihomo 字段和目标能力去重 |

生产基准包含 bot 提交 `966282ff34a9fb95e11aaaebd0886077f9dc0d1e`。工作分支中的 42 个受控产物及 README 数量保留该生产基准；真实新产物仅写入独立验收副本。

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
- R5. 新 wildcard pattern 经 ordinary／Surge／QX／YAML 实际 bytes 回读；marker、奇数尾反斜杠、引号、括号、非 ASCII 和 markup 按目标局部支持。scalar／logical、source／white、同轮／disk-only、三个 purpose／三个 no_resolve、source-IP 方向及 static／旧产物保留同时成立。
- R6. 短 keyword 在某目标 unsupported 时不能删除该目标可表达的长项。实际 Rule Unicode 原值、native ignored-tail、root-dot、allow／options／来源身份、逆序和一次性 iterable 保持。普通安全包含仍归约，外部原始 white 与生成 parent white 使用各自真实流程。

### 最终代码验证

- R7. 使用最终提交完整 git archive，以标准库 tarfile 解包到 Debian WSL Linux `/tmp` 新目录。记录 commit、tree、所有受控路径／mode／Git blob／SHA-256；测试前后全部相同。Python 使用 `-I -B` 并显式加入可信 root，不在 `/mnt/c` 运行重型 suite。
- R8. 实际完成相关联合回归和完整离线 unittest discovery，无 failure／error；保留十个既有 Windows-only skips，不修改 timeout 或 skip。代码或测试变化后重新验证最终提交，不将旧组件日志算作最终树证据。

### 真实来源与产物

- R9. 从最终 `rulesets.json` 枚举全部远程角色，以最终 `fetch_https` 真实 HTTPS 读取每个唯一 URL。每份数据置于独立新空目录，保存 URL、bytes、SHA-256、全部角色、公共 parser 结果及 warnings。代码／脚本和下载目录分开，Python `-I`，不执行下载内容或客户端。已有 fetch cache 仅固定本轮真实获取的 bytes，不作替代来源。
- R10. 用同批固定 bytes、最终 `generate`／`publish` 在独立可信代码副本生成 42 个原始 LF 文件并更新副本 README 数量，static 前后 hash 相同。保留全部生成诊断；受控生产文件不变。
- R11. 实际运行既有 `accept_artifacts.py`，可信 `--root` 与独立 `--artifact-root` 分离，baseline 为 `d9d2a0b` 原始 blobs 的验收 JSON。完整检查路径／count／UTF-8 LF／排序／重复／no-resolve／Surge split／DNS 每行 65,536 bytes／单文件 100 MiB／README。不预处理 CRLF。以相同上游 bytes 在固定生产代码生成对照，逐组／格式解释数量及大小差异，不用任意比例判断。
- R12. 完成规格、功能／回归、简化复审及必要修正。最终受控改动全部英文提交，`git diff --check` 通过且工作区 clean；保存已忽略 `.tmp/final-verification/` 的脚本、原始来源、日志、manifest 和验收 JSON，清理本轮无需保留的 OS 临时目录。

## 验证依据

复用 alias、wildcard dependency、ordinary wildcard DNS、chunked OWS、CI、keyword、routing、target field 及既有 generate／rules／formats／YAML／static／transport／README 公开测试。联合缺口才新增小型回归，不复制已有矩阵。新问题先具体 red，再最小修复及 green，随后完整回归和产物重验。

真实构建复用 `load_config`、`resolve_source`、`fetch_https`、`parse`、`parse_whitelist`、`generate`、`publish` 和 README update，不另写 HTTP 或规则 parser。测试 fixture 使用 OS 临时机制；需复用的证据保存在已忽略工作目录，运行解释器的 cwd 始终为可信代码或脚本目录。

## 范围限制

不启动客户端，不进行网络安全扫描或修复，不做本机／多平台适配，不调查本机已知系统问题，不处理 Mihomo YAML DOMAIN-SUFFIX 大小写，不增加批量 regex suffix 改写。不重新开启未确认的手工 SRC-IP canonical、GEOIP LAN 或普通 keyword 特殊 Host 结论。闭源运行语义不由转换器公开 bytes 测试推断。main 合并、push、远程 Actions 和远端产物验收由后续阶段执行。
