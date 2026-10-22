# CI 过期运行发布设计

## 目标与范围

修复事件提交 A 已测试、远端 main 已前进时旧更新 job 发布失败的问题。workflow concurrency 只控制运行次序，排队及 rerun 仍保留原事件 SHA；分钟级 ADB Version 足以让两个 A 的运行生成不同提交。

保留 `test -> update`、两个 job 的事件 SHA、固定 `github.sha` checkout、main 且非 PR 的更新条件、北京时间 schedule、现有 concurrency 和 job 权限。只增加标准库 `update.py`、`tests/test_ci_publication.py`，精确修改 workflow 及结构测试、README 的 Actions 行为说明和本规格/计划。生成、格式、配置、static 及其他测试不修改。不增加依赖、分支/remote 参数、重试、dry-run、rebase 或 force push。

## 公共行为边界

`update.update(root: Path, tested_sha: str) -> str` 是行为测试入口，返回 `published`、`unchanged` 或 `superseded`。`update.py` 的 CLI 从 `GITHUB_SHA` 读取本轮已测试 SHA，root 固定为脚本目录。workflow 在 `needs: test` 成功后调用 CLI；入口本身不重复运行 suite。

行为测试调用真实入口，使用 OS 临时目录中的 bare origin、detached runner 和独立 writer，并实际调用 `generate`、`publish`、`update_readme_counts.update`。仅时钟及 HTTPS fetch 作为替换边界；Git、生成器、文件发布和 README 更新不模拟。观察返回值、原诊断、实际提交/父提交/文件 bytes、远端引用及剩余工作区状态。此边界验证本地发布协议，不证明 GitHub 服务的凭据、网络或新 SHA 的测试结果。

## 发布顺序与安全边界

1. 核对 `HEAD` 完全等于 `tested_sha`，否则失败；不切换或更新源码。成功执行 `git ls-remote --exit-code origin refs/heads/main`，要求唯一 main 引用。读取失败或缺失分支失败。若 tip 不等于 A，明确输出 superseded，并在生成、写文件和暂存前结束。这仅表示旧运行跳过。
2. 当前 tip 仍为 A 时，检查 index 没有既有暂存内容。已有暂存改动则失败并完整保留，防止把外部改动带入 bot 提交。无关的未暂存 tracked/untracked 内容不作为失败条件，不删除或暂存。
3. 复用 `publish(generate(root, fetch_https), root=root)`，随后调用 README 数量更新。使用 `load_config(root)` 的实际组名与 `formats.FILES` 构造精确的相对路径，再加 `README.md`。当前配置为 42 个产物加 README；数量随配置变化，不硬编码组名，不暂存目录、static 或源码。
4. 提交前再次成功读取远端 main。不同于 A 时输出 superseded 并跳过暂存、提交和推送；已生成的工作区文件保留，不 reset、clean 或丢弃已有内容。
5. 精确 `git add -- <允许路径>` 后执行 `git diff --cached --quiet`。退出 0 返回 unchanged，退出 1 继续，其他退出值失败并保留诊断。以 `github-actions[bot]` 和既有 bot 邮箱正常提交英文 `Update generated rules`；身份只通过本次命令的 `-c` 设置。commit/hook/signing 失败传播，不绕过。
6. 普通 `git push --porcelain origin HEAD:refs/heads/main`。成功返回 published，所有原始 stdout/stderr 保持可见。失败只按下述限定规则复核，没有重试或自动整合源码。

Git 子进程固定 `LC_ALL=C`、`LANG=C`，不修改全局或仓库配置。所有 Git 命令均在传入 root 执行。

## push 错误分类

只接受 porcelain 中恰好一个逐 ref 状态，目标精确为 `HEAD:refs/heads/main` 且 flag 为 `!`。无状态、多状态、其他 ref 或未知 summary 均失败。

| 实际状态 | 进一步证据 | 结果 |
| --- | --- | --- |
| `[rejected] (fetch first)` 或明确的 `non-fast-forward` 拒绝 | 再次成功读取 main，tip 不等于 A | superseded |
| `[remote rejected] (failed to update ref)` 或 `(incorrect old value provided)` | stderr 有 main 的精确 `cannot lock ref` old-value mismatch，expected 为 A、actual 不等于 A；再读 main 成功且不等于 A | superseded |
| 同样的竞争状态，但 main 仍为 A | 无 A 被替代的证据 | 保留 push 非零 |
| 认证、权限、服务端 policy/hook、transport、未知 remote rejected | 即使 main 同时前进也不转换 | 保留 push 非零及原诊断 |
| 竞争状态后的 main 读取失败或分支缺失 | 无法确认远端 | 失败，push 和读取诊断均可见 |

不笼统接受 remote rejected，不以 push 非零加 main 不同代替拒绝原因判断。无法识别的 Git 版本输出继续失败，不推断成功。

## 验收矩阵

- 同 SHA 严格串行：先发布 A 的新产物 B，再从 detached A 运行第二轮，改变时钟也不得再次生成或发布；远端保持 B。
- 开始时已过期：即使来源损坏也应在生成前跳过，工作区和 index 不变。
- HEAD 不符、main 缺失、首次/第二次读取失败：失败，无不明身份发布。
- 生成期间 writer 正常推进源码：提交前检查跳过，旧 checkout 保持 A，新源码不丢失。
- 最后预检查后、push 广告前推进：真实 non-fast-forward/fetch-first 状态，确认后 superseded。
- ref 广告后推进：真实 pre-push hook 推进 writer，真实 receive-pack old-value race，确认后 superseded。
- 正常发布：父提交 A，bot 身份/英文消息正确，七组六文件与 README 真实更新，普通 push。
- 无变化：固定时钟/bytes，返回 unchanged，无新提交。
- 精确暂存：使用自建七组名称；仅配置六文件与 README 入提交，无关源码、static、额外输出、tracked/untracked 保持原状；既有暂存内容失败且不动。
- commit hook 拒绝、服务端 policy 拒绝、transport/权限失败：失败；policy/transport 与 main 前进同时发生仍失败。
- old-value 状态不能仅凭 generic remote rejected 识别；竞争后的远端确认失败仍失败。
- cached diff 的非 0/1 错误失败，不把它当作有变更。
- workflow 结构仍保护同 SHA、needs、main、只读 PR、schedule、concurrency 和非 force 边界；业务行为由真实入口测试覆盖。
- 完整 Linux suite 在 Debian WSL 的 OS 临时 Linux 文件系统快照运行，不能以 Windows skips 代替 Ubuntu 路径验收。真实 GitHub 正常发布留给主会话最终 push 验收，不主动制造远程竞争。
