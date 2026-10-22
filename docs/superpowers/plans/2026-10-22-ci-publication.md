# CI 过期运行发布实施计划

## 基准与完成条件

基线 `4c1f29d55e47f939b96cf87a5284f947938191ed`。仅在任务独立 worktree 编码，主仓库和其他 worktree 不修改。规格为 `docs/superpowers/specs/2026-10-22-ci-publication-design.md`，其中 `update(root, tested_sha)` 与 CLI 是本次要求的公共测试边界。

完成条件：下列行为逐条经历 red -> 最小 green，相关回归通过，完整 Linux suite 获得真实终态；全部差异完成规格、文件保留及简化审查并正常英文提交。所有测试远端均为 OS 临时 bare Git，不 push 真实 GitHub。

## 影响范围

| 文件/接口 | 修改或核查 |
| --- | --- |
| `.github/workflows/main.yml` | 更新 job 调用 `update.py`，两个 checkout 明确事件 SHA；保留 needs/main/非 PR/schedule/concurrency/权限 |
| `update.py` | 最小标准库入口；HEAD/远端/暂存/生成/README/提交/push 的顺序与错误分类 |
| `generate.generate/publish/fetch_https` | 复用现有公开接口，不修改；测试实际生成及磁盘发布 |
| `sources.load_config`、`formats.FILES` | 复用配置验证及精确路径，不硬编码组名 |
| `update_readme_counts.update` | 复用真实 README 更新，不修改 |
| `tests/test_ci_publication.py` | 七组临时 fixture、真实 bare/runner/writer、真实 Git hooks 和失败注入 |
| `tests/test_workflow.py` | 结构断言指向真实入口，保留同 SHA/needs/main/PR/非 force 约束 |
| `README.md` | 只修改 Actions 行为段落；计数区和路由字段说明不改 |
| 本规格及计划 | 交付文档，先于实现提交 |

## 执行步骤与核查

### 1. 核查与文档提交

- 读取 workflow/test_workflow 全文、生成/发布/count/config 调用、FILES/时钟、同 SHA 既有规格/计划和三份完整复核证据。
- 确认 cwd、worktree、HEAD、clean index/工作区，记录基线测试状态。
- 先写规格，再写本详细计划；核全部要求、错误分类和测试边界，`git diff --check` 后单独英文提交。
- 核查：不增加框架、选项或依赖，八个范围均有负责文件且无其他 owner 位置冲突。

### 2. 已过期运行的生成前判定

- 首个失败测试直接调用尚未存在的公共入口；使用真实生成的七组 A 和第二轮 detached runner。
- 最小实现 HEAD 核对、远端 main 严格读取及已过期跳过。单独添加 HEAD 不符、缺失/不可读 main 的负例，每次先运行该例观察 red，再实现所需边界。
- 核查：未调用网络、未写新产物、未改变 index/HEAD；同 SHA 第一轮完成后第二轮严格串行。
- 相关回归、规格/简化审查后英文提交。

### 3. 正常生成、提交与无变化

- 正常发布的失败测试验证真实 README、七组六文件、父提交 A、bot 身份、英文消息及远端 bytes；只实现该路径所需的公开函数复用与普通 push。
- 无变化测试固定时钟，先 red 后添加 cached diff 0 分支；保持 diff 1 和其他错误的明确区分。
- 精确暂存测试逐条增加无关 tracked/untracked/static/额外输出，以及既有暂存保护；每条先 red 再加必要保护。规格复审补查允许路径自身的既有 tracked 修改：README 非计数段落和手工产物都须在生成前失败并保留，不把它们带入 bot 提交。补查按同样的 red -> green 和完整 Linux suite 验证。
- 核查：配置使用七个自建组名，当前允许集合恰为 43 个路径；不通过复制生成算法构造期望，读取真实生成结果核已知字面内容与提交路径。
- 相关回归、规格/简化审查后英文提交。

### 4. 生成期间 main 前进

- 通过 HTTPS fetch 系统边界让真实 writer 推进源码，生成/发布仍执行实际实现；失败测试验证提交前跳过旧产物。
- 最小增加第二次远端读取；再独立添加第二次读取失败的先 red/green 负例。
- 核查：远端保留 writer 新源码，runner HEAD 保持 A，无生成提交，无关改动不丢失。
- 相关回归、规格/简化审查后英文提交。

### 5. 最后检查之后的 push 竞争

- pre-commit hook 推进真实 writer，产生广告前 fetch-first/non-fast-forward 失败。先 red，再实现单目标 porcelain 分类及成功远端确认。
- pre-push hook 在真实广告后推进 writer，产生 old-value mismatch。先 red，再只增加精确 main/expected A/actual 不同的诊断确认。
- 核查：两条窗口实际产生不同真实 Git 状态，远端均不包含旧运行产物，不 rebase、不 force、不重试。
- 相关回归、规格/简化审查后英文提交。

### 6. 错误边界

逐个增加测试并运行；已有实现通过的保护例记录为回归，缺少保护的用例必须 red 后修复，再进入下一例。

- 真实 commit hook 失败和 bare pre-receive policy 拒绝。
- 失效的本地 push 地址导致 transport/权限型失败。
- policy 拒绝与 main 前进同时发生，不能判 superseded。
- transport 失败与 main 前进同时发生，不能判 superseded。
- generic remote rejected/不同 ref 的拒绝不可作为 old-value 证据。
- 明确竞争后的 ls-remote 失败或 main 缺失，必须失败。
- 利用真实 index/hook 故障验证 cached diff 错误码；不模拟 Git 成功。

核查：保留原始 stdout/stderr 和非零退出；错误分类没有仅凭远端变化吞错的分支。相关回归、规格/简化审查后英文提交。

### 7. workflow、README 及完整验收

- 先让 workflow 结构测试要求真实入口及两个显式事件 checkout，确认 red，再精确修改 YAML。
- 保留 PR 只读、needs/main、schedule/concurrency、非 force 和 static 可维护边界；业务不靠 YAML 子串测试证明。
- 只更新 README Actions 段落，说明 superseded 不代表新 SHA 已测试或发布。
- 在 Linux 文件系统 OS 临时目录创建可信本工作树快照，运行 `python3 -B -m unittest discover -s tests -v`；记录解释器、Git、真实命令、测试数、skips、失败或成功终态。不提高 timeout，不弱化测试。
- 核查全部实际 diff、逐项规格覆盖及简化：删除本次冗余实现/无用 import，不修改其他任务拥有的文件。修正后重跑受影响检查及必要完整 suite，英文提交。
- 清理本次临时目录；未清理项如实记录。返回绝对 worktree 路径、branch/base/head、各 commit、文件、red/green/完整 suite、分类证据、审查结果及未检查风险。worktree 保留供主会话合并，不提前删除未合入提交。

### 8. 允许路径中的既有 untracked 文件

- 复审修正基准为 `c029dd464fbd2310931ba19408fa079f56757940`；保留已有十二个提交。本轮只改 `update.py`、`tests/test_ci_publication.py` 及本规格/计划。README 的 Actions 段已有精确暂存说明，无需更改；不修改 Windows 换行或 Git 文案测试，不修改 push 错误分类。
- 先更新规格中的文件保留要求，再提交本计划。完成条件限定正常业务功能、文件保留、规格及测试，不开展网络安全扫描、修复、客户端或多平台适配。
- 从公开 `update(root, tested_sha)` 入口逐项测试。首例使用真实提交使旧配置的产物从 index 移除，确认 HEAD 等于远端及测试 SHA、index 和 tracked diff 为空，留下手工 bytes；先观察 red，再用现有允许路径集合和成熟 Git 命令增加生成前检查，单例 green 后才增加下一例。
- 独立验证新增并提交的配置组已有手工产物时拒绝，以及被 Git 忽略的允许目标仍被识别；已有实现能通过的例子记录为回归。不得用 `--exclude-standard` 漏掉 ignored 目标，不复制整个测试矩阵，不 mock Git 成功、生成器或文件发布。
- 每次拒绝均核查发生在 HTTPS fetch 和文件替换前，手工 bytes、index、tracked diff、HEAD 和远端不变。另验证不存在的允许输出可首次生成和发布；复用既有集合外 tracked/untracked/static 保留回归，确认它们不阻塞、不改写、不进入提交。
- 完成相关真实 Git 回归、规格与简化复审，再在 Debian WSL 的 Linux `/tmp` 可信完整快照运行 `python3 -B -m unittest discover -s tests -v`，不改既有 timeout/skip，记录真实终态。核查受控差异仅有本轮四个文件后英文提交，不 amend、push 或合并 main。
- 清理本次临时文件，返回原目录，保留 worktree 及本轮提交供主会话合并；列明 red/green、完整 Linux 结果、修改文件和未检查/未清理项。

### 9. Ubuntu generic ref 拒绝断言

- 本轮基准为 `118f0ded6da2e1f8b5e1a1b46ade44abbdb53838`。GitHub run `39763336400` attempt 1、test job `119772643196` 在 Ubuntu 24.04.5、Git 2.55.0 运行 1363 tests，1520.936 秒后仅 `test_generic_ref_failure_with_main_advance_is_not_an_old_value_race` 失败，errors 0、skipped 10。已保存的完整日志第 1678–1688 行记录旧断言要求 `(failed to update ref)`，真实 porcelain 为 `!\tHEAD:refs/heads/main\t[remote rejected] (reference already exists)`；公开入口已抛出 `CalledProcessError`，退出码 1 断言已通过。以此为实际 red，不伪造额外失败。
- 规格的 push 错误分类及验收矩阵已要求 generic remote rejected 即使 main 前进也保留失败，无需修改规格或生产行为。仅将该例的 stdout 断言改为稳定的 `!\tHEAD:refs/heads/main\t[remote rejected]`，保留 `File exists` stderr、远端 tip 等于 writer 提交及不含 superseded 的原断言，不增加 Git 模拟、诊断文案枚举、parser 或抽象。
- 核查同一真实 Git 用例和全部 CI publication 相关回归。记录本地 Linux Git 的实际版本及结果；本地 green 不代表 Ubuntu Git 2.55.0 已通过，该版本由主会话正常合并、push 后的 Actions 验证。
- 必要改动英文提交后，将最终 exact commit 用 `git archive` 导出到 Linux `/tmp`，以 `python3 -I -B` 显式加入可信快照 root，运行全部实际收集的 tests。保存唯一测试身份、counts、failures/errors/skips、耗时、exit、完整日志和逐路径 mode/blob/SHA256 前后清单，不改 8 秒 timeout、2 MiB 阈值或原有 10 个 Windows-only skip。
- 核查相对本轮基准仅本计划与该测试文件变化，五个生产模块、其他源码、static、配置、42 个产物和 README counts 全部不变；完成规格、范围及简化复审、`git diff --check` 和 clean 检查。复用证据只存本 worktree 已忽略的 `.tmp/ubuntu-git-rejection-verification`，清理本轮 OS 临时快照，保留 worktree 与提交供主会话合并，不 push 或修改 main。
