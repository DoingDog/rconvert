# CI 过期运行发布实施计划

## 基准与完成条件

基线 `4c1f29d55e47f939b96cf87a5284f947938191ed`。仅在任务独立 worktree 编码，主仓库和其他 worktree 不修改。规格为 `docs/superpowers/specs/2026-10-22-ci-publication-design.md`，其中 `update(root, tested_sha)` 与 CLI 是本次要求的公共测试边界。

完成条件：下列行为逐条经历 red -> 最小 green，相关回归通过，完整 Linux suite 获得真实终态；全部差异完成规格、安全及简化审查并正常英文提交。所有测试远端均为 OS 临时 bare Git，不 push 真实 GitHub。

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
- 精确暂存测试逐条增加无关 tracked/untracked/static/额外输出，以及既有暂存保护；每条先 red 再加必要保护。
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
