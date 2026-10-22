# wildcard 输入实施计划

规格：`docs/superpowers/specs/2026-10-22-wildcard-input-design.md`。工作树为 `.claude/worktrees/wf_dcf70dde-e2b-1`，branch 为 `worktree-wf_dcf70dde-e2b-1`，任务基准为 `4c1f29d55e47f939b96cf87a5284f947938191ed`，接手 HEAD 为 `df12eb1ad31f7b6cfca9bbe53107b41f172f0c7d`。保存的 parser 实现和 11 项新测试保留，在独立 OS 临时 Git 基准 snapshot 重做必要 red，不覆盖 worktree 中的内容。所有变更限于规格列明的 mutation boundary。

## 1. 核查、复现和文档提交

- 核实 HEAD、branch、status、index 和全部 diff，读取已有测试、全部 validator／converter 调用及生成发布消费者；保护已保存改动，不 reset、stash 或在 main 编辑。
- 基于真实基准构造 Linux `/tmp` Git snapshot，加入当前新测试，实际复现 universal wildcard、Surge quoted literal 和磁盘混合 source／white 丢失。
- 补全 spec 的修改归属、普通 DNS 证据前置条件、完整验收及协作边界，再写本计划；仅提交这两份文档，英语消息。
- 核查：基准失败来自普通 hostname 限制，原文件 bytes 未被替换；`git diff --check`，文档准确覆盖共享输入与六目标消费者。

## 2. 保存 parser 行为的 red／green 和定向提交

- 逐项核查已保存测试：scalar `*`／dotless／多点／长 pattern、Surge quoted literal、AND／OR／NOT／嵌套、三种 purpose × 三种 no_resolve、来源 IP 方向。
- 在基准 snapshot 执行每类 proof，在当前完整 snapshot 执行同一 proof；后续行为不新增生产分支，保持共享 `_valid_domain` 修复。
- 验证 exact／suffix／hosts／bare hostname 校验、普通 class／native literal bracket、非法控制／结构、case／root／byte guards、allow 与 external white；仅保留两个已授权旧拒绝断言修改。
- 真实 generate／publish 覆盖三文本及 YAML、同轮／disk source／white、单条／混合、全部六产物实际 bytes、Surge full／split／DSET 分区、输入不变及发布前旧产物保护；mock 仅时间，不 mock parser、render、generate、publish。
- 核查：11 项新测试和相关既有 parser／projection／coverage 模块全部通过，再以明确英语消息提交已验证的 parser 实现、两个旧断言和新测试。

## 3. 普通 wildcard DNS 的逐行为修复

- 首个行为先更新原 DNS 测试 1011–1017 hunk：`*ads*`／`*`／`a?`／`a??` 使用已知 body 和 ASCII 见证，`*<ads>*` 仍 skip；核查 skip 计数，保留同方法三种 bracket 来源差别。
- 接着单独添加未证明 ordinary literal 的公开入口测试，包括引号、括号、反斜杠、非 ASCII 和其他非旧 literal 字符。运行并记录 red 后，最小修改 ordinary wildcard DNS 分支，按原已证 ASCII literal／class 范围局部拒绝新形状；不改普通 keyword 或 native encoder，不把字符 `?` 替换为 byte token。
- 再添加长 pattern 的恰好 65,536 bytes、增加一个 byte 和大 pattern 测试，覆盖 block／allow／external white；先 red，再用有依据的早期预算与 `_dns_join` 限制扩展分配。只修改必要 `_wildcard_regex` 预算连接，不增加通用框架。
- 覆盖三 purpose × 三 no_resolve，目标局部 skip 不影响其他可表达格式；真实普通 source／white generate／publish 检查 DNS bytes、诊断、static 不变及旧文件保护。
- 核查：每个新增行为先出现预期失败，再当前 green；全部普通／native DNS、projection、coverage、readback 相关测试通过。README 仅补充已验证的 wildcard／DNS 支持范围，英语提交该完整单元。

## 4. H 集成及文档归位

- 核查 `fe34c69abe6695af86c796da003400d68ee7e12d` 的实际历史及 diff，确认与已提交 W hunk 不重叠后正常 merge 到 W branch，保留 H 全部 commits，不改变 H production 逻辑。
- 核实 H 的 root `plans/2026-10-22-chunked-ows.md` 确属该任务新建文件，保留内容并移至既有 `docs/superpowers/plans/`，精确更新实际引用；不删除用户原有目录。
- 核查：H 的 10 项新测试和 transport 回归通过，W 相关测试仍通过；无冲突、无未授权 production 改动，文档归位用英语提交。

## 5. 规格、简化复审和完整交付

- 逐条核对 spec、所有授权调用和实际 diff，检查新增逻辑是否复用现有 helper、是否存在冗余或未经请求的支持扩展；发现问题在本 worktree 修正、定向测试并复审。审查已复现 ordinary `..`、`*..` 和 `*123..` 在 `Rule` 单尾点规范化后不能稳定回读，须在 `_valid_domain` 保持原先的多尾点拒绝，补 scalar／logical／white 和发布前旧 bytes 保护的 red／green；不修改 normalize 或 native 语义。
- 用标准库 tarfile 与 git archive 构造当前完整 Linux `/tmp` 可信 snapshot，包含所有受控文件与新测试并逐文件核验 SHA-256；保存 manifest 身份和日志，在 snapshot 内一次前台等待完整 `python3 -B -m unittest discover -s tests -v` 的真实退出。保留既有 timeout 和 skip，不在 `/mnt/c` 跑重型 suite。
- 首次旧 `/mnt/c` suite 的 10 个断言失败和 12 个 timeout error 是已记录失败，不能计为通过；新 snapshot 的终态是本轮完整验证依据。不调查或修复本机系统。
- 核查：完整 suite 无失败或错误，`git diff --check`，修改列表仅含授权 W 路径和 H 历史，全部英文 commits；最终 HEAD 与已验证内容 hash 一致。
- 仅在逐个确认归属后清理本任务遗留 fixture 和无须保留的 snapshot；保留日志等交付证据，不能泛删或删除用户原有内容。返回原目录，保留干净 worktree 和 branch 供主会话集成，不 push、不 merge main。
- 最终返回 path／branch／base／head、commits、全部变更、逐行为 red／green、完整 suite 实际终态和日志、审查／简化结果、未检查／未清理项与风险，不在运行中请求主会话恢复。
