# wildcard 输入实施计划

规格：`docs/superpowers/specs/2026-10-22-wildcard-input-design.md`。工作树为 `.claude/worktrees/wf_dcf70dde-e2b-1`，基准 `4c1f29d55e47f939b96cf87a5284f947938191ed`。每个行为依次添加测试、核实基准失败、执行共享修复后的成功验证；不一次写完全部测试。首次共享修复覆盖的后续行为无需再增加生产分支，其 red 以同一测试对未修改基准模块的执行记录证明。

## 1. 核查与规格提交

- 核实 cwd、Git worktree、branch、HEAD 和初始 clean 状态，阅读实际函数、全部调用、关联既有测试、README、四份历史 spec 及对应三视角 checks。
- 记录公共 seams、fixtures／配置／输出影响和 owner 边界，写入完整设计和本计划。
- 核查：只有当前 worktree 被修改；spec／plan 无遗漏的支持边界，`git diff --check`；先正常英语提交这两份文档。

## 2. scalar pattern 的第一条 red／green

- 新增实际 native parse -> normalize -> render -> 三文本 bytes／YAML -> parse／parse_whitelist 回读测试，先以 universal `*` 复现。
- 核查 red：三个文本各出现 `invalid domain *`，YAML 控制路径成功。
- 最小 green：仅在 `_valid_domain` 中统一 wildcard 的安全 scalar 检查，并为非 native 保留既有 class 语法；DOMAIN／SUFFIX 路径保持。扩展同一行为的数据到 dotless、多点、长 pattern 和 quoted literal，逐项在基准证实失败并在当前树通过。
- 核查：规则原文、来源和无 warning；Surge full/split 相同、DSET 无 wildcard；只精确更新两处已授权的旧普通 wildcard 拒绝预期。

## 3. logical、来源和目标边界

- 添加 AND／OR／NOT／嵌套 source 的真实生成输出回读，检查三 purpose × 三 no_resolve；覆盖有／无初始目的 IP 标志与来源 IP。
- 添加普通类有效／非法、native literal bracket、非空和不安全 scalar、hostname 校验不变、byte／字符及 case／root 反例。核查 source／external white／allow 保留和目标局部计数；不增加 logical white。
- 核查：新行为在基准 red、当前 green；所有 parser／wildcard regex／Mihomo／DNS／white 消费者在各自已证明范围仍符合规格。特殊 QX 字段和新 literal 的 DNS 安全编码交给既定 routing 集成，不改 formats。

## 4. 实际生成依赖与发布

- 添加三文本和 YAML 的 source／white、同轮／disk、单条／混合邻居矩阵，覆盖三 purpose × 三 no_resolve。
- fixture 使用系统临时目录；真实 generate／publish；fetch 不允许网络。仅固定时间以比较全部六产物。
- 核查 red：基准同轮依赖失败或 disk 混合遗漏；green：无 invalid-domain warning，wildcard 不丢失，子组全部六文件与相同 disk bytes 结果及诊断相同。旧产物在 publish 前保持、随后实际 bytes 与输出相同，static 不变。
- 添加非法 white／generated logical white 的发布前保护，以及只靠有效 wildcard 清空的合法空结果；冻结和事务回滚复用完整 suite 的既有验收。

## 5. 规格、简化复审与交付

- 逐条核对 spec 验收、原完整 checks、实际 diff 和全部调用；删除本次新增的重复或无用实现，不改无关区域。
- 核查：相关模块通过；完整 Debian Linux `unittest discover -s tests -v` 通过，无旧 timeout 修改；`git diff --check`，修改列表只含授权文件，static／配置／其他测试无改动。
- 修正发现并重跑受影响检查，复审后正常英语提交实现与测试。记录 commit／HEAD、red／green／Linux suite 的实际结果，列明格式协作未核范围、未运行客户端／远端 Actions，以及任何未清理材料。不 push、不 merge、不清理其他 worktree。
