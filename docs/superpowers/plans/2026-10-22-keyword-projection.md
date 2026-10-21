---
title: native keyword 目标输出保留 - Plan
type: fix
date: 2026-10-22
artifact_contract: ce-unified-plan/v1
product_contract_source: keyword-projection-design
origin: docs/superpowers/specs/2026-10-22-keyword-projection-design.md
execution: code
---

# native keyword 目标输出保留 - Plan

## Goal Capsule

- Objective：用户从 native keyword 来源生成或重新导入规则时，Surge 和 block DNS 的有效长 keyword 正文及 DNS 例外完整保留。
- Means：在现有包含去重处限制末尾点 native 覆盖 keyword 的删除资格，见 KTD1。
- Authority：行为以 `docs/superpowers/specs/2026-10-22-keyword-projection-design.md` 的 R1-R8 为准；本计划规定实施与核验。
- Execution profile：独立 worktree、Python 标准库、Linux 测试、禁止客户端执行；完成规格提交后实施同一根因的一项修复。
- Stop conditions：新证据改变已确认的行为范围时更新规格和计划；未确认的其他问题不实施。
- Ownership：本任务完成测试、规格审查、简化、修正、复审和本地英文提交；主会话只合并已完成提交。

## Product Contract

### Summary

实现规格 R1-R8，恢复 native keyword 包含去重后的有效目标输出及生成依赖中的 DNS 例外。

### Problem Frame

`normalize` 当前只按来源包含关系删除较长 keyword。
末尾点 native 短 keyword 在 Surge/DNS 中不能表达，删除较长规则会使后续目标没有可输出的 matcher。

### Requirements

规格是 R1-R8 的唯一完整定义，本计划按下表分配验证范围。

| 需求 | 验证范围 |
|---|---|
| R1、R5 | native 两规则、任意子串位置、YAML 入口、purpose/no_resolve 矩阵 |
| R2、R3 | 安全去重对照、全部身份分组、重复/逆序/iterator |
| R4 | 六目标正文与诊断、邻居、完整 logical、字符边界 |
| R6 | public allow 与 DNS `@@` 顺序 |
| R7 | generate/publish、同轮与磁盘 source/white、外部白名单对照 |
| R8 | 有效投影继续发布、完全 unsupported 冻结、空依赖严格边界 |

### Scope Boundaries

仅修改 `rules.py` 的 keyword 包含去重、新建 `tests/test_keyword_projection_regressions.py` 及本任务两份文档。
保留 native 根点 guard、公共 Rule、白名单来源过滤、logical 叶子和生成依赖 bytes 校验。
不增加通用投影依赖、配置、性能重构或客户端执行；本任务没有真实生产长 keyword 的性能证据。

## Planning Contract

### Key Technical Decisions

- KTD1. 直接扩展现有 substring comprehension 的资格条件，使用 `domain_source` 区分 Mihomo；native scalar 的 `native_fields=False`，该字段不能判断来源。对应 R1-R3。
- KTD2. 测试通过既定公开 seams 比较可表达正文和字面预期，复用 `tests/test_formats.py` 的 `DNS_BYTE_TOKEN` 常量表达已知 DNS 文本；不导入私有生产转换 helper 求 expected。对应 R4-R7。
- KTD3. 集成 fixture 使用标准库 `TemporaryDirectory`、本地文件、真实 `generate` 和 `publish`；fetch 回调遇到网络请求即失败，仅证明本任务 fixture 不联网。对应 R7-R8。

### Assumptions

本任务的客户端语义依据为已提供独立复核和已读取的固定 Mihomo 源码；不推断未获证明的 QX 特殊字段语法。
完整 Linux 本地测试可验证跨平台 Python 行为，不能代表已经执行远程 GitHub Actions。

## Implementation Units

### U1. 保留可表达的 native 长 keyword

**Goal：**完成规格 R1-R8 的单一根因修复。

**Dependencies：**规格与本计划先经审查并独立提交。

**Files：**`rules.py`、`tests/test_keyword_projection_regressions.py`。

**Approach：**

1. 在公开 parse -> normalize -> render seam 增加最小两 keyword 失败例，先核实未修改实现确实丢失 Surge/DNS 长规则正文，保留 red 终态。
2. 只在现有 keyword 包含判断中加入 KTD1 所述资格条件，使该最小例通过；不改目标转换。
3. 逐个补充下列同根因验收行为，每个行为先以基准实现验证失败，当前实现通过后再进入下一行为；正确对照先记录基线通过。
4. 完成相关和完整测试后，按规格复审范围与边界，删除本次冗余内容，修正发现的问题并重跑受影响检查。
5. 确认只有授权路径改变后，独立英文提交本项修复。

**Execution note：**测试按行为纵向完成 red -> green；基准失败核验只在测试进程载入基准源码，不回退工作文件，不使用 mock 客户端。

**Test Scenarios：**

- native `123.` / `123.45` 的精确六文件正文、标题数量和精确 unsupported 字典，Surge 拆分保持一致。
- `.`、`23.`、`123.`、`45.`、`12.34.` 等短值在前缀、中间及多个位置包含；两种输入顺序、重复输入、一次性 iterable。
- payload/rules 与三种 scalar 引用，覆盖 block/direct/proxy 和 add/strip/keep。
- public native allow 长 keyword 的 DNS 例外不消失，保留 `45` blocker，例外排在拦截前。
- Surge/QX 同源正常去重、native 安全 `123`、两个末尾点值及额外安全 keyword 仍可归约。
- 每个身份属性单独不同的两规则不跨组删除，中文及 Greek 原有回归通过。
- 含字面引号、反斜杠、内部空白的长 keyword 保留现有编码；逗号和控制字符仍按各目标原有规则处理。
- 相邻非 keyword 规则及 AND/OR/NOT/嵌套表达式完整保留，目标不支持 leaf 时按父 operator 计一次。
- 实际生成 parent/fin.yaml 供同轮 child.sources 使用，并 publish 后作非空 disk-only 来源，长 keyword 的 Surge/DNS 正文保持。
- whiteparent/fin.yaml 用作生成白名单，和外部原始 white.yaml 对照；DNS 有效 `@@` 保留，同轮与非空 disk-only 结果一致。
- 有效 Mihomo/QX 投影继续发布，完全 unsupported 组保留旧六文件及依赖，合法同轮空 fin.txt 继续生成，disk-only 空文件仍拒绝。

**Verification：**新测试失败证据指向目标丢失，修复后所有字面正文和边界断言通过；相关和完整 Linux suite 通过，审查未留下待主会话补做的步骤。

## Verification Contract

| 步骤 | 核查 |
|---|---|
| 基线与范围 | HEAD 为指定基准、工作目录清洁、唯一 normalize 生产调用方及相关现有测试已阅读 |
| 最小 red | Linux 执行新增单测，确认失败于有效长 keyword 正文缺失 |
| 最小 green | 最小资格条件后相同测试通过 |
| 各验收行为 | 按行为追加；在基准模块验证失败或正确对照通过，再在当前模块验证通过 |
| 相关回归 | 新测试、test_rules、test_formats、test_generate、functional audit projection/DNS 和 coverage 等相关模块通过 |
| 完整测试 | Linux Python 执行 `-m unittest discover -s tests -v`，保留真实命令、退出码、终态；Linux 临时 fixture 不使用 Windows skip 替代验收 |
| 审查与简化 | 逐项核 R1-R8、生产 diff、测试 seam/expected、全部分组、循环依赖及输入不变 |
| 提交检查 | `git diff --check` 通过，仅授权路径暂存和提交，不 push、不 merge |

## Definition of Done

规格先独立提交，U1 的最小失败证据和全部 Linux 终态可在任务返回中核查。
当前实现满足 R1-R8，测试不复制内部算法，不要求冗余 Mihomo/QX 行数完全不变。
本次临时材料已清理或如实列明未清理项，未修改生产输入及无关文件。
最终返回 worktree、branch、base/head、全部 commit、修改路径、测试证据、审查结果和未检查风险。
