---
title: 功能审查修正与发布 - Plan
type: fix
date: 2026-10-24
artifact_contract: ce-unified-plan/v1
product_contract_source: functional-audit-design
execution: code
origin: docs/superpowers/specs/2026-10-24-functional-audit-design.md
baseline: 00d20710af4ad62805ad63c609c4796711058de8
---

# 功能审查修正与发布 - Plan

## Goal Capsule

- **目标：**合法规则经公开转换及真实文件回读后保留可表达 matcher，非法 regexp2 与 native `@@` 不进入生成链，GitHub Actions Ubuntu 更新的七组产物满足现有格式和发布要求。
- **依据：**`docs/superpowers/specs/2026-10-24-functional-audit-design.md` R1-R13 规定行为和完成条件；本计划分配实现所有权及验证顺序，不重定义 matcher 语义。
- **方法：**A dedup、B regex、C SUBNET／native、D quoted process 四个独立 worktree 并行，组内行为连续完成 vertical TDD、审查、修正、英文提交及最终 head 完整 Linux suite（KTD1-KTD3）。
- **开始条件：**R1-R8 及 R13 已确认，R8 包含合法 DNS 输出完整性；独立单元按已提交确定范围实施。六领域终报已收齐，主会话在最终集成前核对覆盖收据，后续确认问题精确交对应 owner，不阻塞无修改冲突的单元。
- **停止条件：**实际证据与规格冲突、需要写入其他 owner 位置或无法保持目标能力时，报告具体缺口并停止对应操作。原始用户请求已明确要求 main 合并、GitHub push 及远程更新核验，发布按该授权范围执行。
- **交付责任：**各 owner 完成其全部实现与验证，主会话只合并已完成且无所有权冲突的提交，并负责最终精确树、固定输入、main、获授权发布和清理。

---

## Product Contract

### Summary

实施规格 R1-R8 和 R13 的九项已确认修正，包含 QX 非 ASCII 比较、normalize 的合法 keyword 输出能力及普通 quoted process 尾注释，完成公开接口回归、精确树 Linux 测试和固定 bytes 生成发布验收。

### Problem Frame

基线的共享归约与校验会删除普通 wildcard 仍需的 Mihomo 投影，误判部分 regexp2 conditional／class、legacy SUBNET 和 native NOT，将 native quoted ABP 例外误读为 allow，因 QX 非 ASCII 比较误删不同 matcher，并丢失合法长 keyword 的 DNS 输出。普通 quoted process 的尾注释还会进入 matcher。这些结果经白名单和生成依赖传递，可能丢失可表达规则或发布错误 matcher。新增测试须证明具体行为，DNS 长值结论限定输出完整性。

### Requirements

| 规格要求 | 执行单元 | 可核查结果 |
| --- | --- | --- |
| R1 wildcard／suffix | U2 | 全小写根点见证所需 regex 保留，suffix 原生输出及安全归约保持 |
| R2 expression options | U3 | 按 `ntTestgroup`／`ntTestref` 与真实嵌套层级校验，完整 capture 集合保持 |
| R3 condition header | U3 | noncapture／atomic 合法，原 matcher 与外层分支计数正确 |
| R4 completed range | U4 | 合法单 hyphen 保留、非法双 hyphen 拒绝，escape endpoint 与 probe 一致 |
| R5 legacy SUBNET | U5 | bare BSSID 可回读，prefixed 与未知 colon 边界保持 |
| R6 native NOT | U6 | ASCII space 包装按结构接受，native 单 child 及 ordinary 行为保持 |
| R7 native `@@` | U7 | 解码后拒绝，无 allow／DNS 例外泄漏，其他 mixed-format 兼容保持 |
| R8 Unicode comparison／keyword 输出能力 | U8 | QX 跨值限制、keyword 原文代表及双重 contains 证明同时生效，合法 DNS 行和安全归约保持 |
| R9 公开入口与 bytes | U2-U8、U13 | 六格式、source＋white 同轮及非空 disk-only、三 purpose × 三 no_resolve |
| R10 精确树 suite | U2-U10、U13 | 各 owner 最终 head 和最终集成树独立完整 Linux 验证 |
| R11 固定生产输入 | U10 | 同输入 baseline 对比、两轮 42 文件稳定、static／README／格式核查 |
| R12 集成与远程 | U9、U11、U12 | clean 提交正常合并、真实授权、Ubuntu 与远端实际结果、限定清理 |
| R13 quoted process 尾注释 | U13 | 四 process 字段在已闭 quote 外识别尾注释，裸 marker／policy／logical／native 保持 |

Product Contract 由独立规格承载。这里的引用保留全部行为边界，不把审查复现或内存实验写成产品修复验收。

### Scope Boundaries

生产变更限定在规格的 A／B／C／D 位置。`Rule`、API、配置、依赖、导出和六文件集合保持。只新增各 owner 的独立小型测试，不复制已有大型矩阵；A 精确调整两处旧 wildcard 断言和指定性能测试的 QX pair 期望，其他 owner 不写旧测试。当前文档任务仅更新 origin 和本计划，不修改其他受控路径，不执行客户端、安全工作、源码修正或远程操作。

本轮不处理 suffix 大小写、批量 suffix regex 改写、本机／多平台适配、未确认性能问题或独立 publish 非 canonical leaf API。不新增 Unicode 表，不改 Rule 原值，不承诺闭源 QX 全域 Unicode 等价。

---

## Planning Contract

### Key Technical Decisions

- KTD1. **四组按共享状态分配所有权。**A 拥有 dedup／comparison，B 拥有相关 regex scanner，C 拥有 SUBNET／native 三处，D 只修改普通 process comment 分支。R2/R3 及 R4 共享 `_valid_regex` 的初始化、probe 和收尾状态，由 B 顺序实现。四组生产 hunk 和新测试互不重叠，独立实施不等待其他单元的审查终报。
- KTD2. **同一 owner 按行为完成 vertical TDD。**每个 slice 从一个公开失败用例开始，只修共享根因使该例 green，再逐例加入相邻边界及真实 bytes 联动；完成规格／功能／简化审查、修正、复审和英文提交后才进入下一 slice。R2/R3 是同一 conditional 状态 slice，R4 另行提交。
- KTD3. **各 owner 完成最终提交 head 的全套后交付。**A、B、C、D 在各自最终 head 满足规格 R10，返回 clean commit／tree、red／green、相关回归、审查和完整 suite 证据。失败由原 owner 连续处理，主会话不接收待测试或待修正半成品。
- KTD4. **共享修正保留既有目标能力。**R2-R4 只修来源 validator 和验证 probe，保持 DNS 独立证书及 URL-REGEX；R5 不新增目标支持；R6 仅 native 分支；R7 只拒解码后的 native `@@`；R8 连续完成 QX 原文 key、两个 caller 跨值限制、keyword equality／索引／contains 输出能力保护；R13 只修普通 quoted process 尾注释，不改全局 lexer。复用现有 caller 和字段读取，不增加 parser、wrapper 或依赖。
- KTD5. **输入身份与执行身份分开记录。**只读固定 manifest／body，baseline 与最终代码运行在各自可信 archive；下载数据和执行脚本分开，不从下载目录运行解释器。旧抓取 commit／hash 不改写为最终代码 SHA。
- KTD6. **受控树确定后才做最终验收。**正常合并全部已完成分支和必要文档修正，形成唯一 commit／tree，再执行 R10、R11。测试后发生任何受控修改，重新提交并验证新树；组件和 baseline 日志不能替代最终结果。
- KTD7. **本地固定输入与远端实时更新分别验收。**固定输入验证代码差异和两轮稳定性，Ubuntu 按实际事件 SHA 与当次来源更新；分别保存结果，不把不同输入的数量差异归因于代码。

### Ownership and Impact

| owner | 可修改生产位置 | 测试文件 | 调用方与保持项 |
| --- | --- | --- | --- |
| A | `rules.normalize` 的 wildcard／keyword identity、索引及 contains，`_domain_comparison_value`、`exclude_covered` 的 QX 跨值覆盖 | 新增 `tests/test_wildcard_suffix_normalization_regressions.py`、`tests/test_qx_unicode_comparison_regressions.py`；精确调整 `tests/test_rules.py` 两个 wildcard 断言及 `tests/test_keyword_normalization_performance.py` 指定方法中 QX pair 期望 | source／allow／white 顺序、目标覆盖、合法 DNS 行、keyword 长度索引、identity、ASCII 及 Surge 安全归约 |
| B | `_valid_regex` conditional、class 与 probe；确需时同一 owner 修改 `_regexp2_capture_slots`／`_valid_deep_regex` | 新增 `tests/test_regexp2_conditional_regressions.py`、`tests/test_regexp2_completed_range_regressions.py` | scalar parse、logical normalize／no_resolve、DOMAIN-REGEX white、`formats._dns_regex`、deep；不改 DNS 投影算法 |
| C | `_valid_simple` SUBNET、`_logical_children` native 分支、`parse` native `@@` | 新增 `tests/test_subnet_legacy_regressions.py`、`tests/test_native_not_space_regressions.py`、`tests/test_native_allow_regressions.py` | scalar／logical／kind traversal、native 字段与标量解码、allow／white、mixed shortcut、生成冻结与旧产物 |
| D | `_source_parts` 的普通 process 分支，复用 `_literal_fields` | 新增 `tests/test_process_comment_regressions.py` | `_source_records`／`_without_comment`、parse、生成依赖、process 不新增 white 支持、裸 marker／policy／logical／native 保持 |
| 集成 owner | 已完成分支的合并、必要规格／计划修正 | 复用上述模块，缺口交回原 owner | 最终 exact tree、固定 bytes、README 副本、main、Ubuntu 和远端产物 |

A 不修改 regex 或 parser，B 不修改归约或其他 parser，C 不修改 regex／dedup／process comment，D 不修改其他分支或全局 lexer。测试 fixture 在临时 root 自建；不改 `rulesets.json`、static 或生产输出。实现需要跨所有权位置时，提供具体 failing caller，由主会话调整分工后继续。

### High-Level Technical Design

共享调用链决定每个修正的传播范围。

```mermaid
flowchart TB
    O[ordinary 与 native 原始 bytes] --> P[parse 与共享校验]
    W[white 原始 bytes] --> PW[parse_whitelist]
    P --> E[exclude_covered 来源过滤]
    PW --> E
    E --> N[normalize]
    N --> R[render 六格式与目标覆盖]
    PW --> R
    R --> G[generate 输出映射]
    G --> U[publish 写入]
    G --> S[同轮 source 与 white 依赖]
    U --> D[非空 disk-only source 与 white]
    S --> P
    S --> PW
    D --> P
    D --> PW
```

A、B、C 从 `109ea30f83720178130a1db0c608937eaae86ef8` 独立实施并吸收各自后续确认文档，A 连续 U2／U8，B 连续 U3／U4，C 连续 U5-U7。D 从包含 R13 的文档提交独立完成 U13。覆盖收据在 U9 前核对。

```mermaid
flowchart TB
    Q[U1 已提交确定文档] --> A1[U2 A wildcard]
    A1 --> A2[U8 A comparison 与输出能力]
    Q --> B1[U3 B conditional]
    B1 --> B2[U4 B completed range]
    Q --> C1[U5 C SUBNET]
    C1 --> C2[U6 C native NOT]
    C2 --> C3[U7 C native allow]
    A2 --> I[U9 已完成提交集成]
    B2 --> I
    C3 --> I
    Q --> D1[U13 D process comment]
    D1 --> I
    COV[覆盖收据与确认范围核对] --> I
    I --> F[U10 最终 Linux 与固定 bytes]
    F --> M[U11 main 与真实授权 push]
    M --> V[Ubuntu test 与 update 及远端核验]
    V --> X[U12 证据保存与本次清理]
```

### Evidence and Execution Preconditions

R1-R8、R13 及 DNS 输出完整性补充的独立终报已收齐，既有文档独立审查已通过，本次确定补充按证据自审。六领域补查已完成，主会话在最终集成前核对全部源码、20 static、42 产物、35 回读和 52 CI 测试等覆盖收据及候选处置；不阻塞已确认独立单元。额外问题须经独立确认后精确更新并交对应 owner 完整处理。

可信 Linux archive 运行方法、固定响应和旧验收脚本可复用，但实际目录、commit、tree、body hash 和终态须在执行时核查。旧脚本中的固定文件数、测试数和 SHA 属于其原运行身份，只允许在新副本适配本次身份，不放宽产品断言。

---

## Implementation Units

| 单元 | 交付结果 | 主要文件 | 依赖 |
| --- | --- | --- | --- |
| U1 | 确定范围与文档提交 | 两份功能审查文档 | 已收齐的确认终报 |
| U2 | wildcard 投影保留 | `rules.py`、wildcard 新测试、`tests/test_rules.py` 精确断言 | U1 |
| U3 | conditional 层级与 header | `rules.py`、conditional 新测试 | U1 |
| U4 | completed range 状态 | `rules.py`、completed-range 新测试 | U3 |
| U5 | legacy SUBNET | `rules.py`、SUBNET 新测试 | U1 |
| U6 | native NOT 包装 | `rules.py`、NOT 新测试 | U5 |
| U7 | native `@@` 拒绝 | `rules.py`、native-allow 新测试 | U6 |
| U8 | Unicode comparison 与 keyword 输出能力 | `rules.py`、QX comparison 新测试、指定 QX 旧期望 | U2 |
| U9 | 已完成提交集成 | 四组提交与必要文档 | A、B、C、D 最终交付及覆盖收据核对 |
| U10 | 最终 Linux 和固定输入验收 | archive、隔离证据与产物 root | U9 |
| U11 | main、Ubuntu 与远端验收 | 既有 update／workflow | U10、真实授权 |
| U12 | 证据和限定清理 | 本次 worktree／branch | U11 或明确本地交付状态 |
| U13 | quoted process 尾注释 | `rules.py`、process-comment 新测试 | 包含 R13 的 U1 文档提交 |

### U1. 固定最终范围和共同文档 base

**要求：**R1-R13。当前文档任务只完成本单元，不执行功能实现。

1. 核对获准 worktree 的 HEAD／branch／status 与当前文档提交，保留原内容、不 reset；仅编辑指定两份文档。初始 base 为 `109ea30f83720178130a1db0c608937eaae86ef8`，后续采用正常文档追加提交。
2. 依据已完成独立报告、当前代码及固定源码规定 R1-R8、R13。R8 覆盖 QX 跨值关系及 normalize 的 equality／索引／contains 输出能力，R13 规定最窄 process 分支；同步 owner、测试、依赖与实际并行安排。
3. 核对要求、caller、fixture、目标能力、测试及交付边界，保留已有独立文档审查结果，对确认补充自审并运行 `git diff --check`。只提交两份文档，使用英文 commit 消息。
4. 主会话记录实际 clean 文档 commit／tree，各 owner 仅吸收相关确定范围，在独立 worktree 连续完成。已确认独立任务并行，最终集成前核对覆盖收据，完成后主动回报、不轮询。

**完成标准：**确定要求与终报一致，文档提交可供对应 owner 使用；未确认候选不写为实施要求。当前文档任务不创建实现任务、不改其他路径。

### U2. A：普通 wildcard 的必要投影

**要求：**R1、R9、R10。**依赖：**U1。**文件：**`rules.py` 的 `normalize`，新增 `tests/test_wildcard_suffix_normalization_regressions.py`，`tests/test_rules.py` 中 `test_normalize_keeps_wildcard_predicates_and_source_groups` 与 `test_wildcards_are_only_dropped_when_suffix_proves_coverage` 的相关期望。

**方法：**以最小公开输入中 `normalize` 丢失已有 Mihomo regex 的失败开始，按实际 source／目标能力限制归约。复用现有 wildcard 转换和能力事实，不改 suffix 投影，不一律关闭 wildcard 归约。旧测试按 source 及实际可投影 pattern 精确分开；外部 white 期望保持其原语义。

**测试情景：**

- 同组 `DOMAIN-SUFFIX,example.com` 与 `DOMAIN-WILDCARD,*.example.com` 保留必要 regex；用 `ads.example.com.` 与无根点对照核查，另核查 apex／其他域名。
- `api-*.example.com`、问号和已支持 class pattern 保留实际投影；无法生成 Mihomo 投影的 pattern 保持安全归约。native／QX 同组对照维持其原结果。
- allow／options／literal_process／native_fields／domain_source 不同组不互删，重复／逆序／一次性 iterable 结果稳定。
- source 层 suffix white、公开 allow、raw 和 generated white 分别检查，target filtering 根据最终 matcher 判断；不把正常白名单删除当作本项修正。
- 三 purpose × 三 no_resolve，六格式完整正文／diagnostics，真实 generate／publish 的同轮 source＋white 和非空 disk-only，static／旧产物保持。

**核查：**逐例 red -> green 后运行 domain coverage、native domains、ordinary wildcard、QX wildcard、wildcard dependency、keyword projection／performance 与相关 generate 回归。规格／功能／简化审查、修正复审后单独英文提交。A 连续完成 U8，最后按 KTD3 交付最终 head。

### U3. B：conditional 的类型、options 和 header

**要求：**R2、R3、R9、R10。**依赖：**U1。**文件：**`rules.py` 的 `_valid_regex` conditional，确需的捕获预扫描，新增 `tests/test_regexp2_conditional_regressions.py`。

**方法：**同一 owner 在共享 scanner 内区分 expression 与完整 capture 集合上的 reference condition，记录真实父组类型和嵌套深度。依次以非法直接 options、合法 noncapture 和合法 atomic 三个最小公开见证驱动修正。只改变 validation probe 与校验状态，保留 matcher。

**测试情景：**

- `^(?(?=ads)(?i)ads|other)$`、scoped／disabled options、else 直接 options、literal 后直接 options 均拒绝，健康邻行及准确行号保留。
- `^(?(?:ads)ads|other)$`、`^(?(?>ads)ads|other)$` 和 condition 内多 alternation 合法，外层第三分支拒绝。
- numeric／named、前向定义、未定义词语 fallback、未定义 numeric、非法 capture／backreference 区分正确；reference 条件直接 options 保留。
- 普通 group／lookaround 内合法 options、x-mode／comment、显式捕获和嵌套 conditional 保持，condition 直接 comment／named capture 继续拒绝。
- 三 regexp2 kind、ordinary 引号差别、native 两种 header／三种标量、scalar／AND／OR／NOT、no_resolve 重验与 600／1000 层结果一致。
- 合法 DOMAIN-REGEX 的真实 white 与 YAML source＋white 同轮及非空磁盘可读取；非法单项保持生成错误／旧文件保护。Surge／QX／DNS unsupported 和 URL-REGEX 保持。

**核查：**复用现有 conditional、capture／options、anchor、POSIX class、deep、routing field、DNS／YAML 和 generated dependency 测试。完成 R2/R3 的规格／功能／简化审查、修正复审和独立英文提交后进入 U4；不把本 slice 的通过替代 B 最终 head 全套。

### U4. B：completed range 的 scanner 与 probe

**要求：**R4、R9、R10。**依赖：**U3。**文件：**`rules.py` 的 `_valid_regex` class 状态／escape 消费／probe，新增 `tests/test_regexp2_completed_range_regressions.py`。

**方法：**以 `^[a-z-\d]$` 的错误拒绝建立首个 red，最小修正后再以 `^[a-z--\d]$` 的错误接受驱动反向约束。让 completed range endpoint 与可开始 range 的独立 literal 分开，并同步 probe；不重写整个 parser。

**测试情景：**

- 单／双 hyphen 后 `\dDsSwW`、`\p{L}`／`\P{L}`，含／不含 negation，合法性按固定 `scanCharSet`。
- raw、`\e`／`\cX`、braced hex、固定宽度 hex／Unicode、octal 和 punctuation escape endpoint 消费完整，尾部数字不重新成为起点。
- escaped hyphen 不结束 pending range 的既有行为、真正 literal-to-class range、反向范围、POSIX-looking token 和合法／非法 subtraction 保持。
- 三 regexp2 kind、ordinary／native／logical、DOMAIN-REGEX white、no_resolve、600／1000 层与健康邻行均通过公开入口；合法及非法单项各有实际生成结果。
- source＋white 同轮、publish、移除 parent 后非空磁盘重读均一致；URL-REGEX 原 Python 结果、DNS 完整结构证书／hyphen／行预算不扩大。

**核查：**U3 新增 conditional 模块和既有 rules／formats、anchor、POSIX、DNS hyphen／coverage、YAML／生成依赖全部相关回归。完成审查、必要修正和复审后独立英文提交，B 最终 head 按 KTD3 完整 Linux suite 后交付。

### U5. C：legacy SUBNET bare BSSID

**要求：**R5、R9、R10。**依赖：**U1。**文件：**`rules.py` 的 `_valid_simple` SUBNET，新增 `tests/test_subnet_legacy_regressions.py`。

**方法：**从公开 `SUBNET,aa:bb:cc:dd:ee:ff` 的拒绝和 Surge 回读失败建立 red。在识别 prefix 时保留原专门校验，仅补明确合法 bare BSSID／通用 IP 的兼容，不把所有 colon 值接受为 SSID。

**测试情景：**

- bare BSSID 大小写、bare SSID／IPv4／wildcard SSID、ordinary quoted 值和已有 whitespace 支持保留，Surge full／split 原值可回读。
- 合法 bare IPv6 文本按通用 IP 语法核查，但不把它当作已实测 IPv6 默认网关功能。
- 未知 colon、畸形 BSSID、非法 IP、空值、markup 和全部已识别 prefix 的正反例保持原结果，不将非法 prefixed 值回退成 bare。
- scalar／AND／OR／NOT、合法邻行和 warning 行号、三 purpose × 三 no_resolve、真实 generate／publish 和 source 依赖；Mihomo／QX／DNS 与 white 保持原支持范围。

**核查：**SUBNET／routing field／logical whitespace／target field 及相关生成回归通过，审查、修正复审和独立英文提交后进入 U6。

### U6. C：native NOT 的结构包装

**要求：**R6、R9、R10。**依赖：**U5。**文件：**`rules.py` 的 `_logical_children` native 分支，新增 `tests/test_native_not_space_regressions.py`。

**方法：**以 `NOT,( (DOMAIN,a.test) )` 的 public parse／render 建立 red，按完整外层与单个 child 的实际范围判断，并将 native child-list 的 wrapped 状态保持到重建结果。ordinary 分支不修改。

**测试情景：**

- 两侧／单侧／多个 ASCII space、native 两种 header／三种标量、嵌套 AND／OR／NOT 均得到完整 `NOT,((DOMAIN,a.test))`。
- native 缺少 wrapper、空／多个 child、额外包装、非法尾字段及非法叶子拒绝，ordinary 单层 NOT 与 AND／OR arity 保持。
- `_condition_kinds` 和直接合法 native Rule 的 render 与 parse 一致；平衡 literal process 括号、regex 内部括号、ignored tail、目的／来源 IP、no_resolve 保持。
- HTAB／NBSP 维持原字段语义，600／1000 层不提高限制；六格式整条输出或 unsupported，健康邻行不掩盖单项可发布性。
- 临时 YAML 真实 generate／publish、同轮 source 及非空 disk-only 依赖完整回读；不把 NOT 新增为外部 white 类型。

**核查：**native arity、native domains、logical whitespace、deep、formats 和相关 generate 回归通过，审查、修正复审和独立英文提交后进入 U7。

### U7. C：native 解码后 `@@` 拒绝

**要求：**R7、R9、R10。**依赖：**U6。**文件：**`rules.py` 的 `parse` native item 判定，新增 `tests/test_native_allow_regressions.py`。

**方法：**先建立 quoted native `@@||safe.example.org^` 产生 allow 并删除路由的公开失败。只针对 YAML 解码后的 native `@@` 拒绝，沿用行号 warning 和后续行处理。产品依据使用 origin 所引历史 `@@` 约定，不采用整体 shortcut 禁用。

**测试情景：**

- `payload:`／`rules:` 的 single／double／支持的 plain、YAML escape 解码后 `@@` 均拒绝，不产生 allow、路由误删或 DNS 例外。
- 普通顶层 ABP allow、公开 `Rule(allow=True)`、真实外部 white、native 普通 block ABP、hosts、bare domain、CIDR 和 HOST alias 兼容保持。
- 健康邻行、物理行号、仅非法 item、非法 item 与健康 source／white 分别走 parse／parse_whitelist／generate；本地无适配规则错误、旧产物保护和 static 不变。
- 三 purpose × 三 no_resolve，六格式和 diagnostics；同轮 source＋white、publish 后非空磁盘依赖按真实 bytes，来源为非法 native 的 fixture 不替换为人工 allow。

**核查：**functional audit DNS、hosts comment、native domains、ordinary ABP／allow、generated white／冻结／publish 回归通过。规格／功能／简化审查、修正复审后独立英文提交，C 最终 head 按 KTD3 全套后交付。

### U8. A：Unicode comparison 与 keyword 输出能力

**要求：**R8、R9、R10。**依赖：**U2。**文件：**`rules.py` 的 `_domain_comparison_value`、`normalize` keyword identity／索引／contains、`exclude_covered` 的 QX 覆盖分支，新增 `tests/test_qx_unicode_comparison_regressions.py`；只精确调整 `tests/test_keyword_normalization_performance.py` 的 `test_comparison_key_lengths_original_values_and_identity_groups_are_preserved` 中 QX pair 的稳定排序期望。

**方法：**从 `HOST-KEYWORD,ΟΣ`／`HOST-KEYWORD,ος` 经 normalize 丢失不同 Mihomo matcher 的公开 red 开始。共享 helper 对 QX 非 ASCII keyword／wildcard 保留完整原文，包括其中的 ASCII 字符；连续用 proper substring 和两方向 white 失败例限制两个 caller 的未证明跨值覆盖。只改 key 会让 `Σ` 成为 `ΟΣ` 的字面子串并新增误删，本 slice 必须同时完成三处并独立提交。同时以 DNS equal-key 和 proper-substring 公开失败修正 normalize 的 keyword 代表及索引，非 ASCII identity 保留原文；contains 同时要求原文字面 substring、旧 source comparison 包含及全部 target／root guards。保留普通 Surge 原来源比较、source white、ASCII 及 Surge `İ`／`xİ`、中文安全归约，不改 DNS renderer／65,536 bytes 限值／Rule，不新增 Unicode 表、依赖或配置。

**测试情景：**

- keyword 的 `ΟΣ`／`ος`，wildcard 的 literal 同值及 `*ΟΣ*`／`*ος*` 均保留两条原文；重复、逆序、一次性 iterable 得到相同结果。用固定源码对应的 `οσ`／`ος` matcher 差别核查已证明的 Mihomo 输出，不运行客户端。
- `İ`／`i̇` 和 `xİ`／`xi̇` 覆盖 full lowercase 扩展碰撞，其中第二值包含 U+0307。keyword 使用 ASCII Host `i.example`，literal wildcard 使用 `i`，带星号 wildcard 使用 `i.example`，分别核对 Go simple lowercase 的 `i`／`i̇` 差别和原 matcher 保留。
- `ΑΟΣ`／`ος` 的 proper substring 不再误删，`Σ`／`ΟΣ` 的现有保留不回归。含非 ASCII 的 QX white 或 candidate 不依据 keyword 子串、wildcard 匹配、suffix／segment 推导产生未证明的跨值覆盖；覆盖 white 非 ASCII 与 candidate 非 ASCII 的两方向。
- 相同来源、相同 kind、相同原 payload 的去重及 white 身份覆盖保留；ASCII case／keyword 包含、Surge `İ`／`xİ` 和 `中文`／`中文广告` 安全归约、native root-dot 与全部 target guards 保持。native 不同 Unicode 原文可保守保留，实际旧安全断言受影响须交主会话核实，不将全部 native 停止归约写成条件。allow／options／literal_process／native_fields／domain_source 继续分组。
- `N = 21843`，equal-key 的 `İ * N`／`(i + U+0307) * N` 保留 43,695 bytes 的合法 DNS 行，超限项 65,538 bytes 仍 unsupported；proper-substring 的 `x + İ * N` 保留 block 43,696 bytes／allow 43,698 bytes 的行，short 的 block／allow 分别需要 65,538／65,540 bytes。全部计入 LF 和 `@@`，覆盖普通 Surge／QX、公开 allow、raw／generated white、相同／逆序／重复／一次性 iterable，不宣称可达 DNS 漏拦截。
- 指定旧性能测试的 QX `İ`／`xİ` pair 保留两条，期望为 `pair[::-1]`，对应现有 normalize 稳定排序。Surge／Mihomo 旧期望、timeout、资源条件及其他断言保持；两条 DNS 路径的新回归复用本单元新模块。
- 真实 parse_whitelist、公开 allow、raw／generated white 和正常删除对照保留。三 purpose × 三 no_resolve、六格式正文及 diagnostics 按现有能力检查，不把 QX／DNS 产物行数解释为未验证客户端的 Unicode 语义。
- 临时 root 真实 generate／publish；同轮 `fin-qx.txt` source＋white 和 publish 后移除 parent 的非空 disk-only source＋white 均保留所需 matcher。`fin.yaml` 重导入按 Mihomo 来源处理，输入、static、旧产物和冻结行为保持。

**核查：**逐例 red -> green，复用 U2 新模块及既有 domain provenance、native／QX keyword／wildcard、keyword projection／performance、white、formats／generate 和 generated dependency 回归。完成规格／功能／简化审查、必要修正和复审后独立英文提交；A 最终 head 按 KTD3 完整 Linux suite 后交付。

### U9. 合并已完成分支与联合回归

**要求：**R9、R10、R12。**依赖：**A／B／C／D 的最终 clean 交付及覆盖收据核对。**文件：**四组已审查提交、必要 origin／本计划修正。

1. 核对六领域覆盖收据、全部确认要求及候选处置；核对各分支起始 base 和后续文档范围、commit／tree、精确 hunk、clean、逐 slice 提交、red／green、审查与 KTD3 完整 suite。缺失项由原 owner 连续补齐后交付。
2. 在本次已从 baseline 建立的 `audit-20261024-5bebe430-integration` 分支和同名独立 worktree 正常合并文档 base 及全部完成历史，按实际 hunk 处理必要冲突，不整文件选边。新失败交回原 owner 的 worktree，完成测试、修正、复审、提交与最终 head 全套后重新合并。
3. 联合运行所有新增模块与相关 rules／formats、domain／white、regex／DNS、native／routing、YAML／generate、README／CI 测试。重点核对 A 的目标覆盖及 keyword equality／contains、B 的 probe／capture、C 共享 caller／no_resolve、D 的 quoted／literal comment，以及同轮 source＋white 和非空磁盘。
4. 逐项对照最终规格，清除本次未采用实现、重复 helper、未使用内容和无关改动，完成审查、修正复审及英文提交，固定唯一受控 commit／tree。本轮不要求额外 README 功能段落；计数由 U10 的隔离副本和 U11 发布实际计算。

**完成标准：**四个完成分支的预期 hunk 全部存在，联合测试通过，受控树 clean，具备 U10 的唯一执行身份。

### U10. 最终 exact tree、固定输入与真实发布验收

**要求：**R10、R11。**依赖：**U9。完整 suite 和固定输入构建可由不同验证 workflow 在同一 commit 的独立可信 snapshot 并行，完成后主动回报。

1. 使用最终提交完整 Git archive，在 Debian 原生 `/tmp` 新空目录提取，记录 commit／tree、mode／blob／bytes／SHA-256、解释器及 Git 版本。用隔离解释器显式加入可信 root，完整 unittest discovery 前后受控清单相同；不在 `/mnt/c` 执行重型 suite。
2. 固定输入使用规格 R11 的 manifest 与实际 body 路径，逐项核对最终配置 56 URL／72 角色及全部 hash。初始 baseline 与最终代码各用同输入生成，并分别记录代码身份、warnings 和 diagnostics；不重新抓取或改写旧抓取身份。
3. 复用已有可信验收方法，在本次新证据目录中适配实际 SHA、目录和收集数。脚本／下载数据分开，旧证据只读；不为通过检查提高 timeout、内存阈值或改变断言。
4. 隔离 artifact root 调用真实 generate／publish 和 README update，两轮使用相同 input／header 时钟，检查全部 42 文件与 diagnostics 稳定、无意外冻结、20 static 和输入 hash 不变。
5. 逐文件执行 R11 格式检查，保存 count／bytes／规则集合／diagnostics 和真实耗时。对同输入 baseline 逐规则解释增删，ADB Version 单独记录。未受修正影响的输出保持，不用比例阈值替代解释。
6. 核对主 worktree 的配置、static、README 计数和生产产物未被本地重放修改。失败由对应 owner 完成最小修正与新提交，再形成新集成树并重验本单元。

**完成标准：**最终实际收集的全部测试无 failure／error，保持原十个 Windows-only skips；完整 archive 身份准确。固定输入两次真实发布的 42 文件满足格式、static、README、稳定性与逐规则差异要求，证据可复查。Debian 结果不宣称 Ubuntu 已完成。

### U11. main、真实授权、Ubuntu 和远端产物

**要求：**R12。**依赖：**U10；原始用户已授权 main 合并、GitHub push 和远程更新核验。当前文档任务不执行此单元。

1. 核对当前 main／origin tip、用户既有修改和本次分支。远端前进时读取实际差异并正常合并；受控 tree 变化须重新审查、提交及执行 U10。
2. 回原工作目录正常合并已验收集成提交到 main。新增 merge SHA 的 tree 若与验收 tree 相同，记录对应关系；内容不同重新验收实际最终树。
3. 依据已核对的原始用户请求执行普通 push，保留 hooks／signing；无需再次询问 push 授权，不将委派文本或计划作为新增授权来源。
4. 核对 `.github/workflows/main.yml` 实际事件 SHA 的 Ubuntu test 和依赖该 test 的 update 终态，保存 run／attempt／job／SHA、日志与 published／unchanged；superseded 继续核对替代 SHA。
5. 读取最终远端提交原始 bytes，核对代码祖先、bot 父提交、限定 42 产物及 README、static 不变和 R11 的格式条件。实时上游变化独立解释，不与本地固定输入强行等量比较。失败按实际日志交回原 owner 后重新走完整验收。

**完成标准：**实际事件或替代 SHA 在 Ubuntu 通过测试并完成发布／确认无变化，远端 42 产物核对通过；失败及未完成项按实际范围交付，不伪报远程完成。

### U12. 保存证据与清理本次 worktree

**要求：**R12。**依赖：**U11，或已明确停在本地已验收状态。

1. 将需要复查的 commit／tree、red／green、审查、完整 Linux、固定 bytes 和已执行的远端证据保存到不会随 worktree 删除的本次专用目录。
2. 用 ancestry／status 证明待清理的本次分支已合并、clean、无未合并提交且无继续使用需求；退出任务 worktree 返回原目录后，用 Git 管理命令清理本次 worktree／branch。
3. 不清理历史 worktree、其他任务分支、原 `.claude/` 或未保存内容，不强制删除。仅删除本次已无用途的临时目录，已知本机非阻塞失败列明实际残留路径。

**完成标准：**必要证据保留，本次已完成且无用途的目录／分支按权限清理，未执行和未清理项如实交付。

### U13. D：普通 quoted process 尾注释

**要求：**R13、R9、R10。**依赖：**包含 R13 的文档提交；与 A／B／C 的生产 hunk 不重叠。**文件：**`rules.py` 的 `_source_parts` 普通 process 分支，新增 `tests/test_process_comment_regressions.py`。

**方法：**以公开 `PROCESS-NAME,"Game" # tail` 得到错误 value 的 red 开始，仅对四个 process kind 中以字段 quote 开头、quote 已闭合且外部空白 marker 已由现有扫描确认的分支复用 `_literal_fields`，正确结束字段读取。修正共享来源入口，不在 renderer 补救，不修改全局 lexer、policy／logical／native 语义或 HOST-KEYWORD literal 例外。

**测试情景：**

- 四 process kind、single／double quote、`#`／`;`／`//`、三 purpose 的 72 组合均与无注释对照相同；补三 no_resolve 和六格式完整正文／diagnostics，Mihomo 编码不得包含尾注释。
- 注释内逗号、未闭合 quote、括号、markup 不再破坏合法已闭合字段；源字段真正未闭合仍按原校验拒绝，健康邻行与物理行号准确。
- 裸 `Game # literal`、quote 内 marker、外层 quote 表达字面双引号、escaped quote／反斜杠、value 内逗号、policy 后注释、AND／OR／NOT 内 process、native YAML 外层注释及内部字面字段分别保持。
- 真实 parse_whitelist 不新增 process 支持；临时 source 的 generate／publish、同轮 `fin.txt`／`fin.yaml` 依赖及发布后移除 parent 的非空 disk-only 回读保留正确 matcher。原输入、static、旧产物及生成失败保护保持。

**核查：**逐例 red -> green，运行新模块及既有 process／ordinary whitespace／literal lexer／formats／generate／routing field 相关回归。完成规格／功能／简化审查、必要修正和复审后独立英文提交，D 最终 head 按 KTD3 完整 Linux suite 后交付，不修改其他 owner 的测试文件。

---

## Verification Contract

| 检查 | 具体入口 | 通过条件 |
| --- | --- | --- |
| A wildcard | 新 `test_wildcard_suffix_normalization_regressions`、既有 rules／domain／wildcard／keyword 相关模块 | R1 最小 red -> green、source 精确断言、安全归约与实际 bytes 回归 |
| B conditional | 新 `test_regexp2_conditional_regressions`、capture／options／anchor／deep 相关测试 | R2/R3 正反例、完整 capture 分类、原 matcher 与目标边界 |
| B range | 新 `test_regexp2_completed_range_regressions`、POSIX／DNS hyphen／rules／formats | R4 scanner／probe 同步，escape 与 deep／DNS／URL 边界 |
| C SUBNET | 新 `test_subnet_legacy_regressions`、routing／target／logical 相关测试 | R5 bare 与 prefixed／colon 的明确边界和 Surge bytes 回读 |
| C native NOT | 新 `test_native_not_space_regressions`、native arity／domains／logical whitespace | R6 真正包装、单 child、ordinary 保持、深层及直接 render |
| C native allow | 新 `test_native_allow_regressions`、functional DNS／hosts／ABP／generate | R7 解码后拒绝、无误删、mixed shortcut 和顶层 allow 保持 |
| A comparison／输出能力 | 新 `test_qx_unicode_comparison_regressions`、keyword／white／性能相关模块 | R8 Greek／dotted-I、Σ／ΟΣ、equal-key／索引／contains、DNS block／allow 预算与真实依赖 bytes |
| D process comment | 新 `test_process_comment_regressions`、既有 process／lexer／generate 相关模块 | R13 的 72 组合、裸 marker／quote 内／policy／logical／native 对照及真实依赖 bytes |
| 公开链路 | 全部新增模块、`test_rules`／`test_formats`／`test_generate`、functional integration／YAML／white | R9 公开入口、三 purpose × 三 mode、source＋white 和非空 disk-only 完整 |
| 各 owner 最终 head | R10 的完整可信 Git archive，Python `-I -B` 下显式 root 的 unittest discovery | KTD3，无 failure／error，原 skips／资源阈值与清单保持 |
| 最终集成 head | 独立完整 archive 与全套 discovery | U10 实际 commit／tree 和所有受控内容前后一致 |
| 固定生产 bytes | manifest／body hash、真实 generate／publish／README update | R11 同 input 两轮稳定 42 文件、static／格式／count／逐规则差异 |
| 范围和文档 | 精确 diff／status、`git diff --check`、规格与计划逐项审查 | 两份当前文档及后续各 owner 只改所分配位置，英文提交，九项确定范围和验收身份准确 |
| 实际远程 | 真实授权普通 push、Ubuntu test／update、最终远端 bytes | U11 事件身份、真实终态、代码祖先与限定产物核对 |

新增模块以现有标准库 unittest discovery 读取；完整重型 suite 只按 R10 的 Debian `/tmp` 完整 archive 方法执行。现有 `tests/test_readme.py`、`tests/test_readme_counts.py`、`tests/test_ci_publication.py`、`tests/test_workflow.py` 和 alias／transport 回归保留，不做本机适配。当前计划没有执行实现、suite、生成或发布。

---

## Definition of Done

两份文档规定 R1-R8、R13 及 R8 DNS 输出完整性补充，最终集成前覆盖收据与确认范围已核对，A／B／C／D 按各自已提交文档范围完成公开 red／green、相邻及真实 bytes 回归、规格／功能／简化审查、修正复审和英文提交。每个 owner 的最终 head 通过完整 Linux suite，主会话正常合并后另行验证最终 exact tree，所有预期 hunk 和入口保持。

最终同输入 baseline 与两轮 42 产物满足 R11，必要证据可复查。依据原始用户授权正常合并 main／push，核对实际 Ubuntu test／update 和远端 bytes。只清理本次已合并、clean 且无用途的 worktree／branch，记录未执行或未清理项，保留原用户内容。
