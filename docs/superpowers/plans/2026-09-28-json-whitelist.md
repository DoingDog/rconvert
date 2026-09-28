# JSON Rulesets and Whitelist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用 JSON 配置生成六组原路径规则集，并以集合完整覆盖语义应用来源同型白名单。

**Architecture:** 保留 `Rule`、现有解析器、六种 renderer 和 `generate(root, fetch)` 公开入口。`sources.py` 读取根目录 `rulesets.json`，`rules.py` 解析并应用白名单，`formats.py` 输出目标客户端规则和 AdGuard DNS 的例外，`generate.py` 按配置顺序读取、处理并发布。三个互不编辑相同文件的任务在隔离 worktree 并行完成，再由主 worktree 集成。

**Tech Stack:** Python 3.11+ 标准库、`unittest`、仓库内 `.venv/Scripts/python.exe`、git worktree。

**Spec:** `docs/superpowers/specs/2026-09-28-json-whitelist-design.md`

## Global Constraints

- 不修改主仓库的工作区；只把用户已修改的 `static/main/Direct.list`、`static/main/NoReject.list` 原样带入当前 worktree 和最终提交，除此不改 `static/`。
- 旧 `del.ini` 内容全部废弃。六个 `rule-list.ini` 只迁移启用的来源，最终删除全部十份 INI。
- 输出固定为六组各自的 `fin.txt`、`fin-qx.txt`、`fin.yaml`、`fin-adb.txt`、`fin-surge.txt`、`fin-surge-ds.txt`，共 36 个原路径。
- AdGuard DNS 的精确 DOMAIN、后缀、keyword、可安全转换的 wildcard 不能扩大匹配；新白名单另输出对应的 `@@`，IP 不生成 DNS 例外。
- 只删被白名单完整覆盖的规则；源 `@@` 不删较宽路由规则；不支持的规则不参加目标格式的错误去重。
- 所有 Python 测试和生成调用使用当前 worktree 的虚拟环境。每个新行为先验证 RED，再最小实现 GREEN，跑全套离线测试后提交。

## Review Focus

1. 精确白名单域名碰到宽 `DOMAIN-SUFFIX`，宽规则仍保留，DNS 例外只覆盖精确域名。
2. `DOMAIN-WILDCARD` 无法输出到 Surge DOMAIN-SET 时，该文件保留未被真正覆盖的精确／后缀规则。
3. QX／Surge 白名单规则带其他策略时仍按类型和值排除，但 USER-AGENT／PROCESS 不产生白名单效果。
4. `IP-CIDR` 与 `SRC-IP-CIDR` 方向不同、IPv4 与 IPv6 不混淆，父网段可覆盖子网段，反向不可以。
5. JSON 路径越界、非 HTTPS、无效结构或指向尚未生成的组，均失败且不会发布部分输出。

---

### Task 1: JSON 配置和来源解析（与 Task 2、3 并行）

**Files:** `sources.py`、`tests/test_sources.py`、新增 `rulesets.json`。不要编辑 `generate.py` 或删除旧 INI，最后集成时再清理。

**Interfaces:** `load_config(root: Path) -> list[dict]` 读取并验证按顺序排列的组；`resolve_source(root: Path, entry: str) -> str | Path` 解析一个 HTTPS URL 或仓库相对路径。数据包含 `name`、`purpose`、`no_resolve`、`sources`、`whitelist`。保持现有 `load_sources` 临时可用，供并行任务和旧测试使用。

- [ ] 先在 `tests/test_sources.py` 增加行为测试，例如在 `TemporaryDirectory(dir=ROOT)` 中写 `rulesets.json`，`load_config(root)[0]['name'] == 'a2'`、`resolve_source(root, 'static/main/Direct.list') == root / 'static/main/Direct.list'`；同时测试 HTTP、越界、非列表 JSON、重复组名、未知 purpose 被拒绝。运行 `.venv/Scripts/python.exe -B -m unittest tests.test_sources -v`，确认缺失接口导致 RED。
- [ ] 用标准库 `json`/`pathlib`/`urllib.parse` 实现最小验证；来源仓库路径以根目录为准并在 `resolve()` 后检查 `is_relative_to(root)`。运行同一命令，确认 GREEN。
- [ ] 将原六份 `attach/rule-list.ini` 中启用的条目按原顺序迁入 `rulesets.json`；a1 的本轮依赖为 `a2/fin.txt`，big-data 的依赖为 `cdn/fin.txt`，a3 的 `whitelist` 为 `static/main/Direct.list` 和 `static/main/NoReject.list`，其他组暂为空列表。测试这些关系、全部 36 个预期输出目录名和配置边界。
- [ ] 在独立分支提交 Task 1 的文件，并返回 commit SHA、RED/GREEN 命令及结果。

### Task 2: 白名单解析及完整覆盖（与 Task 1、3 并行）

**Files:** `rules.py`、`tests/test_rules.py`。不要编辑 `generate.py`／`formats.py`；暂不移除原 `normalize(..., exclusions)`，集成时在新测试保护下移除。

**Interfaces:** `parse_whitelist(text: str) -> list[Rule]` 使用现有语法读取、忽略 action／policy、只返回允许的域名与 IP 类型；`exclude_covered(rules: Iterable[Rule], whitelist: Iterable[Rule]) -> list[Rule]` 只删匹配集合被完整覆盖的源规则，忽略 `no-resolve` 等输出选项差异，不混合 src/dst 或地址族。源码 `@@` 不应删掉与之仅相交的宽路由规则。

- [ ] 新增先失败的例子：`[DOMAIN-SUFFIX,a.com]` 遇 `DOMAIN,a.com` 保留、遇 `DOMAIN-SUFFIX,com` 移除；`DOMAIN,sub.a.com` 遇 `DOMAIN-SUFFIX,a.com` 移除；`IP-CIDR,192.0.2.0/25` 遇同方向 `/24` 移除，反向或 `SRC-IP-CIDR` 不移除。逐个运行 `tests.test_rules` 中具体测试，观察 RED 后实现 GREEN。
- [ ] 增加 QX `host-suffix,a.com,DIRECT`、Surge `DOMAIN-KEYWORD,ads,REJECT`、`USER-AGENT,*bot*` 与 `PROCESS-NAME,App` 混合白名单的测试；无效格式按现有 parser 跳过并报告，不执行来源里的命令或正则。
- [ ] 为 wildcard／keyword 写可证明覆盖与不可证明覆盖的反例，包含 Surge bracket wildcard；如果无法证明，只保留源规则。以 `tests.test_rules` 全集及完整测试命令检查性能不回退。
- [ ] 在独立分支提交 Task 2 的文件，并返回 commit SHA、RED/GREEN 命令及结果。

### Task 3: AdGuard DNS 格式与白名单例外（与 Task 1、2 并行）

**Files:** `formats.py`、`tests/test_formats.py`。不要编辑 `generate.py`、`rules.py`、JSON。保持现有 `render(group, rules)` 测试接口；可以新增可选白名单输入，在集成时连接。

**Interfaces:** `render(group: str, rules: Iterable[Rule], *, whitelist: Iterable[Rule] = ()) -> tuple[dict[str, str], dict[str, int]]`。新白名单只在 block 组增加 AdGuard DNS `@@` 行；来源 `allow=True` 保留原 `@@`，但不改变其他目标格式。

- [ ] 在 `tests/test_formats.py` 先写并运行 RED：`Rule('DOMAIN','exact.example.org')` 在 `fin-adb.txt` 只能输出裸 `exact.example.org`，后缀仍输出 `||example.org^`；keyword 值含 `.` 要转义正则；`api-*.example.org` 以锚定 DNS 正则表示，`[...]` 若不安全则跳过并计数。
- [ ] 再写并运行 RED：`whitelist=[Rule('DOMAIN','safe.example.org'), Rule('DOMAIN-SUFFIX','safe.org')]` 产生锚定的精确 DNS 例外 `@@|safe.example.org|` 和后缀 `@@||safe.org^`，不能把前者扩大为后缀；IP 白名单不产生 DNS 行。实现最少格式逻辑后运行全套格式测试 GREEN。
- [ ] 新增 `DOMAIN-WILDCARD,api-*.example.org` 与独立精确域名共同渲染的测试，断言 Surge `fin-surge-ds.txt` 保留精确域名，QX/Mihomo 格式符合官方语法。
- [ ] 在独立分支提交 Task 3 的文件，并返回 commit SHA、RED/GREEN 命令及结果。

### Task 4: 集成、删除旧入口及 CI（等 Task 1、2、3 合入）

**Files:** `generate.py`、`tests/test_generate.py`、`rules.py`（删除旧 exclusions 实现）、`formats.py`（只把配置 purpose/no_resolve 接到已有 renderer）、`README.md`、`.github/workflows/main.yml`、`tests/test_workflow.py`；删除六份 `rule-list.ini`、四份 `del.ini`。仅把主仓库两份用户 static 改动的精确 diff 应用到当前 worktree。

**Interfaces:** 保留 `generate(root, fetch) -> dict[Path, str]`、`publish(outputs)`、命令 `generate.py --root <path>`；从 `load_config` 循环，经 `resolve_source` 读取规则与白名单，调用 `parse_whitelist`、`exclude_covered`、`normalize`、`render(..., whitelist=...)`。配置顺序不满足组依赖时抛异常，决不读旧磁盘产物。

- [ ] 将 `tests/test_generate.py` 的临时 fixture 改为写根目录 `rulesets.json`，先新增 a3 两份本地白名单、URL 白名单缓存、宽后缀+精确白名单、后缀包含、上游 `@@`、错误 URL 原子发布及动态组用途测试；单个用例先 RED，再逐步集成 GREEN。
- [ ] 在测试保护下移除 `normalize` 的 `exclusions` 参数与旧冲突删除／自动例外路径，移除硬编码组名、用途与 AdGuard 组集合；动态配置驱动 `no_resolve`。保持 36 个文件原路径，删除十份 INI，更新 README 配置与 DNS 用法。
- [ ] 应用用户两份 static 修改的原始 patch，先运行现有 CI static 检查确认 RED；仅改 CI 中两处快照哈希，使这两份改动后的树为唯一允许状态，GREEN；新增测试防止将新 hash 写回旧值。
- [ ] 用当前 worktree 的 `.venv/Scripts/python.exe -B -m unittest discover -s tests -v` 跑完整套件；执行 `git diff --check`、确认 `static/` 差异仅有两处用户修改和全部 36 个目标路径仍存在。

### Task 5: 真源生成、独立审查和提交

**Files:** 仅按测试失败修复上述任务涉及的文件，以及运行生成器后确实变化的既有 `*/fin*` 路径。

- [ ] 在虚拟环境里先以离线 JSON fixture 跑完整生成流程，再尝试 `.venv/Scripts/python.exe -B generate.py` 抓取真实 HTTPS 来源；任何失败都记录 URL 与错误，不把旧输出误称为新生成物。
- [ ] 并行独立审查规格与路径、白名单包含关系／性能、客户端规则语法、CI／static；经复现后对缺陷继续按 RED -> GREEN 修复。
- [ ] 最后再次运行全套测试、校验 36 个输出路径、static tree、新旧 INI 均不存在和工作区差异；用显式路径暂存并提交，只提交本任务与用户指定的 static 改动，不推送。
