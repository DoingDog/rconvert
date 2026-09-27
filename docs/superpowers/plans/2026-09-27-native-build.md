# Linux 原生生成与发布 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Test each observable behavior red -> green before the next one.

**Goal:** 在 Linux GitHub Actions 上用仓库内 Python 虚拟环境安全生成六组各六个固定路径的文件。

**Architecture:** `sources.load_sources` 只读取各组源清单；`rules.parse/normalize` 处理语义；`formats.render` 输出文本；`generate.py` 只负责 HTTPS 获取、依赖顺序、失败保护和发布。先用离线受控输入走完真实模块，再验证联网运行，不允许旧脚本或外部二进制执行。

**Tech Stack:** Python 3.11+ 标准库、`unittest`、`ubuntu-latest`、工作区内 `.venv`。

**Spec:** `docs/superpowers/specs/2026-09-27-native-rules-design.md`

## Global Constraints

- 原有 a1/a2/big-data/cdn/dirt 的 30 个 `fin*` 路径不变，新增 a3 的相同六个；`static/` 18 个已跟踪文件绝不改。
- a3 仅下载 AdRules `qx.conf`、AntiAD `anti-ad-surge.txt`、AWAvenue 完整 QX 规则；dirt 定向加入 gaoyifan IPv4/IPv6 与 Loyalsoldier Apple 中国列表，不加大型中国域名列表或重复的 domestic_cdn。
- `a1` 用本次 `a2/fin.txt`，`big-data` 用本次 `cdn/fin.txt`；同一次网络 URL 不重复获取。
- 失败不覆盖已有产物；成功时 UTF-8 LF、固定排序、无当前时间字段；每种输出保留其客户端所有可适配来源类型。
- 所有运行、测试、暂存数据、虚拟环境均在 worktree 内；无第三方 Python 包及外部可执行文件；CI 不使用 `git push --force`。

## Review Focus

1. a1 不得读上次的 a2 文件：同一 fixture 两次构建，在第二次变更 a2 源，a1 内容随之改变。
2. 最后一个 URL 失败时，已生成的所有目录旧文件仍逐字节相同。
3. 200 HTML、GitLab 登录页或非法 UTF-8 不得进入 `fin*`，必须有非零退出状态和来源 URL。
4. gaoyifan 的裸 IPv4/IPv6 CIDR 必须进入 dirt 的 Mihomo/Surge/QX IP 输出，并按地址族合并；不得写入 `fin-adb.txt`。
5. CI 中测试工作和有写权限的定时更新分离，不能让 PR 执行写仓库步骤。

---

### Task 4: 离线端到端构建和失败保护

**Files:** Create `generate.py`; create `tests/test_generate.py`.

**Interfaces:**
- Consumes: `sources.load_sources(root: Path, group: str) -> list[str | Path]`；`rules.parse(text: str, *, purpose: str) -> tuple[list[Rule],list[str]]`（purpose 分别为 block/direct/proxy）；`rules.normalize(rules, exclusions) -> list[Rule]`；`formats.render(group,rules) -> tuple[dict[str,str],dict[str,int]]`。
- Produces: `generate(root: Path, fetch: Callable[[str], bytes]) -> dict[Path,str]`，仅返回全部 36 个目标路径的已验证文本，不修改任何输出；`publish(outputs: Mapping[Path,str]) -> None` 只在完整 generate 成功后写工作区内临时文件并替换目标。CLI 在仓库根调用 `generate`、`publish`。

- [ ] **Step 1: Write a failing integration test**：在 `tests/test_generate.py` 用 `unittest.TestCase` 先于测试创建仓库内 `.tmp/`，再用 `tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1] / '.tmp')` 创建六组简短配置及本地来源；假 fetch 返回带 `DOMAIN-WILDCARD`、`SRC-IP-CIDR`、`IP-CIDR6` 的可解码字节。断言 `set(generate(root, fake_fetch))` 恰好等于 `{root / group / name for group in ('a1','a2','a3','cdn','big-data','dirt') for name in ('fin.txt','fin-qx.txt','fin.yaml','fin-adb.txt','fin-surge.txt','fin-surge-ds.txt')}`。
- [ ] **Step 2: Verify red**：运行 `.venv/Scripts/python.exe -m unittest discover -s tests -p 'test_generate.py' -v`，确认缺少 `generate` 行为。
- [ ] **Step 3: Implement and verify green**：仅实现六组分派与内存输出，运行该测试及完整测试集。
- [ ] **Step 4: Repeat vertical TDD**：先测 `a1` 使用本轮 a2、big-data 使用本轮 cdn，随后测同一 URL 只获取一次、`del.ini` 生效、来源策略阻止 `DIRECT` 进入 block、裸 IPv4/IPv6 CIDR、同组含未知类型时告警计数；路由组域名排除与 `DOMAIN-KEYWORD` 冲突、AdGuard DNS 宽拦截配合 `@@` 例外时保留宽规则，分别用真实输出断言。每个新测试先失败再实施。
- [ ] **Step 5: Failure cases first**：分别让 fake fetch 返回 404 异常、超时、HTML、空列表、非法 UTF-8、最后一个 URL 失败；先测调用 publish 前旧输出字节未变，再以可注入的替换失败测试覆盖第 2 个文件替换时抛错的回滚行为；然后实现 fetch 的 HTTPS、证书、响应大小与超时检查，以及全部解析成功后才发布、发布异常时恢复旧文件。
- [ ] **Step 6: Verify and commit**：运行 `.venv/Scripts/python.exe -m unittest discover -s tests -v`，检查 `git diff HEAD -- static` 为空且原 18 个路径及未跟踪文件无变化，提交此任务文件。

### Task 5: Linux 工作流与文档

**Files:** Modify `.github/workflows/main.yml`、`README.text`；delete `.github/workflows/history.yml`、`.github/workflows/size.yml`、`.github/workflows/del.yml`、`r.cmd`；create `tests/test_workflow.py` only if it actually runs the generated command on a Linux runner or checks a consumer-visible effect rather than comparing YAML strings.

**Interfaces:**
- Consumes: Task 4 的 `generate.py` CLI；Linux 内置 `python3`、`git` 和 GitHub 官方 checkout Action。
- Produces: Ubuntu 定时、手动构建，以及只读权限的 PR 离线测试。定时更新采用 `python3 -m venv .venv`、`.venv/bin/python -m unittest discover -s tests -v`、`.venv/bin/python generate.py`；检查 `git diff HEAD --exit-code -- static`、18 个既有路径及未跟踪 static 文件，只暂存六组生成物，有变化才正常提交、推送。README 包含六组用途、QX `LIST` 与 `force-policy`、Mihomo classical、Surge 两种文件的配套关系、规则来源与混合许可。

- [ ] **Step 1: Test the real command**：在隔离临时 fixture 下运行 `.venv/Scripts/python.exe generate.py --root <fixture>`，预期先失败于缺失 CLI 或参数，再实现相同 CLI 并运行一次成功。Windows 本地只验证命令行为，最终 Linux CI 验证 `.venv/bin/python` 路径。
- [ ] **Step 2: Configure GitHub Actions**：仅官方 checkout，无第三方删除运行记录 Action；在独立测试 job 上使用 `contents: read`，更新 job 仅在非 PR 时使用 `contents: write`，设置 `concurrency` 防止同时推送。
- [ ] **Step 3: Remove unsafe entry points**：先检查 `r.cmd` 和历史清理工作流的内容（已在调查读过），删除动态下载 EXE/ZIP/JAR 和强推步骤，不保留不执行的失效入口。
- [ ] **Step 4: Update README and verify**：说明 upstream GPL/AGPL/MIT 与当前 WTFPL 的范围，分别注明 AWAvenue GitHub GPL-3.0 和旧官网文字冲突；运行完整 unittest，核对 GitHub workflow 使用 Ubuntu 且不含 `push -f`，确认 `static` 不变。
- [ ] **Step 5: Commit**：提交 workflow、README 和旧入口移除。

### Task 6: 真实源更新、验证与性能报告

**Files:** Modify only the 36 generated `fin*` files; amend code/tests only for real-input failures proven by a newly failing regression test.

- [ ] **Step 1: Run live build**：用工作区 `.venv` 运行 `.venv/Scripts/python.exe generate.py`，逐源核实非零状态；不得在失败时提交部分产物。
- [ ] **Step 2: Diagnose and TDD-fix**：遇到 200 HTML、暂时 403、格式不支持、超时或例外冲突时保留原始错误与源 URL，写一个能复现的离线失败测试，再最小改动使其通过；只有可验证的过时链接才从清单移除。
- [ ] **Step 3: Verify deterministic artifacts**：完整测试、规则格式校验和构建连续执行两次，第二次 `git diff` 不得增加差异；核对五组旧文件路径与六个 a3 文件完整，`git diff HEAD -- static` 为空，且 static 未出现新文件。
- [ ] **Step 4: Benchmark and record**：固定输入在 `.venv` 内离线运行至少三次并记录中位数、峰值内存、真实网络耗时；旧脚本不能安全执行，不能声称与旧数字逐字可比。
- [ ] **Step 5: Final review and commit**：审阅 36 个文件及源代码差异，按 `a1 a2 a3 cdn big-data dirt` 六组暂存并提交；保留分支与 worktree，不推送或合并到 main。