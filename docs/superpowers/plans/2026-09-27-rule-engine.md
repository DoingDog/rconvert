# 原生规则引擎 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Each task uses a failing test before implementation and a fresh green run afterward.

**Goal:** 将不同来源逐行转换为保留规则语义的内部规则，并产生六种客户端文件。

**Architecture:** `rules.py` 定义唯一规则数据结构，并解析、排除、去重；`formats.py` 只负责按目标能力渲染，不访问网络或文件系统。两者共享已提交的 `Rule` 接口，之后可在独立 worktree 并行完成。网络、文件写入和 CI 在后续集成任务中接入。

**Tech Stack:** Python 3.11+ 标准库，`unittest`，仓库内 `.venv`。

**Spec:** `docs/superpowers/specs/2026-09-27-native-rules-design.md`

## Global Constraints

- 现有五组各六个 `fin*` 路径保持不变；新增 `a3` 的同名六个文件；`static/` 不改。
- 保留每种目标格式可适配的全部来源规则类型，包括 Mihomo `SRC-IP-CIDR`、`PROCESS-NAME`、端口、逻辑规则等；不按旧脚本的删除表过滤公共规则。
- a3 仅使用 AdRules、AntiAD 和 AWAvenue 完整列表；dirt 定向补充；非去广告组的 `fin-adb.txt` 不输出拦截规则。
- 使用 Python 标准库，不执行下载的代码或二进制；所有测试、虚拟环境与临时文件位于仓库 worktree 内。
- 每一项先运行相应失败测试，再以最少代码使其通过。对不适配目标的规则记录类型与数量，不伪造匹配等价性。

## Review Focus

1. `DOMAIN-WILDCARD,*.example.com` 不匹配根域；覆盖去重不能把它错误替换成后缀。由 Task 2 的 wildcard 用例保护。
2. 来源 `@@||safe.example.com^` 与宽后缀同时存在时，删掉宽规则不能误删无关窄规则。由 Task 2 的例外用例保护。
3. `SRC-IP-CIDR,2001:db8::/32` 在 Mihomo 保持来源地址匹配，不能变成 `IP-CIDR6`。由 Task 3 的 IPv6 用例保护。
4. QX `LIST` 只是策略占位，不是内建动作；渲染结果必须保留字段且文档要求调用方设置 `force-policy`。由 Task 3 的 QX 用例保护。
5. `DOMAIN,exact.example.com` 不能转换成覆盖子域的 `||exact.example.com^`。由 Task 3 的 AdBlock 用例保护。

---

### Task 1: 共享规则契约

**Files:** Create `rules.py`; create `tests/test_rules.py`.

**Interfaces:**
- Produces: `Rule(kind: str, value: str, options: tuple[str, ...] = (), allow: bool = False)`，不可变、可哈希；`kind` 规范为大写，域名类型的 `value` 规范为小写并去掉末尾的点，其他类型保留值的大小写。`options` 保存正规化的逐条选项，不保存输出策略。
- Consumes: Python 标准库 `dataclasses`，无项目依赖。

- [ ] **Step 1: Write the failing test**

```python
import unittest
from rules import Rule


class RuleTests(unittest.TestCase):
    def test_domain_canonicalization_and_process_case(self):
        self.assertEqual(Rule("domain", "Ads.Example.COM."), Rule("DOMAIN", "ads.example.com"))
        self.assertNotEqual(Rule("PROCESS-NAME", "FooApp"), Rule("PROCESS-NAME", "fooapp"))
        self.assertEqual(len({Rule("DOMAIN", "EXAMPLE.COM"), Rule("domain", "example.com")}), 1)
```

- [ ] **Step 2: Verify red**：运行 `.venv/Scripts/python.exe -m unittest discover -s tests -p 'test_rules.py' -v`，预期 `ModuleNotFoundError: rules`。
- [ ] **Step 3: Implement**：在 `rules.py` 用 `@dataclass(frozen=True, slots=True)` 定义 `Rule`，仅在 domain 系类型上规范化 `value`；其余逻辑留给 Task 2。
- [ ] **Step 4: Verify green**：运行同一命令，并运行 `.venv/Scripts/python.exe -m unittest discover -s tests -v`。
- [ ] **Step 5: Commit**：提交 `rules.py`、`tests/test_rules.py` 和 `.gitignore`。

### Task 2: 解析、排除与确定性去重

**Files:** Modify `rules.py`; modify `tests/test_rules.py`.

**Interfaces:**
- Consumes: Task 1 的 `Rule`。
- Produces: `parse(text: str, *, purpose: str) -> tuple[list[Rule], list[str]]`，purpose 为 `"block"`、`"direct"` 或 `"proxy"`，分别只接受同用途动作或无动作规则，第二项含来源行号与未转换原因；`normalize(rules: Iterable[Rule], exclusions: Iterable[str] = ()) -> list[Rule]`，返回稳定顺序且不含已排除或被可靠覆盖的规则。调用方在下载、解码和限制响应大小后传入正文。

- [ ] **Step 1: Write first failing test**

```python
import unittest
from rules import Rule, parse


class ParseTests(unittest.TestCase):
    def test_mixed_inputs_and_wildcard_survive(self):
        rules, warnings = parse("HOST-SUFFIX,EXAMPLE.COM,REJECT\nDOMAIN-WILDCARD,api-*.example.com\n0.0.0.0 ads.test\nbody{", purpose="block")
        self.assertIn(Rule("DOMAIN-SUFFIX", "example.com"), rules)
        self.assertIn(Rule("DOMAIN-WILDCARD", "api-*.example.com"), rules)
        self.assertIn(Rule("DOMAIN", "ads.test"), rules)
        self.assertNotIn("body{", [rule.value for rule in rules])
        self.assertTrue(warnings)
```

- [ ] **Step 2: Verify red**：运行该测试，确认失败原因是 `parse` 尚未实现。
- [ ] **Step 3: Implement and verify green**：只增加逐行格式识别及必要验证；运行该测试与完整 `tests/test_rules.py`。
- [ ] **Step 4: Repeat red/green vertically**：分别以已知字面结果增加 ABP `@@` 和条件过滤、Surge DOMAIN-SET、单引号 YAML `payload`、QX 策略字段、`SRC-IP-CIDR`、端口、进程、逻辑 `AND/OR/NOT`、HTML 输入、未知类型告警测试；每条先观察失败再实现。
- [ ] **Step 5: Cover semantic dedup and exclusions**：先测 `DOMAIN-SUFFIX,example.com` 覆盖精确域名和子后缀，但不能覆盖 `notexample.com`；先排除后压缩并保护未排除的窄规则；相同 wildcard 及有完整标签边界可证冗余的 wildcard 去重；对 IPv4/IPv6、来源/目标 CIDR 与 `no-resolve` 分组后用 `ipaddress.collapse_addresses` 聚合。每条用例单独经历红绿。
- [ ] **Step 6: Verify and commit**：运行 `.venv/Scripts/python.exe -m unittest discover -s tests -v`，提交 Task 2 修改。

### Task 3: 客户端目标格式渲染

**Files:** Create `formats.py`; create `tests/test_formats.py`.

**Interfaces:**
- Consumes: Task 1 的 `Rule`，以及 Task 2 返回的规则序列；渲染不得调用下载函数或改写输入规则。
- Produces: `render(group: str, rules: Iterable[Rule]) -> tuple[dict[str, str], dict[str, int]]`。第一个字典的键严格为 `fin.txt`、`fin-qx.txt`、`fin.yaml`、`fin-adb.txt`、`fin-surge.txt`、`fin-surge-ds.txt`；第二个字典按目标和被跳过类型记录计数。每个文件有确定性头部与 LF 行尾。

- [ ] **Step 1: Write first failing test**

```python
import unittest
from rules import Rule
from formats import render


class FormatTests(unittest.TestCase):
    def test_wildcard_survives_compatible_targets(self):
        out, skipped = render("a3", [Rule("DOMAIN-WILDCARD", "api-*.example.com")])
        self.assertIn("DOMAIN-WILDCARD,api-*.example.com", out["fin.txt"])
        self.assertIn("HOST-WILDCARD,api-*.example.com,LIST", out["fin-qx.txt"])
        self.assertIn("DOMAIN-WILDCARD,api-*.example.com", out["fin.yaml"])
        self.assertNotIn("api-*.example.com", out["fin-surge-ds.txt"])
```

- [ ] **Step 2: Verify red**：运行 `.venv/Scripts/python.exe -m unittest discover -s tests -p 'test_formats.py' -v`，预期 `ModuleNotFoundError: formats`。
- [ ] **Step 3: Implement and verify green**：仅实现第一个用例的格式映射，运行该测试及全套测试。
- [ ] **Step 4: Repeat red/green vertically**：用已知字面输出覆盖 Mihomo `SRC-IP-CIDR` IPv4/IPv6、`PROCESS-NAME`、`SRC-PORT`、`DST-PORT`、`IP-ASN`、`AND`；Surge `SRC-IP`、`DEST-PORT`；QX `HOST`、`HOST-SUFFIX`、`IP6-CIDR`、`LIST`；Surge DOMAIN-SET 只有裸域名和前导点后缀；AdBlock 仅去广告组且不能拓宽精确域名；三组非去广告 `fin-adb.txt` 注释占位；兼容性不足的类型只进入跳过计数。每例先红再绿。
- [ ] **Step 5: Verify and commit**：运行 `.venv/Scripts/python.exe -m unittest discover -s tests -v`，提交 Task 3 修改。

**Integration order:** Task 1 先在当前 worktree 运行并提交；Task 2 与 Task 3 各在独立 worktree 同时 TDD 开发；依次 cherry-pick 两者提交并运行完整测试。后续来源配置、文件生成、Linux Actions 和真实规则再生成另列集成任务。