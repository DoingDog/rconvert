# Six-format Rule Preservation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve every proven representable rule in the six existing outputs, fix direction-changing conversions, and apply `no_resolve` to supported logical IP leaves according to configuration.

**Architecture:** Keep the existing `parse -> exclude_covered -> normalize -> render` pipeline. Correct source interpretation in `rules.py`, including the supported YAML scalar subset and regexp2 field boundaries; use target-specific conversion in `formats.py`, and preserve verified Mihomo YAML process/domain source semantics through `Rule` and `generate.py`. Build no new subsystem or runtime dependency.

**Tech Stack:** Python 3.11+ standard library, `unittest`, GitHub Actions; optional local Mihomo CLI for syntax spot-checks only.

**Spec:** `docs/superpowers/specs/2026-09-29-rule-preservation-design.md`

## Global Constraints

- Keep `formats.FILES` exactly `fin.txt`, `fin-qx.txt`, `fin.yaml`, `fin-adb.txt`, `fin-surge.txt`, `fin-surge-ds.txt`; do not add a target or change output paths.
- Do not add product dependencies, download or execute a client in the production build, or change tracked files under `static/`.
- A target that cannot express a rule skips only that output and increments its skip count; it must never emit a reversed or broader matcher.
- `no_resolve` applies to supported destination-IP leaves only. `add` adds one flag, `strip` removes it, `keep` retains one source flag, including inside `AND`/`OR`/`NOT` without reordering children.
- Quantumult X remote fourth-field interface parameters are unverified. Preserve the three-field matcher and record loss of the interface option; do not claim that remote interface selection remains effective.
- Preserve Mihomo YAML `PROCESS-NAME` literals containing `*`/`?` and Surge-source process globs as distinct rule intents.
- All modifications are test-first. Use `C:/Users/user/.local/bin/python.exe` for local tests; the default LibreOffice Python causes two CLI tests to fail with `WinError 5`.
- 每个 Git 编码子任务使用独立 worktree 的动态 workflow，连续完成编码、测试、规格与质量审查、必要修复及复审，达到完成条件后单独提交；互相独立的任务并行执行，主会话只核对已完成任务的修改范围并合并。选择 Claude 模型时使用当前可用的 `[1m]` 长上下文型号。
- 全面扫描按六种产物及共享解析、白名单、规范化、生成依赖、逻辑表达式和 `no_resolve` 分支并行覆盖，记录覆盖情况并补查遗漏。最终 a3 两类各 100 条核查作为产物检查，不能代替全面分析。
- 现有累计改动保存在共享本地基线 checkpoint，该提交不表示问题已全部修复。全部任务整合、完整测试及最终审查通过后再正常推送 main；原有未跟踪 `.claude/` 不暂存，`static/` 不修改，不强推。

## Review Focus

- An uppercase `SRC` policy remains a destination-IP matcher; a lowercase fourth-field `src` after a policy yields a source-IP matcher. Mihomo rejects a policy-free single `src` unless a policy group named `src` exists, so an unresolvable plain source must warn rather than infer direction. Task 1 and the scoped follow-up test all six targets.
- A target-specific `IP-SUFFIX,no-resolve` must not leak an unsupported `IP-SUFFIX` into Surge or QX: Task 1 tests every output.
- Spaces and quoted commas inside logical children must not silently discard the complete rule: Task 2 and Task 3 test both inputs.
- Nested `no-resolve` and `NOT` must preserve child order and truth conditions while changing only eligible leaves: Task 3 tests mixed and nested child types.
- Mihomo-specific regexp2 syntax, field splitting, YAML plain/single/double scalar rules, and HTML error-page detection must work together: Tasks 2/4 test literal `{` and `{b,c}` inside regex, `(?#...)` comment groups, YAML ` #` versus `;`／`//` comments, quoted backslashes, valid `(?<name>...)`／`\z`, and real HTML rejection.

---

### Task 1: Source IP direction and target-specific IP options

**Files:** Modify `rules.py:370-445`, `formats.py:13-36,120-199`, `generate.py:219-228`; test `tests/test_rules.py`, `tests/test_formats.py`, `tests/test_generate.py`.

**Interfaces:** Consume `parse(text, *, purpose, ignore_policy=False)` and `render(group, rules, *, purpose, no_resolve, ...)`. Produce `Rule("SRC-IP-CIDR", ...)`, `Rule("SRC-IP-SUFFIX", ...)`, `Rule("SRC-GEOIP", ...)`, `Rule("SRC-IP-ASN", ...)` when a case-sensitive lowercase `src` is an option in the actual source grammar; distinguish provider inputs without a policy from inline inputs with a policy. Keep `IP-SUFFIX` `no-resolve` for Mihomo only.

- [ ] **Step 1: Write failing tests.** Add cases in `tests/test_rules.py` equivalent to:

```python
rules, warnings = parse("IP-CIDR,192.0.2.0/24,SRC\nIP-CIDR,192.0.2.0/24,PROXY,src", purpose="proxy")
self.assertEqual(rules, [Rule("IP-CIDR", "192.0.2.0/24"), Rule("SRC-IP-CIDR", "192.0.2.0/24")])
self.assertEqual(warnings, [])
self.assertEqual(parse("IP-SUFFIX,8.8.8.8/24,PROXY,no-resolve", purpose="proxy")[0],
                 [Rule("IP-SUFFIX", "8.8.8.8/24", ("no-resolve",))])
```

Add a `tests/test_formats.py` case verifying source CIDR maps to `SRC-IP` in both Surge files and `SRC-IP-CIDR` in YAML, not destination CIDR in QX; verify `IP-SUFFIX` with `no_resolve="add"` appears in YAML with one flag and never appears in Surge or QX.

- [ ] **Step 2: Run red.** `C:/Users/user/.local/bin/python.exe -m unittest tests.test_rules tests.test_formats -q`; require failures on the new assertions, not an environment error.
- [ ] **Step 3: Fix the common parse action/option partition.** Separate the third-field policy from subsequent case-sensitive `src` options and map only documented IP-family matchers to source kinds. Preserve a policy named `SRC`; warn about an ambiguous plain third-field lowercase `src`, while a policy `src` plus an explicit fourth-field `src` remains a source rule. Accept `no-resolve` for destination `IP-SUFFIX`; do not put `IP-SUFFIX` through the Surge or QX option branch. Preserve an existing source IP matcher even when an irrelevant option is warned about. Restrict each renderer's emitted kinds to its declared supported set; leave skipped counters intact.
- [ ] **Step 4: Run green.** Run `tests.test_rules`, `tests.test_formats`, and the new local-source `tests.test_generate` case; verify per-target skip counts and that no output reverses direction.

### Task 2: Logical input normalization without dropping children

**Files:** Modify `rules.py:47-72,180-227,250-445`; test `tests/test_rules.py`.

**Interfaces:** Keep `Rule("AND"/"OR"/"NOT", value)` as a well-formed nested expression string. `_fields()` already understands quoted commas and balanced bracket classes. Normalize a port comparison to its closed interval and `80/443` to an inner `OR`, rather than accepting a rule that render later drops.

- [ ] **Step 1: Write failing tests.** Include:

```python
rules, warnings = parse("AND,((SRC-PORT,>=50000),(DOMAIN,a.example.com)),PROXY", purpose="proxy")
self.assertEqual(warnings, [])
self.assertIn("(SRC-PORT,50000-65535)", rules[0].value)
rules, warnings = parse("OR,((DST-PORT,80/443),(DOMAIN,a.example.com)),PROXY", purpose="proxy")
self.assertEqual(warnings, [])
self.assertIn("(OR,((DST-PORT,80),(DST-PORT,443)))", rules[0].value)
```

Test `AND,((DOMAIN,a.example.com), (DOMAIN,b.example.com))`, `(DOMAIN ,a.example.com)`, a quoted process comma, and `IP-CIDR,...,no-resolve,no-resolve`; add `AND,((PROCESS-NAME-REGEX,^Game{bar$),(DOMAIN,a.example.com)),DIRECT`、regex literal `{b,c}` with custom policy `China`、`(?x:(?#note[)...)` 与 `(?#note\)...)` 的有效/无效对照。YAML plain `;`／`//`、字符类中的空格 `#`、单引号内反斜杠与有效的双引号 `\x73` 分别按 YAML 1.2.2 及 Mihomo 实际加载核对；assert that accepted inputs remain complete and malformed HTML/ports still warn. Update the pre-existing `test_logical_child_skips_port_forms_not_safe_for_both_renderers` expectation only after recording red.

- [ ] **Step 2: Run red.** `C:/Users/user/.local/bin/python.exe -m unittest tests.test_rules -q`.
- [ ] **Step 3: Implement the smallest recursive normalization at the existing logical parser boundary.** 在 `_fields` 及 YAML `payload:` 解析入口按来源语法区分结构括号、真正数值量词与正则字面 `{`/成对 `{b,c}`、注释组内字符；YAML plain 只以空格后的 `#` 引入注释，单引号内反斜杠是普通字符。继续复用 `_port_comparison`，只去除引号外的语法空白，将符合条件的重复 `no-resolve` 规范化为一次，并保留子规则顺序。 Keep unsupported child types intact in the shared Rule so each target can decide locally; do not remove a child to rescue a logical rule.
- [ ] **Step 4: Run green.** Run `tests.test_rules` and focused logical cases in `tests.test_formats`.

### Task 3: Target-aware logical rendering and recursive no-resolve

**Files:** Modify `formats.py:37-97,115-210`, adjust `generate.py:219-228` only if pre-normalization would otherwise reintroduce duplicates; test `tests/test_formats.py`, `tests/test_rules.py`, `tests/test_generate.py`.

**Interfaces:** Reuse parsed `Rule.value` logical expression and `_fields` from `rules.py`. For each target, translate children before checking target support. Keep `_logical_value(...) -> str | None` and extend it with `no_resolve` or a target-specific argument without affecting current callers.

- [ ] **Step 1: Write failing tests.** In `tests/test_formats.py`, require `AND,((NETWORK,udp),(DOMAIN,a.example.com))` to emit `PROTOCOL,UDP` in both Surge RULE-SET outputs, and `AND,((DEST-PORT,443),(DOMAIN,a.example.com))` to emit `DST-PORT,443` in YAML. Require quoted `PROCESS-NAME,'Foo,Bar'` and comma-containing `URL-REGEX` to survive valid Surge quoting; check `fin-surge-ds.txt` remains domain-only.

```python
source = Rule("OR", "((IP-CIDR,192.0.2.0/24),(GEOIP,CN,no-resolve))")
added, _ = render_configured("a3", [source], purpose="block", no_resolve="add")
stripped, _ = render_configured("a3", [source], purpose="block", no_resolve="strip")
self.assertIn("(IP-CIDR,192.0.2.0/24,no-resolve)", added["fin.txt"])
self.assertNotIn("no-resolve", stripped["fin.txt"])
```

Add `keep`, nested `AND`/`OR`/`NOT`, Mihomo-only `IP-SUFFIX`, unsupported source IP, and duplicate-flag cases. Replace the old `tests/test_rules.py:529-544` strip assertion after confirming it fails under the new requirement.

- [ ] **Step 2: Run red.** `C:/Users/user/.local/bin/python.exe -m unittest tests.test_formats tests.test_rules -q`.
- [ ] **Step 3: Update the existing logical renderer.** Use `_fields` to split children, normalize space and valid quoted payloads, map Surge and Mihomo aliases before checking the target set, reuse top-level quoting for comma-containing values, and apply add/strip/keep only to supported destination-IP leaves. `IP-SUFFIX` receives this option only for Mihomo. Never attach `no-resolve` to a logical parent or rewrite one target's unsupported kind as another kind.
- [ ] **Step 4: Run green.** Run targeted tests then `C:/Users/user/.local/bin/python.exe -m unittest discover -s tests -q`; check `fin.txt` and `fin-surge.txt` stay paired.

### Task 4: Domain patterns and regexp2 preservation

**Files:** Modify `formats.py:75-111,185-211`, `rules.py:205-210,250-286,421-430`; test `tests/test_rules.py`, `tests/test_formats.py`, `tests/test_generate.py`.

**Interfaces:** `_dns_pattern(Rule) -> str | None` must return `/.../` or `@@/.../`-ready patterns only when their DNS matching range is preserved. Mihomo converts a safe Surge wildcard character class to anchored `DOMAIN-REGEX` rather than dropping the Rule.

- [ ] **Step 1: Write failing tests.** Cover `DOMAIN-WILDCARD,api-[0-9].example.com` from Surge and Mihomo YAML separately: Surge 的字符类命中数字，Mihomo 原生的方括号是字面文本，不得误匹配数字；both DNS block and explicit allow for Surge must match a digit and reject a letter. Add case-sensitive native Mihomo keyword/wildcard versus case-insensitive Surge source comparisons on uppercase Host, logical children, white-list coverage direction, normalization, generation dependencies and all six target outputs; unknown QX matching behavior must not become a reason to discard representable rules. Cover a portable `DOMAIN-REGEX,^api[0-9]\.example\.com$` in DNS, while regexp2-only constructs remain out of unverified DNS output. Test `DOMAIN-REGEX,^(?<name>ads)\.example\.com$` and `DOMAIN-REGEX,^ads\.example\.com\z` accepted for Mihomo, with real `<html><body>login</body></html>` still rejected while process regex `^<!doctype$` and a following valid rule are preserved. Add a bounded-timeout subprocess RED for an unterminated `\\x{41` escape; malformed input must warn instead of hanging. Check excessive numeric quantifiers for `OverflowError` against Mihomo syntax. Keep `*ads` rejected as an obvious invalid source regex. Update `tests/test_formats.py:33-41,520-535` assertions that currently require the wildcard to be skipped.
- [ ] **Step 2: Run red.** `C:/Users/user/.local/bin/python.exe -m unittest tests.test_formats tests.test_rules -q`.
- [ ] **Step 3: Fix only proven conversions.** 按来源转换已验证的 Surge `[a-z0-9-]` wildcard 字符类，转义字面点号并锚定完整 hostname；Mihomo YAML 只有 `*`、`?` 具有通配意义，不得将原生方括号当字符类。保留能影响输出或覆盖判断的来源语义；Surge 大小写不敏感的 keyword/wildcard 转 Mihomo 时须在真实大写 Host 输入上保真，Mihomo 原生规则转到无法表达区分大小写的目标时跳过并计数；不等价构造按目标处理。 Avoid treating `(?<...>)` within a well-formed regex rule as an HTML tag, while preserving the document-level HTML guard. Do not use Python `re.compile` as a blanket regexp2 gate; keep explicit rejection for obvious malformed sources and do not drop valid regexp2 `\z` or named groups. Do not treat Python `(?P<...>)` as Mihomo-supported.
- [ ] **Step 4: Run green.** Run focused tests and the full suite; if a local Mihomo binary is available, run an optional `-t` check for the new YAML examples without making it a build prerequisite.

### Task 5: Source-sensitive process semantics and Quantumult X fallback

**Files:** Modify `rules.py:10-24,250-445`, `formats.py:69-86,151-190`, `generate.py:219-228`; test `tests/test_rules.py`, `tests/test_formats.py`, `tests/test_generate.py`; update `README.md:41-56` only where behavior changes.

**Interfaces:** Add `literal_process: bool = False` to `Rule` as the last field. A `PROCESS-NAME` parsed inside a Mihomo `payload:` uses `literal_process=True`; plain Surge-style input retains `False`. Preserve this field when reconstructing Rule for no-resolve handling and through normalize; include it in any key that groups or orders rules whose output differs by this flag, so mixed sources remain deterministic. Apply the source distinction to a process child inside a logical YAML rule as well as a top-level process rule. Mihomo literal names keep `PROCESS-NAME,Foo*Bar`, Surge globs map to `PROCESS-NAME-WILDCARD,Foo*Bar`. If a target cannot preserve a literal `*` process name, skip only that target and report it.

- [ ] **Step 1: Write failing tests.** Assert that `parse('payload:\n  - "PROCESS-NAME,Foo*Bar"\n', purpose='proxy')` retains the literal marker, while `parse('PROCESS-NAME,Foo*Bar,PROXY', purpose='proxy')` retains glob interpretation. Test both render outputs, a logical YAML process child with `*`, and preservation through `normalize` and `generate` when both source intents have the same matcher. Assert `PROCESS-PATH-WILDCARD,/usr/*/wget` becomes `PROCESS-NAME,/usr/*/wget` in Surge.

```python
rules, warnings = parse("HOST-SUFFIX,googleapis.com,PROXY,force-cellular", purpose="proxy")
self.assertEqual(warnings, [])
self.assertEqual(rules[0].kind, "DOMAIN-SUFFIX")
self.assertIn("HOST-SUFFIX,googleapis.com,LIST", render_configured(
    "proxy", rules, purpose="proxy", no_resolve="keep")[0]["fin-qx.txt"])
```

Repeat the QX case for `multi-interface`、`via-interface=pdp_ip0` 和官方历史配置出现的 `via-interface=en1`；验证其他输出不写入接口选择文本、不丢可表达 matcher。QX 远程产物仍只写三字段，省略接口语义单独计数；`en0` 和远程第四字段是否有效不得无客户端证据就宣称支持。

- [ ] **Step 2: Run red.** `C:/Users/user/.local/bin/python.exe -m unittest tests.test_rules tests.test_formats tests.test_generate -q`.
- [ ] **Step 3: Preserve source intent at the existing YAML parse boundary.** Add the marker only where the source establishes Mihomo semantics; avoid guessing from `*` alone. 将已文档化的 QX 接口选项（包括合法的 `via-interface=<name>` 值）与策略字段区分，不因固定接口名列表丢弃 matcher。 Render remote three-field matchers, report omitted interface behavior, and keep plain Surge process globs unchanged.
- [ ] **Step 4: Run green.** Run focused tests and the complete 277-plus-test suite.

### Task 6: End-to-end check, review, and publish

**Files:** Review `rules.py`, `formats.py`, `generate.py`, `tests/test_rules.py`, `tests/test_formats.py`, `tests/test_generate.py`, `README.md` if changed, and the two new docs. Do not stage unrelated files or `static/`.

**Interfaces:** Existing `generate(root, fetch)` and `formats.FILES` retain their public signatures and all six outputs. The GitHub Actions workflow `.github/workflows/main.yml` runs `test` then `update` on a push to `main`.

- [ ] **Step 1: Add one local-source integration test.** Use `configure_groups` or a temporary `rulesets.json` to feed `src`, nested IP `no-resolve`, wildcard character class, and YAML literal process name through `generate`. Assert all six output files exist, supported targets retain the expected matcher, QX/DNS/domain-set files omit only unrepresentable types, and `dirt` strips eligible flags.
- [ ] **Step 2: Run the integration test and record its actual result.** If an independently specified cross-component case fails, confirm RED, fix the responsible behavior and confirm GREEN. If Tasks 1-5 already make it pass, report it as an integration regression check, not a witnessed RED. Then run `C:/Users/user/.local/bin/python.exe -m unittest discover -s tests -q`, `git diff --check`, `git diff --exit-code -- static`, and `git status --short`. The original baseline was 277 passing tests, so every new test must also pass.
- [ ] **Step 3: Independent review.** Have a fresh subagent challenge each repaired case with an input that would be silently dropped, broadened, or reversed; fix verified regressions with another red-green cycle. Check emitted YAML with Mihomo `-t` where available and relevant official syntax; do not make client binaries a CI dependency.
- [ ] **Step 4: Commit each completed task after its tests and independent review pass.** Stage explicit approved paths only, inspect `git diff --cached --stat` and `git diff --cached --check`, then create a normal task commit; do not include `.claude/`, scratch reports, or amend an existing commit. Independent tasks use separate worktrees from the shared baseline checkpoint. Integrate their commits and rerun the complete suite before publication.
- [ ] **Step 5: Push and confirm remote build.** Push the current `main` to `origin/main` without force, find the push-triggered GitHub Actions run, observe `test` and `update`; if either fails, inspect logs, repair with TDD, commit, push again, and verify the new run. If `update` creates a bot commit, confirm its result and report the final remote SHA. Never describe a merely queued or locally passing job as remotely successful.

## Verified post-review regressions (complete before Task 6 publication steps)

An independent eight-agent audit after Tasks 1–6 found the following concrete missed inputs. These three repairs remain subject to all Global Constraints and to task-scoped RED -> GREEN -> review. The original Task 6 integration test ran green on first run; do not rewrite that history.

### Task 7: Preserve valid source input without misclassifying HTML or policy

**Files:** `rules.py`, `tests/test_rules.py`, `tests/test_formats.py` only if a target output assertion requires it.

- [ ] Add failing tests for logical `AND,((IP-CIDR,192.0.2.0/24,src),(DOMAIN,x.example.com))`, QX `HOST-SUFFIX,googleapis.com,PROXY,multi-interface-balance`, literal `PROCESS-NAME,Foo]Bar` in YAML, and regex `PROCESS-NAME-REGEX,^foo<bar>$`. Verify both a true HTML document after `\k<html>` and a regex containing literal `<bar>` at the same time.
- [ ] Add failing tests for supported Mihomo regexp2 `\p{N}`, `\p{Nd}`, `\p{Han}`, `(?'n'...)`, duplicate named groups and `(?n:...)`, while rejecting Python-only `(?a:...)`. For `DOMAIN-REGEX,^foo,bar$,PROXY` and policy-free `DOMAIN-REGEX,^foo,bar$`, prove preservation of the full matcher or an explicit non-broadening warning; do not interpret a successful client `-t` alone as proof that an unquoted comma has the intended match set.
- [ ] Run focused RED using `C:/Users/user/.local/bin/python.exe`, implement the smallest changes at input classification, then run focused and full green tests. Confirm no true HTML page is imported and no valid source matcher is silently broadened.

### Task 8: Preserve process matcher scope in Surge and Mihomo outputs

**Files:** `formats.py`, `tests/test_formats.py`, `tests/test_generate.py` only for a cross-component regression.

- [ ] Write failing target-output tests for `PROCESS-NAME-REGEX,^Foo{1,2}Bar$` at top level and inside AND: Mihomo accepts commas in these values. Test Surge `PROCESS-NAME,/usr/bin/ssh` and an absolute-path glob mapped respectively to Mihomo `PROCESS-PATH` and `PROCESS-PATH-WILDCARD`, including logical children. Test Mihomo literal `PROCESS-PATH,/Applications/Foo*Bar` stays exact in Mihomo but does not broaden into Surge full-path glob, at top level or inside AND. A Mihomo name-only `PROCESS-NAME-WILDCARD,/usr/*/ssh` must likewise not become a Surge leading-`/` full-path glob, top-level or inside AND; preserve Mihomo and count skipped Surge outputs.
- [ ] Run RED; render only client-supported equivalent matchers, skip only the incapable target and count it; run focused/full green tests and `git diff --check`.

### Task 9: Keep portable DNS regex and publish whitelist-only changes

**Files:** `formats.py`, `generate.py`, `tests/test_formats.py`, `tests/test_generate.py`, `README.md` (update the freeze description only if behavior changes).

- [ ] Write failing tests for AdGuard DNS block and `@@` output of proven-portable `DOMAIN-REGEX` using `\z`, `\A`, `\x{61}`, `\p{Nd}`, `(?:...)`, capture-only `(?<name>...)` (including duplicate names), scoped ASCII `(?i:ads)`, and verified `\p{L}` uses. Validate match scope with both regexp2 and AdGuard DNSEngine, not compilation alone: regexp2 `\d` is Unicode but Go `\d` is ASCII, so translate it to proven-equivalent `\p{Nd}`; POSIX-looking `[[:alpha:]-a]` and regexp2 class subtraction `[a-z-[aeiou]]` must not be emitted unchanged, including `@@`. Skip with a counted omission unless a target-equivalent rewrite is proven. Reject Go-invalid property ranges such as `[a-\\p{L}]`, and verify a Go-valid property class such as `[\\p{L}-a]` semantically before preserving it. A Go-incompatible bound `{0,1001}` must not be emitted; a regexp2 repetition `{01}` must not be written unchanged into Go regex where it matches literal braces. Preserve intended scope with proven equivalent output when possible. Do not mistake a POSIX bracket-class literal `{01}` for an outer repetition. Keep backreferences and other unproven Mihomo-only constructs out of DNS; test block and `@@` together.
- [ ] Reproduce the freeze bug with old outputs and valid sources wholly covered by a whitelist: both domain blocks with DNS `@@` and IP blocks without DNS exceptions, including proxy/direct groups, must replace all six old outputs. Also test a valid allow-only source. A generated header-only upstream rule file is a valid empty dependency for both `sources` and `whitelist`; propagate the empty result where appropriate. Any actual rule body that this parser cannot adapt, whether no rules or only some rules parse (e.g. generated AdBlock block regex alongside a parseable suffix or exception), must prevent publishing incomplete dependent outputs and identify the source. Handle case-varied in-memory generated paths correctly on Windows. Preserve separate freeze behavior for unavailable/empty ordinary sources, including a missing remote source alongside an empty generated dependency. Update pre-existing freeze assertions only after observing RED against the new requirements.
- [ ] Run RED, make minimal fixes, run focused and full tests plus `git diff --check` and `git diff --exit-code -- static`. Complete the independent Task 9 review before publication.

### Task 10: Correct independently reproduced whole-change findings

**Files:** `rules.py`, `formats.py`, `generate.py`, their three test files, and this plan if review evidence changes an earlier expectation.

- [ ] Write failing parser tests for valid regexp2 Unicode properties, inline flags and named backreferences; reject Mihomo-invalid possessive quantifiers and quoted invalid logical regex. Normalize lowercase logical child types, keep explicit source-IP children when ignoring `no-resolve`, and apply same-direction `SRC-*` whitelist entries without covering destination matchers. Cover the generated dependency chain where quoted YAML `PROCESS-NAME,Game #1` becomes a plain `fin.txt` source: downstream parsing must not silently change its matcher to `Game`. Reproduce the independent parser-review failures: regexp2 property at the end of a character range (`[a-\p{Lu}]`) and a quantifier directly after zero-width inline flags (`(?i)+`) must be rejected, while nearby valid constructs remain. Preserve process-name/path/wildcard/regex values containing `#`, `;`, or `//` both in standalone rules and logical children, and through generated dependencies; continue to recognize actual whole-line and non-process trailing comments. The next parser review also requires tests for hexadecimal escapes as character-range endpoints, scoped/global `(?x)` state changes, ordinary apostrophes in regex and YAML scalars, true trailing comments after a regex containing policy-like text, and unquoted literal commas in logical regex children.
- [ ] Write failing six-output tests for Surge app-bundle path prefixes and Mihomo exact trailing-slash paths, including AND children. Also check Surge's documented case-sensitive process name/path matching against Mihomo's `EqualFold`/lowercased wildcard matcher in both conversion directions; if an inline case-sensitive `PROCESS-*-REGEX` can preserve the Surge rule, use it after client verification, otherwise skip and count the incapable target rather than changing match scope. Fix quoted logical regex output using Mihomo runtime matching as evidence. Add DNS block and `@@` tests for POSIX classes, regexp2 class subtraction, Unicode `\d`, and verified portable escape forms; test DNS patterns against legal hostnames normalized to lowercase as verified in the public AdGuard Home and AdGuardDNS request paths; record the bare DNSEngine uppercase shortcut as a direct-API limitation, not a server-side rule regression. Separately verify source DOMAIN-KEYWORD and DOMAIN-WILDCARD behavior on uppercase Host inputs in Mihomo and Surge before changing their target expressions, preserving their distinct source semantics. Skip any target expression whose match scope cannot be preserved and count it.
- [ ] Write failing output and dependency tests for literal ` #`, ` ;`, ` //` in process, USER-AGENT and URL-REGEX matchers. Apply the documented Surge VALUE-quoting syntax where it preserves the value; distinguish local roundtrip from unavailable Surge binary verification. Generated `fin.txt` must not silently change matchers in downstream groups. Restore the valid `.com` DOMAIN-SET suffix as `DOMAIN-SUFFIX,com` when used as a source, and reject colliding group output paths (including Windows `cdn`/`CDN`) before any publication so a frozen group cannot be overwritten.
- [ ] Verify each focused RED/GREEN cycle, full unittest, `git diff --check`, and unchanged `static/`; run independent scoped and whole-change reviews on the final code. Only after the reviews pass, stage the explicit changed paths, make one normal commit, push `main`, and verify GitHub Actions `test` and `update` plus the final remote SHA.

### Task 10 scoped-review follow-up: Parser field lexer and YAML scalars

**2026-09-30 来源范围裁决：** 来源语法复核确认同一普通裸 regex 可以有互斥的完整 matcher／策略加尾注释解释。按 spec 对真实歧义给行号 warning，明确引用字段／provider／无策略叶子的 matcher 完整保留。不得再以锚点、全文逗号或注释尾字符猜测范围。下面历史阶段次序由本节末尾的来源适配器执行次序更新；保留全部验证类别，不重复已完成的 Unicode 名称研究。

**Files:** `rules.py`, `tests/test_rules.py`, necessary `tests/test_generate.py`; for the later output round, `formats.py`, `tests/test_formats.py`.

- [ ] From the sixth parser-round frozen baseline, add independent RED tests for recognized regexp2 delimiter boundaries: escaped or nested literal braces, character classes with first-position `]`, `(?#...)`, `(?x)` comments, and literal commas versus ambiguous unquoted policy fields. Preserve Mihomo-valid conditional groups and escape forms without accepting nearby invalid regex; reject an extra `)` with a warning and keep later rules, while a deeply nested valid expression must not crash. Make the shared scanner change and run focused/full GREEN plus real Mihomo loading, then independent review. Representative inputs are `DOMAIN-REGEX,^a\{b,c\}$,China`, `PROCESS-NAME-REGEX,^[]a,b]Game$,China`, a Mihomo provider `PROCESS-NAME,Game{`, and a balanced 495-level group with an extra closing parenthesis as the invalid neighbor. Also verify `IP-CIDR,192.0.2.0/24,SRC` with a real `SRC` policy remains a destination rule rather than being mistaken for the lowercase `src` option.
- [ ] After lexer review, add RED tests for Mihomo YAML outer scalar quoting versus inner literal matcher quotes, the verified decoder's complete fixed escape set, invalid/incomplete escapes and surrogates, multiple ASCII spaces after the dash, preserved decoded controls/tab/Unicode separators, ASCII-only comment/key whitespace, and a BOM-prefixed HTML document. YAML inputs are standalone classical provider files: both `payload:` and `rules:` alias use no-target grammar; full client configs are validation fixtures, not a new import feature. Split every literal comma and trim only field-edge ASCII space. Provider regex `^Game,REJECT` keeps the suffix, whereas ordinary policy-bearing lines and full configs have a target field; verify these distinct entry points. Ordinary provider second fields are payload and later fields are constructor-specific params, including case-sensitive IP `src`/`no-resolve`; inner quotes/backslashes do not protect commas. Make the source-specific change, run focused/full GREEN and actual loaded Mihomo matcher checks, then independent review. Representative inputs include literal quote characters inside a YAML process matcher, `\U00000073`, `\x85`, an invalid isolated `\uD800`, provider `PROCESS-NAME,Game\,Inc`, and all verified external provider header spellings.
- [ ] Add bounded subprocess RED tests for 600 and 1000 nested `NOT` wrappers around a valid leaf and a later valid rule. Mihomo v1.19.31 accepts these precise inputs; the parser currently exceeds Python's recursion depth near 497 levels and the renderer fails at 1000. Replace the relevant recursive traversal with explicit state, preserve child order and source metadata, and reject nearby invalid deep inputs with warnings. Test `no_resolve=add/strip/keep` at the innermost destination-IP leaf without flags on source-IP or logical parents. Do not raise the global recursion limit or discard a supported rule to avoid the crash; independently review both parser and renderer changes.
- [ ] During the formats process task, add RED tests for Mihomo process/regex matchers containing escaped control characters and U+0085/U+2028/U+2029. Preserve client-supported values in `fin.yaml` using verified safe YAML scalar escapes; retain input validation for malformed rule types/values. Other targets lacking a proven equivalent encoding must skip and count rather than emit physically split lines. Check all six products, generated dependency round trips, and non-BMP Unicode neighbors; do not emit JSON surrogate pairs that the target YAML decoder rejects.

### Task 10 source adapters and bounded field consumption

**Files:** `rules.py`、`formats.py`、`generate.py`、三个既有 test 文件，`README.md` 仅补充真实来源歧义与引用方式。其他授权边界不变，原有未跟踪 `.claude/` 不得暂存，`static/` 不得修改，不得强推。

**Interfaces:** 保持 `parse`／`Rule`／`render` 公共入口和原调用兼容。为原生 provider 逻辑增加末尾默认 false 的 `Rule.native_fields`，由私有 condition／children 消费入口传递；不将 `literal_process` 改作通用来源标志。保留标志参与的 normalize／覆盖／重建结果，禁止合并语义不同的同文逻辑规则。普通来源的明确字段语法、provider 的 native split/rejoin 与无策略逻辑字段分别消费。

- [ ] **Step 1: Record exact RED and source interpretation.** 为准确裸歧义 `DOMAIN-REGEX,^a{b$,My Proxy # note}c$|^foo$` 写行号 warning／后续 DOMAIN 的 RED。分别为引用完整 matcher 和引用短 matcher 加策略／尾注释写保留测试；完整非法 matcher 放在引用字段、provider 和逻辑叶子的明确范围中验证拒绝。对于历史裸 custom-policy／literal-comma／marker 用例，保留准确裸行的 warning 测试，再用引用形式保留原正反例；逐项记录实际入口证据，不删除保护类别。原本 GREEN 的明确保护测试不伪称 RED。
- [ ] **Step 2: Establish source adapters together with fix8.** 先识别独立 provider block/header/scalar，再解码单行子集，使用 ASCII field trim 和 native split/rejoin。普通来源使用一个私有 `_source_parts` 一次确认字段／来源 comment，未知范围直接 warning。PROXY／LIST／DIRECT／block action 的兼容尾字段仅用于普通入口。删除 `_regex_source_end` 等全文／anchor 判定路径，matcher 范围只验证一次；不借编译结果选择候选。fix8 的完整 header、escape、control、BOM/HTML 与方向验证要求全部保留。
- [ ] **Step 3: Consume bounded condition/children and preserve provenance.** `_fields` 接收隔离的条件／列表及明确 native 字段模式，不判断策略／来源尾注释。regex 叶子的完整剩余范围属于 matcher；普通叶子的 params 按来源消费。`_normalize_condition`、`_normalize_logic`、`_has_process_name`、formats `_logical_value` 共享这些范围。默认 false 的 `native_fields` 随原生逻辑经 parse_whitelist／normalize／generate／render 重建保存；最小格式衔接须让已保留 native 字面引号和逗号不被重新解释。深层语义遍历和完整进程／DNS／Unicode 输出仍在后续阶段验证，不宣布阶段外修复通过。
- [ ] **Step 4: Run actual GREEN and independent reviews.** 聚焦／完整 unittest、diff check、static 不变；真正 provider 正文和生成正文核验 matcher／params／语义，native 与 ordinary 同文测试用各自入口。原生逻辑标志做六产物与生成依赖回归；逐目标 unsupported skip 不能删除公共 Rule。来源歧义、YAML scalar/native params、共享接口／六产物三项独立复审均通过后进入原深层逻辑阶段，再执行域名、进程、生成器、DNS、最终审查和发布。提交／推送仍须全部阶段完成。
