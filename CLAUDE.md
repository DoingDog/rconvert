# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 开发命令

使用 Python 3.11+ 标准库，无第三方 Python 依赖。测试还需要 PATH 中的 Git；构建不下载或执行客户端、外部代码或二进制程序。仓库没有配置 lint／formatter 工具。

在仓库根目录运行。以下使用 Windows 虚拟环境路径；Linux／macOS 将 `.venv/Scripts/python.exe` 换成 `.venv/bin/python`。

```sh
python3 -m venv .venv
# 全套离线测试，与 CI 相同
.venv/Scripts/python.exe -m unittest discover -s tests -v
# 单文件
.venv/Scripts/python.exe -m unittest discover -s tests -p test_sources.py -v
# 单个测试
.venv/Scripts/python.exe -m unittest tests.test_sources.SourcesTests.test_loads_ordered_json_groups_and_resolves_sources_from_root -v
# 构建入口参数
.venv/Scripts/python.exe generate.py --help
```

生成配置中的全部规则并更新 README 数量表：

```sh
.venv/Scripts/python.exe generate.py
.venv/Scripts/python.exe update_readme_counts.py
```

`generate.py` 默认 root 为脚本目录，会请求配置中的 HTTPS 上游并替换生成文件；`--root /path/to/project` 可选择包含 `rulesets.json` 和本地输入的独立目录。`update_readme_counts.py` 始终处理脚本目录，只改 `RULE_COUNTS_START`／`RULE_COUNTS_END` 之间的表格。

## 数据流与规则语义

- `rulesets.json` 是按依赖顺序排列的规则组配置，`sources.py` 校验配置并将本地路径限制在选定 root 内。`purpose` 为 `block`／`proxy`／`direct`，`no_resolve` 为 `add`／`strip`／`keep`。当前 `big-data` 读取前置 `cdn/fin.txt`；依赖文件必须先生成，同轮读取内存中的实际输出文本并重新解析，不从其他格式补充规则。
- `generate.generate(root, fetch)` 编排读取、解析、来源白名单过滤、`no_resolve` 处理、规范化和多目标渲染，返回待发布的路径与文本；`publish` 才写文件。HTTPS 内容按 URL 在当轮缓存，本地 `static/` 始终作为输入读取并保持不变。
- `rules.py` 把混合规则、hosts、裸域名／CIDR、DOMAIN-SET 和支持的单行 Mihomo provider 解析为不可变 `Rule`，并返回行号诊断。`Rule` 除 `kind`／`value` 外还保留 `options`、`allow`、`literal_process`、`native_fields` 和 `domain_source`。相同类型与文本可能因 Surge、QX、Mihomo 的来源语义产生不同匹配范围；域名大小写、末尾根点、字符／byte 匹配和进程字面值不能丢失这些区别。相关 Unicode 语义使用 `_unicode15.py` 的固定 Go Unicode 15.0.0 数据。
- `normalize` 在来源、allow、options 等身份分组内去重、归约域名覆盖并合并 CIDR。`exclude_covered` 只删除被白名单完整覆盖的规则，CIDR 按同方向、同实际地址族的完整并集判定，部分覆盖保留整条。`formats.render` 还会按各目标实际生成的 matcher 再做白名单过滤，来源层的一次过滤不足以决定所有输出。
- `formats.render` 返回 `(outputs, diagnostics)`，按目标能力分别转换与统计 unsupported；逻辑规则任一叶子不可表达时跳过该目标整条规则，其他目标继续处理。Mihomo 原生 `DOMAIN`／`DOMAIN-SUFFIX` 直接保留原生 matcher；写出后重新读取只依据实际 bytes 和输入格式，注释不恢复转换前的 `Rule` 来源信息。

每组的六个输出由 `formats.FILES` 统一定义：`fin.txt` 是完整无策略 Surge RULE-SET；`fin-surge.txt` 与 `fin-surge-ds.txt` 是拆分后的规则和 DOMAIN-SET，配对使用时不重复加载 `fin.txt`；`fin-qx.txt` 使用 `LIST` 策略占位；`fin.yaml` 是 Mihomo classical provider；`fin-adb.txt` 只为 `purpose: block` 输出 DNS 拦截和可表达的 `@@` 例外。路由格式无法表达的部分放行需由调用方在规则集前配置显式放行规则。各格式的详细支持边界和诊断含义见 `README.md`。

## 白名单与发布边界

- 上游及白名单均在 `rulesets.json` 配置。当前 `a3`／`a4` 使用 `static/main/Direct.list` 与 `static/main/NoReject.list`，`dirt` 使用 `static/main/NoDirect.list`；所有组另用 LAN 白名单，`tg` 另用 `static/tg-sentinel.txt`。`a3`／`a4` 是广告组，其余组用于分流。`no_resolve` 只处理支持的目的 IP 规则，来源 IP 不改成目的 IP。
- 远端 404 跳过；429、服务器错误、超时和传输不完整终止本轮。远端白名单无可识别内容时跳过，本地白名单损坏会报错。无可路由规则且不满足合法清空条件的组保留旧六文件，并冻结依赖组；缺少完整旧产物时失败。白名单完整覆盖导致的清空、同轮空生成依赖可合法发布，disk-only 空输入仍受严格校验。
- `publish` 在 root 的 `.tmp/` 暂存所有产物和备份，再逐文件替换；替换失败恢复已替换的旧文件。生成异常发生在发布之前，`static/` 不作为输出目标。README 计数更新是独立步骤。
- `update.py` 是有 Git 提交与推送副作用的 CI 入口，要求 `GITHUB_SHA` 等于本地 HEAD；生成前和提交前核查远端 `main`，旧事件返回 `superseded`。仅暂存配置组的六种生成文件及 `README.md`，拒绝已有暂存改动和发布路径改动，不强推。
- `.github/workflows/main.yml` 在 PR／`main` push 运行离线测试；PR 只读，`main` push 测试成功后发布。定时和手动事件仅在 `main` 发布，跳过测试；定时为北京时间每日 00:00。测试与发布 checkout 同一事件 SHA。

`tests/` 同时覆盖解析、六种输出的实际文本、同轮／磁盘依赖、失败时旧产物保留及临时 Git 仓库中的发布行为；测试通过注入 `fetch` 或 mock 隔离远端上游。修改解析或投影时，关联查看 `tests/test_rules.py`、`tests/test_formats.py` 和 `tests/test_generate.py`；发布行为由 `tests/test_ci_publication.py` 覆盖。上游聚合规则的许可与署名按 `README.md` 中的来源声明分别处理，仓库代码的 `LICENSE` 不替代上游许可。
