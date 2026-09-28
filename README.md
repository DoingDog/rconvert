# rconvert

使用 Python 3.11+ 标准库将上游规则合并、按匹配范围去重，生成 Surge、Quantumult X、Mihomo 和 AdGuard DNS 规则。构建不会下载或执行外部代码、客户端或二进制程序。`a3` 使用 `static/main/Direct.list` 和 `static/main/NoReject.list` 作为白名单，`dirt` 使用 `static/main/NoDirect.list` 作为白名单；构建不修改 `static/`。

## 规则集

| 目录 | 用途 | 完整 Surge RULE-SET | Cloudflare 加速 |
| --- | --- | --- | --- |
| `cdn` | CDN 分流 | [cdn/fin.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/cdn/fin.txt) | [cdn/fin.txt 加速](https://r.awsl.app/cdn/fin.txt) |
| `a3` | AdRules、AntiAD、AWAvenue 完整版及 fmz200 广告拦截 | [a3/fin.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/a3/fin.txt) | [a3/fin.txt 加速](https://r.awsl.app/a3/fin.txt) |
| `big-data` | 大流量服务分流，包含 `cdn` | [big-data/fin.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/big-data/fin.txt) | [big-data/fin.txt 加速](https://r.awsl.app/big-data/fin.txt) |
| `dirt` | 国内直连，含 Sukka 和中国 IPv4／IPv6 网段 | [dirt/fin.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/dirt/fin.txt) | [dirt/fin.txt 加速](https://r.awsl.app/dirt/fin.txt) |

`r.awsl.app` 的 Cloudflare 加速链接自动跟踪仓库 `main` 的文件。四个目录各生成以下六种文件，共 24 个输出；将上表任一链接的 `fin.txt` 替换为相应文件名即可使用。原有的其他加速入口：[static/main/Adb-unblock.list](https://r.awsl.app/static/main/Adb-unblock.list) 和 [static/serv/sharing.list](https://r.awsl.app/static/serv/sharing.list)。不要把 `cdn`、`big-data` 或 `dirt` 当作广告拦截列表。

| 文件 | 用法 |
| --- | --- |
| `fin.txt` | 完整、无策略的 Surge RULE-SET。调用方指定 `REJECT`、`DIRECT` 或代理策略。 |
| `fin-qx.txt` | Quantumult X 远程过滤规则，使用 `LIST` 策略占位。订阅时设置有效的 `force-policy`（广告用 `REJECT`、国内直连用 `DIRECT`、分流用代理策略），或自行定义名为 `LIST` 的策略；否则不能直接依赖占位策略。 |
| `fin.yaml` | Mihomo `rule-providers` 的 `behavior: classical`、`format: yaml` 文件。引用时使用 `RULE-SET,<provider>,<policy>`；这不是已停止维护的旧 Clash 兼容承诺。 |
| `fin-adb.txt` | `purpose` 为 `block` 的组输出 AdGuard DNS 域名拦截和适用的 `@@` 放行例外；其余组只有说明注释。不保证浏览器过滤器的精确等价性。 |
| `fin-surge.txt` | Surge 非 DOMAIN-SET 规则，与 `fin-surge-ds.txt` 配合使用。 |
| `fin-surge-ds.txt` | Surge DOMAIN-SET，精确域名与前导点后缀。使用这对文件时不要再重复加载完整的 `fin.txt`。 |

格式参考：[Surge 规则文档](https://manual.nssurge.com/rules/domain.html)、[Quantumult X 官方配置样例](https://github.com/crossutility/Quantumult-X/blob/master/sample.conf)、[Mihomo rule-providers 文档](https://wiki.metacubex.one/en/config/rule-providers/content/) 和 [AdGuard DNS 过滤语法](https://adguard-dns.io/kb/general/dns-filtering-syntax/)。

[`rulesets.json`](rulesets.json) 按依赖顺序列出规则组。每组用 `name` 指定输出目录、`purpose` 指定 `block`／`proxy`／`direct`、`sources` 指定规则来源、`whitelist` 指定白名单来源、`no_resolve` 指定 `add`／`strip`／`keep`。来源与白名单均可使用 HTTPS URL 或仓库相对路径；本轮生成的 `cdn/fin.txt` 会直接供后续组读取。当前三组使用 `add`，`dirt` 使用 `strip`，从所有支持的规则中移除 `no-resolve`。来源 IP 规则不被转换为目标 IP。

白名单只使用域名精确、后缀、keyword、wildcard 及适用的 IP 类规则，忽略 USER-AGENT 和 PROCESS 等类型。只删除与白名单精确相同或匹配集合被其完整覆盖的规则：`DOMAIN,safe.example.com` 不会删除 `DOMAIN-SUFFIX,example.com`；`DOMAIN-SUFFIX,example.com` 可以删除 `DOMAIN,ads.example.com`。对于 `purpose: block`，`fin-adb.txt` 还输出白名单的 `@@` 放行例外，精确域名采用 `@@|safe.example.com|`；Surge、Quantumult X 与 Mihomo 输出不能表达部分放行，需在规则集之前放置显式放行规则。去重仅在能证明覆盖时删除规则，不能因 wildcard 不受目标格式支持就用它删除其他类型。

## 本地构建

在仓库的隔离 worktree 内运行，Python 虚拟环境及临时目录均留在该 worktree：

```sh
python3 -m venv .venv
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python generate.py
```

Windows 将 `.venv/bin/python` 换成 `.venv/Scripts/python.exe`。来源及白名单均在 `rulesets.json` 中配置，不再使用 INI。下载或校验失败会停止构建，不发布部分生成文件；日志包含来源行号与目标格式的跳过计数。GitHub Actions 的 PR job 只运行离线测试；定时更新每天北京时间 00:00 执行，定时和手动更新仅在 `main` 分支运行，仅暂存配置所列规则组的六种生成文件，不强推。

## 上游与许可

上游的完整 URL 清单见 [rulesets.json](rulesets.json)。`a3` 使用 [AdRules](https://github.com/Cats-Team/AdRules)、[anti-AD](https://github.com/privacy-protection-tools/anti-AD)、[AWAvenue](https://github.com/TG-Twilight/AWAvenue-Ads-Rule) 及 [fmz200/wool_scripts](https://github.com/fmz200/wool_scripts) 中标注作者奶思的 Quantumult X 广告列表；国内直连还使用 [Sukka Ruleset](https://ruleset.skk.moe/)、[gaoyifan/china-operator-ip](https://github.com/gaoyifan/china-operator-ip) 与 [Loyalsoldier/surge-rules](https://github.com/Loyalsoldier/surge-rules)。Sukka 新增的 [IPv4 列表](https://ruleset.skk.moe/Clash/ip/china_ip.txt) 文件头标示 CC BY-SA 2.0；其 IPv6 候选经网段覆盖核对全部重复，未另加。其他来源、作者声明和具体许可请按上述清单访问原仓库。聚合过程仅提取可适配的规则、规范化、白名单过滤、去重和转换格式，不包含上游构建代码。

本仓库的 `LICENSE` 只说明本仓库原创代码的许可，不将聚合后的上游规则重新许可为 WTFPL。上游可能有 GPL、AGPL、MIT 或其他不同许可与署名要求；使用和再分发时分别遵守原作者的声明。[AWAvenue 当前 GitHub 仓库](https://github.com/TG-Twilight/AWAvenue-Ads-Rule/blob/main/LICENSE) 标示 GPL-3.0，其旧网站的许可文字与当前仓库不一致，以实际使用的来源及其当前声明为准。[fmz200/wool_scripts 的 LICENSE](https://github.com/fmz200/wool_scripts/blob/main/LICENSE) 为 GPL-3.0；该仓库说明其中部分内容收集自其他开源项目，原作者声明仍需分别遵守。
