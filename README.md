# rconvert

<a name="rule-counts"></a>

## 规则数量

<!-- RULE_COUNTS_START -->
| 格式 | `cdn` | `a3` | `a4` | `big-data` | `tg` | `proxy` | `dirt` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `fin.txt` | 4791 | 228085 | 226844 | 10580 | 27 | 7059 | 14285 |
| `fin-qx.txt` | 4791 | 228082 | 226844 | 10561 | 27 | 7059 | 56720 |
| `fin.yaml` | 4791 | 228083 | 226843 | 10527 | 27 | 7051 | 56695 |
| `fin-adb.txt` | 0 | 228338 | 227141 | 0 | 0 | 0 | 0 |
| `fin-surge.txt` | 80 | 310 | 121 | 2226 | 13 | 138 | 10104 |
| `fin-surge-ds.txt` | 4711 | 227775 | 226723 | 8354 | 14 | 6921 | 4181 |
<!-- RULE_COUNTS_END -->

使用 Python 3.11+ 标准库将上游规则合并、按匹配范围去重，生成 Surge、Quantumult X、Mihomo 和 AdGuard DNS 规则。构建不会下载或执行外部代码、客户端或二进制程序。`a3` 使用 `static/main/Direct.list` 和 `static/main/NoReject.list` 作为白名单，`dirt` 使用 `static/main/NoDirect.list` 作为白名单。`static/` 可增删条目、重排、添加注释、使用 UTF-8 BOM／CRLF 或新增本地文件；构建读取当轮内容并保持输入不变。

## 下载链接

| 格式 | `cdn` | `a3` | `a4` | `big-data` | `tg` | `proxy` | `dirt` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `fin.txt` 非加速 | [fin.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/cdn/fin.txt) | [fin.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/a3/fin.txt) | [fin.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/a4/fin.txt) | [fin.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/big-data/fin.txt) | [fin.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/tg/fin.txt) | [fin.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/proxy/fin.txt) | [fin.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/dirt/fin.txt) |
| `fin.txt` 加速 | [fin.txt](https://r.awsl.app/cdn/fin.txt) | [fin.txt](https://r.awsl.app/a3/fin.txt) | [fin.txt](https://r.awsl.app/a4/fin.txt) | [fin.txt](https://r.awsl.app/big-data/fin.txt) | [fin.txt](https://r.awsl.app/tg/fin.txt) | [fin.txt](https://r.awsl.app/proxy/fin.txt) | [fin.txt](https://r.awsl.app/dirt/fin.txt) |
| `fin-qx.txt` 非加速 | [fin-qx.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/cdn/fin-qx.txt) | [fin-qx.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/a3/fin-qx.txt) | [fin-qx.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/a4/fin-qx.txt) | [fin-qx.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/big-data/fin-qx.txt) | [fin-qx.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/tg/fin-qx.txt) | [fin-qx.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/proxy/fin-qx.txt) | [fin-qx.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/dirt/fin-qx.txt) |
| `fin-qx.txt` 加速 | [fin-qx.txt](https://r.awsl.app/cdn/fin-qx.txt) | [fin-qx.txt](https://r.awsl.app/a3/fin-qx.txt) | [fin-qx.txt](https://r.awsl.app/a4/fin-qx.txt) | [fin-qx.txt](https://r.awsl.app/big-data/fin-qx.txt) | [fin-qx.txt](https://r.awsl.app/tg/fin-qx.txt) | [fin-qx.txt](https://r.awsl.app/proxy/fin-qx.txt) | [fin-qx.txt](https://r.awsl.app/dirt/fin-qx.txt) |
| `fin.yaml` 非加速 | [fin.yaml](https://raw.githubusercontent.com/DoingDog/rconvert/main/cdn/fin.yaml) | [fin.yaml](https://raw.githubusercontent.com/DoingDog/rconvert/main/a3/fin.yaml) | [fin.yaml](https://raw.githubusercontent.com/DoingDog/rconvert/main/a4/fin.yaml) | [fin.yaml](https://raw.githubusercontent.com/DoingDog/rconvert/main/big-data/fin.yaml) | [fin.yaml](https://raw.githubusercontent.com/DoingDog/rconvert/main/tg/fin.yaml) | [fin.yaml](https://raw.githubusercontent.com/DoingDog/rconvert/main/proxy/fin.yaml) | [fin.yaml](https://raw.githubusercontent.com/DoingDog/rconvert/main/dirt/fin.yaml) |
| `fin.yaml` 加速 | [fin.yaml](https://r.awsl.app/cdn/fin.yaml) | [fin.yaml](https://r.awsl.app/a3/fin.yaml) | [fin.yaml](https://r.awsl.app/a4/fin.yaml) | [fin.yaml](https://r.awsl.app/big-data/fin.yaml) | [fin.yaml](https://r.awsl.app/tg/fin.yaml) | [fin.yaml](https://r.awsl.app/proxy/fin.yaml) | [fin.yaml](https://r.awsl.app/dirt/fin.yaml) |
| `fin-adb.txt` 非加速 | [fin-adb.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/cdn/fin-adb.txt) | [fin-adb.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/a3/fin-adb.txt) | [fin-adb.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/a4/fin-adb.txt) | [fin-adb.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/big-data/fin-adb.txt) | [fin-adb.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/tg/fin-adb.txt) | [fin-adb.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/proxy/fin-adb.txt) | [fin-adb.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/dirt/fin-adb.txt) |
| `fin-adb.txt` 加速 | [fin-adb.txt](https://r.awsl.app/cdn/fin-adb.txt) | [fin-adb.txt](https://r.awsl.app/a3/fin-adb.txt) | [fin-adb.txt](https://r.awsl.app/a4/fin-adb.txt) | [fin-adb.txt](https://r.awsl.app/big-data/fin-adb.txt) | [fin-adb.txt](https://r.awsl.app/tg/fin-adb.txt) | [fin-adb.txt](https://r.awsl.app/proxy/fin-adb.txt) | [fin-adb.txt](https://r.awsl.app/dirt/fin-adb.txt) |
| `fin-surge.txt` 非加速 | [fin-surge.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/cdn/fin-surge.txt) | [fin-surge.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/a3/fin-surge.txt) | [fin-surge.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/a4/fin-surge.txt) | [fin-surge.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/big-data/fin-surge.txt) | [fin-surge.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/tg/fin-surge.txt) | [fin-surge.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/proxy/fin-surge.txt) | [fin-surge.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/dirt/fin-surge.txt) |
| `fin-surge.txt` 加速 | [fin-surge.txt](https://r.awsl.app/cdn/fin-surge.txt) | [fin-surge.txt](https://r.awsl.app/a3/fin-surge.txt) | [fin-surge.txt](https://r.awsl.app/a4/fin-surge.txt) | [fin-surge.txt](https://r.awsl.app/big-data/fin-surge.txt) | [fin-surge.txt](https://r.awsl.app/tg/fin-surge.txt) | [fin-surge.txt](https://r.awsl.app/proxy/fin-surge.txt) | [fin-surge.txt](https://r.awsl.app/dirt/fin-surge.txt) |
| `fin-surge-ds.txt` 非加速 | [fin-surge-ds.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/cdn/fin-surge-ds.txt) | [fin-surge-ds.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/a3/fin-surge-ds.txt) | [fin-surge-ds.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/a4/fin-surge-ds.txt) | [fin-surge-ds.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/big-data/fin-surge-ds.txt) | [fin-surge-ds.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/tg/fin-surge-ds.txt) | [fin-surge-ds.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/proxy/fin-surge-ds.txt) | [fin-surge-ds.txt](https://raw.githubusercontent.com/DoingDog/rconvert/main/dirt/fin-surge-ds.txt) |
| `fin-surge-ds.txt` 加速 | [fin-surge-ds.txt](https://r.awsl.app/cdn/fin-surge-ds.txt) | [fin-surge-ds.txt](https://r.awsl.app/a3/fin-surge-ds.txt) | [fin-surge-ds.txt](https://r.awsl.app/a4/fin-surge-ds.txt) | [fin-surge-ds.txt](https://r.awsl.app/big-data/fin-surge-ds.txt) | [fin-surge-ds.txt](https://r.awsl.app/tg/fin-surge-ds.txt) | [fin-surge-ds.txt](https://r.awsl.app/proxy/fin-surge-ds.txt) | [fin-surge-ds.txt](https://r.awsl.app/dirt/fin-surge-ds.txt) |

七个目录各生成六种文件，共 42 个输出；各格式的行数见 [规则数量](#rule-counts)。`r.awsl.app` 的 Cloudflare 加速链接自动跟踪仓库 `main` 的文件。`cdn` 用于 CDN 分流；`a3` 是包含 Sukka reject 的广告拦截，`a4` 使用 `a3` 原有来源但不含本次新增的两份 Sukka reject；`big-data` 用于大流量服务分流，`tg` 用于 Telegram 分流，`proxy` 用于明确代理域名且应放在 `dirt` 前，`dirt` 用于国内直连。不要把 `cdn`、`big-data`、`tg`、`proxy` 或 `dirt` 当作广告拦截列表。原有的其他加速入口：[static/main/Adb-unblock.list](https://r.awsl.app/static/main/Adb-unblock.list) 和 [static/serv/sharing.list](https://r.awsl.app/static/serv/sharing.list)。

| 文件 | 用法 |
| --- | --- |
| `fin.txt` | 完整、无策略的 Surge RULE-SET。调用方指定 `REJECT`、`DIRECT` 或代理策略。 |
| `fin-qx.txt` | Quantumult X 远程过滤规则，使用 `LIST` 策略占位。订阅时设置有效的 `force-policy`（广告用 `REJECT`、国内直连用 `DIRECT`、分流用代理策略），或自行定义名为 `LIST` 的策略；否则不能直接依赖占位策略。来源中的 `force-cellular`、`multi-interface`、`multi-interface-balance`、`via-interface=pdp_ip0` 不会写入远程文件；对应的域名 matcher 保留三字段，但接口选择不再生效，需接口参数时使用 `[filter_local]`。 |
| `fin.yaml` | Mihomo `rule-providers` 的 `behavior: classical`、`format: yaml` 文件。引用时使用 `RULE-SET,<provider>,<policy>`；这不是已停止维护的旧 Clash 兼容承诺。 |
| `fin-adb.txt` | `purpose` 为 `block` 的组输出 AdGuard DNS 域名拦截和适用的 `@@` 放行例外；其余组只有说明注释。不保证浏览器过滤器的精确等价性。 |
| `fin-surge.txt` | Surge 非 DOMAIN-SET 规则，与 `fin-surge-ds.txt` 配合使用。 |
| `fin-surge-ds.txt` | Surge DOMAIN-SET，精确域名与前导点后缀。使用这对文件时不要再重复加载完整的 `fin.txt`。 |

[AdGuard Private DNS 的自定义列表额度](https://adguard-dns.io/kb/private-dns/setting-up-filtering/blocklists/)按套餐分别为 Personal 1,000、Team 5,000、Enterprise 100,000 条总规则，超额列表会自动停用。上表中 `a3`、`a4` 的 `fin-adb.txt` 各自超过 100,000 条，直接作为 Private DNS 自定义列表添加时会超额；生成文件保留全部可表达规则。

`fin-adb.txt` 的每行上限为 65,536 UTF-8 bytes，计入结尾 LF、例外前缀 `@@`、regex 包装 `/.../` 及标题和其他文件头内容；恰好达到上限的行保留。规则或例外超限只跳过该条 DNS 输出，其他五种格式继续按各自支持范围转换。标题或其他文件头超限抛出 `ValueError`，在发布前终止本轮并保留全部旧产物。

生成的 `fin.yaml` 使用 Mihomo classical 原生规则。普通来源和 Surge 的 `DOMAIN`／`DOMAIN-SUFFIX` 直接保留类型和规范化后的 payload，采用 Mihomo 原生的大小写及末尾根点匹配行为；这两种域名规则不转换成 regex，也不承诺与 Surge 跨来源全域等价。不同来源生成的相同最终规则行只保留一份。真实 `DOMAIN-REGEX` 保留 matcher，必要的 keyword／wildcard 转换继续保留。

重新导入只读取实际文件 bytes，按 Mihomo 原生语义解析已输出的 matcher，普通 YAML 注释被忽略；转换前的 Rule 类型和来源信息不通过文件恢复。raw `DOMAIN-REGEX` 不会反向恢复为 Surge 精确域名或后缀，在 Surge／Quantumult X 按实际类型 unsupported；AdGuard DNS 重新检查完整结构证书。已有 raw paired exact 可保留其 ASCII-only 谓词，含根点敏感 legacy 分支的 raw paired suffix 不输出 DNS。在相同来源格式上下文中，相同 bytes 作为用户输入、同轮生成依赖或非空磁盘依赖时，取得相同的目标支持子集。

Mihomo 独立 classical provider 的 `payload:` 和 `rules:` 列表均使用无策略入口，支持单行 plain、single-quoted 和 double-quoted 标量。外层 YAML 引号负责标量解码；解码后的字段按字面逗号分隔，只裁剪字段边缘的 ASCII space。三个原生 regex 类型和逻辑规则将 type 后的全部字段重连为 matcher，内部引号保留为字面内容。完整 Mihomo 配置导入和多行 YAML 标量不在支持范围内，超出单行子集的输入给出行号 warning。

native provider 的 `GEOIP`／`SRC-GEOIP` 支持 `private`、`telegram`、`cloudflare` 等命名类别及首个 `!` 取反，原 payload 保留在 Mihomo 输出中。这些类别及取反语义要求客户端启用 `geodata-mode: true` 并具有相应 dat 类别；转换器不读取数据库，也不承诺默认 mmdb 模式具有同样语义。普通显式 GEOIP 语法保持原范围；Surge／Quantumult X 仍只接受各自已有的 country／LAN／UNKNOWN 等能力，命名类别或取反叶子使对应目标的整条 logical 跳过。

`DOMAIN-WILDCARD`／`HOST-WILDCARD` 按 pattern 校验，接受 `*`、`*123*`、多点和超过 hostname 长度的安全 pattern。普通 Surge 字段引用保护的字面字符可重新读取，生成的 Surge／Quantumult X 安全文本及 Mihomo YAML 可按实际 bytes 供同轮或磁盘 source／白名单使用。精确域名、后缀、hosts、裸域名和 DOMAIN-SET 保持原有 hostname 校验；wildcard 不写入 DOMAIN-SET。

Mihomo provider 中的 `PROCESS-NAME` 把 `*`、`?` 视为字面字符，普通 Surge 来源的同名规则按 glob 转换；字面进程名含通配符时，Surge 产物只跳过该条规则或所在逻辑规则，并计入跳过统计。普通 `PROCESS-NAME` 的精确字面值保留现有 hex regex 转换；其余原样输出的进程名称、路径及 wildcard matcher，以及最终 raw 域名 matcher 首尾含 ASCII space 时，只跳过 Mihomo 输出或所在完整逻辑规则。内部空格、HTAB 和非 ASCII 空白保留各自已有支持。

Mihomo 的有效非 regex matcher 含字面逗号时，只跳过该目标的完整规则；外层 YAML 引号不提供内部字段转义。`IN-NAME`、`IN-USER`、`REMATCH-NAME` 保留原有 `/` 名称列表及各段 Go TrimSpace 语义，scalar 和 logical 均将 U+001C..U+001F 保留为非空名称。UID／DSCP 先按原有规则将逗号列表转换成 `/`；原生 regex 的重连字段与 logical 的结构尾字段保留。logical 的每个非 regex 叶子必须在所有前缀及结尾保持括号平衡，无法表达时跳过整条目标规则；平衡的字面括号和顶层合法单边括号保持支持。

Quantumult X 字段以字面单／双引号开头，或首尾含会被读取器裁剪的空白时，仅跳过该 QX 投影；这包括 keyword、native wildcard 和 USER-AGENT。USER-AGENT 与 wildcard 的奇数个尾反斜杠、空白后紧接 `#`／`;`／`//`，以及 QX wildcard 读取器无法保持平衡的字面括号，同样按目标 unsupported。内部引号、内部空白、USER-AGENT 偶数尾反斜杠，以及 HOST-KEYWORD 已有字面反斜杠和 marker 读取保持。输出与白名单投影共用判定，不改写 matcher 或放宽生成依赖校验。

Surge／Quantumult X 的最终字段若会被普通读取器判为 HTML markup，或非 regex process、USER-AGENT、DEVICE-NAME 字段含该读取器不接受的角括号，仅跳过对应目标；Surge logical 任一叶子不支持时跳过整条。`DOMAIN-KEYWORD,<123>`、`DOMAIN-WILDCARD,*<123>*`、URL-REGEX 的既有字面字段读取，以及 logical 含 regex 叶子时原有的整行 literal-field 例外保持，native 原格式支持与来源 HTML 检查不变。

Mihomo native 的 `DOMAIN`／`DOMAIN-SUFFIX` 以及 `DOMAIN-KEYWORD,123.`、`DOMAIN-WILDCARD,*.*` 等末尾根点敏感规则无法保真转换到 Surge 时，只跳过对应 Surge 输出，包括 DOMAIN-SET；Mihomo 输出保留这些原生域名 matcher。逻辑规则任一叶子无法表达时，跳过该目标的整条 `AND`／`OR`／`NOT`。case／root 判定针对关闭 sniffer、没有 hosts alias 或提前改写的 VLESS TCP raw FQDN，不能用其他入口会清理 Host 的行为替代。

普通混合来源中的裸 regex 可能同时表示完整 matcher、策略或尾注释。例如 `DOMAIN-REGEX,^a{b$,My Proxy # note}c$|^foo$` 给出 `ambiguous unquoted regex comma or policy` warning，并保留后续合法行。用字段引号明确所需范围：

```plaintext
DOMAIN-REGEX,'^a{b$,My Proxy # note}c$|^foo$'
DOMAIN-REGEX,'^a{b$',My Proxy # note}c$|^foo$
```

第一行保留完整 matcher `^a{b$,My Proxy # note}c$|^foo$`；第二行的 matcher 是 `^a{b$`，策略是 `My Proxy`，`#` 后为尾注释。普通双引号字段中的 `\"` 和 `\\` 分别表示字面双引号和反斜杠，其他 regex escape 保留；单引号字段保留内部反斜杠。Surge 输出需要双引号保护时使用该转义语法，适用于 [Surge 官方注明的 Mac 6.8.0+／iOS 5.21.0+](https://manual.nssurge.com/profile/format.html)。已明确的 `PROXY`、`LIST`、`DIRECT` 和拦截动作尾字段继续按普通来源的兼容语法消费；provider 或无策略逻辑叶子中的同名后缀属于 regex。provider 的外层标量引号与普通 matcher 字段引号作用不同，例如 `- 'DOMAIN-REGEX,"^ads$"'` 的 matcher 包含两端双引号。解码后的控制字符在公共 Rule 中保留，各目标的完整安全输出编码仍有后续验证要求。

最终输出按规则类型连续分组，每种类型内按最终规则行的字符数升序排列，同长按完整文本的字典序排列。所有 IP 类规则放在末尾，顺序为无地址族、IPv4、IPv6；`fin-surge-ds.txt` 的规则体整体排序。`fin-adb.txt` 在文件头之后先列出全部 `@@` 放行例外，再列出普通规则，两区分别按字符数和字典序排列。

格式参考：[Surge 规则文档](https://manual.nssurge.com/rules/domain.html)、[Quantumult X 官方配置样例](https://github.com/crossutility/Quantumult-X/blob/master/sample.conf)、[Mihomo rule-providers 文档](https://wiki.metacubex.one/en/config/rule-providers/content/) 和 [AdGuard DNS 过滤语法](https://adguard-dns.io/kb/general/dns-filtering-syntax/)。

[`rulesets.json`](rulesets.json) 按依赖顺序列出规则组。每组用 `name` 指定输出目录、可选的 `title` 指定 `fin-adb.txt` 文件头标题（省略时使用 `name`）、`purpose` 指定 `block`／`proxy`／`direct`、`sources` 指定规则来源、`whitelist` 指定白名单来源、`no_resolve` 指定 `add`／`strip`／`keep`。ADB 文件头按北京时间写入生成时间，`Total count` 是去重后的规则行数，包含 `@@` 例外。来源与白名单均可使用 HTTPS URL 或选定 root 的相对路径；本轮生成的 `cdn/fin.txt` 会直接供后续组读取。`tg` 和 `proxy` 与 `cdn`、`a3`、`a4`、`big-data` 一样使用 `add`，仅给可表达的目的 IP 规则添加 `no-resolve`；`dirt` 使用 `strip`。来源 IP 规则不被转换为目标 IP。

所有规则组均使用 Sukka 的 [非 IP LAN 白名单](https://ruleset.skk.moe/Clash/non_ip/lan.txt) 和 [IP LAN 白名单](https://ruleset.skk.moe/Clash/ip/lan.txt)；`a4` 与 `a3` 的白名单相同。`tg` 还使用 `static/` 中的 [`tg-sentinel.txt`](static/tg-sentinel.txt)，即使远端 LAN 白名单不可用，也排除上游的非 Telegram 哨兵。

白名单使用域名精确、后缀、keyword、wildcard、`DOMAIN-REGEX` 及适用的 IP 类规则，忽略 USER-AGENT 和 PROCESS 等类型。只删除与白名单精确相同或匹配集合被其完整覆盖的规则：`DOMAIN,safe.example.com` 不会删除 `DOMAIN-SUFFIX,example.com`；`DOMAIN-SUFFIX,example.com` 可以删除 `DOMAIN,ads.example.com`。raw `DOMAIN-REGEX` 保留 matcher 原文完全相同的覆盖；另对已有 raw paired 严格模板保留有限的完整包含关系，不推断任意 regex 等价。raw paired suffix white 不能删除仍匹配 Kelvin sign `K` 的 canonical regex，来源覆盖或单个 Host 命中均不能代替实际目标的完整包含证明。

keyword 包含去重同时保留各目标的字段能力：短项因起始引号、边缘空白、普通 markup 读取限制或 native 末尾根点而不能替代长项时，长项继续保留；正常可证明的包含归约和来源／allow／options 身份分组不变。

过滤分别核查来源匹配范围和各路由目标实际生成的 matcher。来源层保留 Mihomo native 与 QX 未证明等价的 Unicode、大小写、末尾根点及 byte／字符匹配差别；Mihomo 路由层按实际输出的原生域名 matcher 和已证明的覆盖关系过滤。其他转换只使用匹配范围不变或属于原白名单已证明子集的目标投影。输入中的 allow 规则按 `no_resolve` 处理及移除受支持接口参数后的实际 matcher 参与路由白名单，外部白名单仍遵守原 options 限制。

对于 `purpose: block`，`fin-adb.txt` 还输出白名单及可表达的 allow 规则的 `@@` 放行例外，普通 Surge 精确域名采用 `@@|safe.example.com|`；路由目标覆盖过滤保留合法的 DNS 拦截与例外。DNS 的 block、allow 和外部白名单使用相同的 case／root 安全判定：native exact／suffix 不输出 DNS，keyword／wildcard 只保留已证明可表达的子集，native `*` 仍支持。所有 raw `DOMAIN-REGEX` 均须取得完整结构证书，未知子结构或不可恢复的大小写／根点区别只计该目标 unsupported。来源字符类中的 `\-` 被用于当前 range 归约的起点或终点时，仅跳过该 DNS 投影，block、allow 和外部白名单共用此判定；独立字面 hyphen、已支持的普通范围及数值 `\x{2D}` 保持原有语义。

普通 wildcard 的 DNS 投影支持已证明的 ASCII 字母、数字、underscore、hyphen、点、`*`／`?` 和 Surge 字符类，不要求含点；例如 `*ads*`、`*`、`a?` 分别输出 `/^.*ads.*$/`、`/^.*$/`、`/^a.$/`。普通来源的引号、括号、反斜杠、非 ASCII 等未证明 literal 只跳过 DNS 并计数，其他可表达目标继续输出；block、allow 和外部白名单使用相同判定。native wildcard 保留现有 byte／presentation、case／root 和 bracket 支持边界。

DNS 证明范围为普通 UDP、单个 A/IN question 的过滤链；目标编码处理 presentation bytes，并使用固定 Go Unicode 15.0.0 的来源 rune 集合，不把 Python 的 Unicode 版本当作来源真值。该范围不承诺未知闭源 Unicode／IDNA 或 Quantumult X 全域等价。本次核验依据固定源码及 Python 公开转换／发布测试，未运行客户端。Surge、Quantumult X 与 Mihomo 输出不能表达部分放行，需在规则集之前放置显式放行规则。去重仅在能证明覆盖时删除规则，不能因 wildcard 不受目标格式支持就用它删除其他类型。

## 本地构建

在仓库目录运行：

```sh
python3 -m venv .venv
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python generate.py
.venv/bin/python update_readme_counts.py
```

`generate.py` 默认以脚本所在目录为 root，也可用 `generate.py --root /path/to/project` 选择包含 `rulesets.json` 的独立项目目录。来源与白名单的本地路径以该 root 为边界，六种生成文件写入该目录下的规则组目录，发布暂存文件位于该目录的 `.tmp/`，该目录的 `static/` 保持不变。

Windows 将 `.venv/bin/python` 换成 `.venv/Scripts/python.exe`。来源及白名单均在 `rulesets.json` 中配置，不再使用 INI。远端普通来源或白名单返回 404 时跳过该 URL 并继续；远端白名单整份为 HTML、坏编码或无法识别时跳过，混合内容保留可识别行。429、服务器错误、超时或传输不完整会停止本轮发布。

来源可用时，规则经来源白名单过滤全部删除，或剩余非 allow 规范规则至少有一条、每条均有有效路由投影且全部有效投影均被白名单覆盖，都可正常更新六种产物，允许路由正文为空；仅含可发布的 AdGuard DNS `@@` 或仅依赖本轮空生成文件的清空也继续发布。生产 `big-data` 读取声明的 `cdn/fin.txt`；父组 native exact／suffix 可使 `fin.yaml` 非空而 `fin.txt` 合法为空，下游不从其他格式补回规则。同轮空生成文件可作来源或白名单；移除父组配置后的 disk-only 本地空来源或空白名单仍按严格输入校验拒绝。无可路由规则时，混入完全 unsupported 规则或普通来源不可用仍冻结该组及依赖组原有六种产物，其他健康组继续更新；已有可路由规则时，部分普通来源不可用仍按现有行为发布。冻结时缺失旧产物，或本地白名单损坏，会停止本轮发布。

日志包含来源行号与转换诊断。`<file>:<kind>` 表示该目标 unsupported；`<file>:<kind>:whitelist-covered` 表示目标 matcher 被白名单覆盖后的合法删除；`whitelist-covered:<kind>` 仅在一条规范规则至少有一个有效路由投影且全部有效路由投影均被覆盖时计一次，完全 unsupported 的规则不计完整覆盖。`fin-qx.txt:<kind>:interface-option` 只统计实际输出且移除了接口参数的 QX 规则。公开 `render` 返回 `(outputs, diagnostics)`，诊断仍为计数字典。

GitHub Actions 的 PR job 以只读权限运行离线测试；向 `main` 推送后先测试同一事件 SHA，再由 `update.py` 生成并发布，定时更新每天北京时间 00:00 执行，定时和手动更新仅在 `main` 分支运行。入口在生成前和提交前读取远端 `main`；事件 SHA 已被替代时记录 `superseded` 并跳过旧运行，推送窗口中明确的非快进或引用旧值竞争也须成功复核远端后才能跳过。`superseded` 不表示新 SHA 已测试或发布。发布仅暂存配置所列规则组的六种生成文件和 `README.md`，不强推；读取失败、权限、网络、服务端策略拒绝及无法确认的推送错误继续报错。

## 上游与许可

上游的完整 URL 清单见 [rulesets.json](rulesets.json)。`a3` 使用 [AdRules](https://github.com/Cats-Team/AdRules)、[anti-AD](https://github.com/privacy-protection-tools/anti-AD)、[AWAvenue](https://github.com/TG-Twilight/AWAvenue-Ads-Rule) 及 [fmz200/wool_scripts](https://github.com/fmz200/wool_scripts) 中标注作者奶思的 Quantumult X 广告列表；国内直连还使用 [Sukka Ruleset](https://ruleset.skk.moe/)、[gaoyifan/china-operator-ip](https://github.com/gaoyifan/china-operator-ip) 与 [Loyalsoldier/surge-rules](https://github.com/Loyalsoldier/surge-rules)。Sukka 新增的 [IPv4 列表](https://ruleset.skk.moe/Clash/ip/china_ip.txt) 文件头标示 CC BY-SA 2.0；其 IPv6 候选经网段覆盖核对全部重复，未另加。其他来源、作者声明和具体许可请按上述清单访问原仓库。聚合过程仅提取可适配的规则、规范化、白名单过滤、去重和转换格式，不包含上游构建代码。

本仓库的 `LICENSE` 只说明本仓库原创代码的许可，不将聚合后的上游规则重新许可为 WTFPL。上游可能有 GPL、AGPL、MIT 或其他不同许可与署名要求；使用和再分发时分别遵守原作者的声明。[AWAvenue 当前 GitHub 仓库](https://github.com/TG-Twilight/AWAvenue-Ads-Rule/blob/main/LICENSE) 标示 GPL-3.0，其旧网站的许可文字与当前仓库不一致，以实际使用的来源及其当前声明为准。[fmz200/wool_scripts 的 LICENSE](https://github.com/fmz200/wool_scripts/blob/main/LICENSE) 为 GPL-3.0；该仓库说明其中部分内容收集自其他开源项目，原作者声明仍需分别遵守。
