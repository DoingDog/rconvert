# 原生规则生成器设计

## 目标和不可变约束

使用 Python 3.11+ 标准库替换 `r.cmd`，不下载或执行外部程序与构建脚本。五个现有目录 `a1`、`a2`、`big-data`、`cdn`、`dirt` 的六个 `fin*` 路径保持不变；新增 `a3` 的同名六个文件。`static/` 的 18 个受版本控制文件及路径、内容均不修改。运行、测试、暂存文件和虚拟环境全部位于仓库 worktree 内。最终 GitHub Actions 使用 Linux，正常提交并推送，不改写历史。

`a3` 的输入严格限于 AdRules `qx.conf`、AntiAD `anti-ad-surge.txt`、AWAvenue 完整 Quantumult X 列表。`dirt` 保留国内直连用途，只补充来源明确、能够证明独立增量的定向规则，不把约 11 万条的 `china-list` 或 `ChinaMax` 全表叠加到现有列表。删去已经核实的五个 404 源，停用已失效域名和会返回登录页的规则源；替换时不能把服务分流列表当作广告列表。参考仓库只作为语法和算法资料，不复制 SukkaW/Surge 的 AGPL 代码。

## 输入与规则语义

`attach/rule-list.ini` 每行是 HTTPS 文本来源或仓库内相对路径；相对路径中的反斜杠在 Linux 上也能解析，但不得越出仓库。`a1` 读取本次生成的 `a2/fin.txt`，`big-data` 读取本次生成的 `cdn/fin.txt`；每个远端 URL 在同次构建中至多下载一次。按行辨认 Surge、Quantumult X、受限的 Mihomo classical YAML、Surge DOMAIN-SET、hosts 和无条件 AdBlock 域名规则。来源的动作字段只在与目标组用途相符时去掉，不能把 `DIRECT` 或放行规则当作广告拦截。拒绝 HTML、错误正文、非法域名或 CIDR，记录来源、行号和未适配类型的数量；不能按整份文件的某一行推断全部格式。

内部规则保留原有类型、值及适用的 `no-resolve` 等选项。所有客户端均先应用 `del.ini` 和可识别的上游放行域名，然后再进行覆盖去重。排除条目支持域名本身及任意层级的子域名，比较完整 DNS 标签而非任意子串；仅精确排除可以显式写 `DOMAIN,example.com`。旧式 `,example.com` 和裸 `example.com` 兼容域名树排除，非域名裸词只按完整规则值或 `DOMAIN-KEYWORD` 值匹配。覆盖该例外的更宽后缀或 wildcard 不能留在无法表达负规则的输出中；宁可舍弃冲突的宽规则并报告，也不扩大拦截范围。

相同类型及参数的规则精确去重；`DOMAIN-SUFFIX,example.com` 确定性覆盖 `DOMAIN,example.com`、其子域精确规则和较窄后缀。只有能证明整个 wildcard 匹配集合都被后缀覆盖时，才移除该 wildcard；通配符不能一律改写为后缀。`DOMAIN-KEYWORD` 的包含关系仅在确实成立时去重。CIDR 使用 `ipaddress.collapse_addresses`，按地址族、方向和参数分别合并包含及相邻网段，不跨 `no-resolve`、来源 IP 和目标 IP 混合。排序与 UTF-8 LF 输出确定，内容相同的再次构建不改变文件字节。

## 输出能力

- `fin.txt`：无策略的 Surge RULE-SET，保留所有已确认适配的来源类型，包括 `DOMAIN-WILDCARD`、`SRC-IP`、`SRC-PORT`、`DEST-PORT`、`PROCESS-NAME`、`USER-AGENT`、CIDR、`IP-ASN`、`GEOIP`。目标不支持的类型只在对应目标跳过。
- `fin-qx.txt`：Quantumult X 远程过滤规则，用 `HOST*`、`IP6-CIDR` 等官方类型名称转换；保留现有 `LIST` 策略占位并在 README 明确要求调用方设置有效的 `force-policy` 或同名策略。未经官方确认的类型不猜名称。
- `fin.yaml`：Mihomo `behavior: classical, format: yaml` 的 `payload:`，不包含策略；保留 Mihomo 支持的来源类型，包括 `SRC-IP-CIDR`（IPv4/IPv6）、`SRC-PORT`、`DST-PORT`、`PROCESS-NAME`、`PROCESS-PATH`、`IP-ASN`、`GEOIP`、`NETWORK`、`IN-TYPE`、`DOMAIN-REGEX` 及有正确括号的 `AND/OR/NOT`。不把 `RULE-SET`、`SUB-RULE` 或 `MATCH` 填入 classical provider；不声称兼容已停止维护的旧 Clash。
- `fin-surge.txt` 与 `fin-surge-ds.txt`：分别承载不适于 DOMAIN-SET 的规则和精确域名／前导点后缀，作为配套文件；完整无策略 RULE-SET 仍在 `fin.txt`。任意 wildcard 不写入纯域名 DOMAIN-SET。
- `fin-adb.txt`：仅 `a1`、`a2`、`a3` 输出 AdGuard DNS 与浏览器共同支持、不会改变原始匹配范围的拦截／放行规则；无等价 DNS 表达式的 CIDR、进程、条件 URL 和精确域名不强行拓宽。`cdn`、`big-data`、`dirt` 保留文件路径，仅写说明注释，不生成拦截国内直连或 CDN 的规则。

每组输出均带实际规则数，不写当前时间。对一个目标格式不能表达的来源类型，应在生成日志报告原因和数量，而不是从公共中间结果删除。测试依照官方 Surge、Quantumult X、Mihomo、AdGuard 文档核验输出语法，不下载客户端可执行文件。

## 错误、安全和发布

HTTPS 请求校验证书、限制超时与响应大小、拒绝跳转到非 HTTPS，并校验规则文本；网络失败、404、登录页、空或失真的必需源使本次构建失败，旧输出在下载和验证失败时保持不变。先在 worktree 内完成全部组的渲染和验证，再使用同一文件系统上的临时文件替换目标；普通 Git commit 保证远端整批文件同时可见。本地多文件 `os.replace` 不承诺断电时的事务原子性。

CI 在 `ubuntu-latest` 创建 `.venv`，先运行 `unittest` 的离线测试，再生成全部 36 个文件，检查 `static` 无差异，只暂存受控输出和必要源码，变化存在时才正常提交、推送。移除下载外部可执行文件的旧入口、强推历史及无关清理工作流。仓库 `LICENSE` 只适用于本仓库原创代码，不宣称聚合规则统一采用 WTFPL；文档列出上游链接、已知 GPL／AGPL／MIT 及 AWAvenue 官网旧协议和当前 GitHub 许可证不一致的情况。

## 可验证结果

测试从公开入口验证规则文本到六种输出，以及固定本地来源到 36 个预期路径；覆盖混合格式、HTML 伪装、失败不覆盖、源依赖、白名单、精确与子域排除、wildcard、来源和目标 CIDR、端口、进程及目标格式类型矩阵。每个行为先写失败测试，再写最小实现。离线大样本与真实网络构建分别测量耗时，不能拿旧 README 的不同环境数字冒充可比基线。完工前核对 `git diff -- static` 为空、路径集合完整、重复生成字节相同及 Linux workflow 语法，并在隔离分支提交。