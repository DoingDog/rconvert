# JSON 规则集与白名单设计

## 目的和边界

以 `origin/main` 的 Python 生成器为基线，将六组规则的来源、用途、生成顺序及白名单配置集中放进仓库根目录的 `rulesets.json`。删除全部 `attach/rule-list.ini`、`attach/del.ini` 及旧 INI 处理逻辑；旧 `del.ini` 条目全部废弃，不迁移。维持 `a1`、`a2`、`a3`、`cdn`、`big-data`、`dirt` 原有的六种 `fin*` 输出位置，共 36 个路径。仅在当前仓库的隔离 worktree 内运行 Python 3.11+ 虚拟环境；生成器不改动 `static/`。

用户已修改的 `static/main/Direct.list` 和 `static/main/NoReject.list` 原样纳入本次提交，并在 `a3` 的白名单来源中引用这两个仓库相对路径；除此之外不编辑 `static/`。更新 CI 的 static 快照，使其验证本次提交后的 static 树，而非旧树。

## 数据流

`rulesets.json` 按生成顺序列出组，每项包含 `name`、`purpose`、`no_resolve`、`sources`、`whitelist`。`no_resolve` 是可复用的 `add`／`strip`／`keep` 配置项：`dirt` 取 `strip`，要移除来源自带的全部 `no-resolve`；其余五组取 `add`，保持自动添加；`keep` 原样保留来源选项。来源和白名单共用 HTTPS URL／仓库相对路径验证、下载缓存和文本读取。配置中的 `a1/fin.txt`、`cdn/fin.txt` 这类路径若来自前面的组，读取本轮内存输出，不依赖磁盘上一次生成结果；引用未完成的组要明确失败。组名及相对路径不得越出 worktree；拒绝非 HTTPS、无效 URL、格式不符的 JSON。配置只包含原 INI 中实际启用的来源。

每组依次解析原规则，保留已支持的 Surge／Quantumult X／Mihomo／AdGuard 来源语法；白名单解析时忽略 QX／Surge 策略字段。白名单仅纳入 DOMAIN、DOMAIN-SUFFIX、DOMAIN-KEYWORD、DOMAIN-WILDCARD，以及 IP-CIDR、IP-CIDR6、SRC-IP-CIDR、SRC-IP、IP-ASN、GEOIP 等 IP 类型；IP-ASN、GEOIP 仅作同类型精确比较，忽略 USER-AGENT、PROCESS 等类型。对源规则，仅当同方向同地址族的 IP 网段或域名匹配集合被某项白名单完全覆盖时才移除；仅有交集不得删较宽规则。无法安全证明覆盖的 wildcard／keyword 组合也保留。源规则自带的 `@@` 不再使较宽的路由规则消失；在 AdGuard DNS 输出中保留来源原有的例外。

先执行上述排除，再按确有匹配范围包含关系的现有去重规则处理；各输出只写该客户端能表达的类型，并按目标的规则行去重。现有实现没有用 wildcard 删除其他类型；新增测试在包含 wildcard 与精确／后缀规则时分别核验 Surge DOMAIN-SET、QX 和 Mihomo 的最终内容，防止以后改变顺序导致丢规则。

## AdGuard DNS 与例外

`fin-adb.txt` 明确以最新版 AdGuard DNS 规则为目标，不承诺与浏览器过滤器精确等价。精确 DOMAIN 写裸域名，DOMAIN-SUFFIX 写 `||domain^`，可安全转换的 keyword／wildcard 写成转义、锚定到域名的 DNS 正则；不安全的匹配形式计入跳过统计，不扩大范围。非 block 组仍写原路径的说明文件。

用户选择额外放行例外：对 block 组的新白名单，除了移除被完全覆盖的拦截规则，还输出语义精确的 AdGuard DNS `@@` 规则。DOMAIN 的例外只匹配精确域名，DOMAIN-SUFFIX 的例外包含子域；支持的 keyword／wildcard 例外也必须匹配同一域名集合。IP 白名单只影响支持 IP 的目标输出，不生成 DNS 例外。对于较窄的白名单与较宽的路由规则，后者留在路由输出；这些路由客户端需自行把显式放行规则置于拦截规则之前。

## 测试与交付

使用标准库 `unittest`，每个行为先新增失败测试并确认 RED，再以最少代码变绿。重点覆盖 JSON 六组与本轮依赖、URL／路径安全、QX／Surge 白名单策略忽略、精确与包含关系及反例、IPv4／IPv6 和地址方向、来源 `@@`、AdGuard DNS 精确与例外、目标格式 wildcard、36 个输出路径、源失败不发布、CI static 快照。先跑完整离线测试，再尝试在当前 worktree 内运行真实来源生成器并检验所有生成路径；若上游不可用，不伪称已刷新远程生成物。提交仅包含本任务文件与用户指定的两处 static 改动，不改主仓库工作区，不推送远端。
