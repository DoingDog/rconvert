# 六种规则产物的无损转换修复设计

## 目标与边界

修复已复现的静默漏转和匹配方向错误。输入经过 `rules.parse`、白名单处理、`normalize` 和 `formats.render` 后，目标客户端支持的匹配条件必须保留原有范围；目标不支持的条件只在该目标跳过并计数，不从公共规则集删除。`FILES` 的六种产物均纳入回归：`fin.txt`、`fin-qx.txt`、`fin.yaml`、`fin-adb.txt`、`fin-surge.txt`、`fin-surge-ds.txt`。现有 277 项测试是修改前基线。

沿用 Python 3.11+ 标准库和现有 `Rule`、`parse`、`render` 入口，不新增构建依赖，不修改 `static/`。仅更改已有解析、转换、构建和相关测试。`fin-surge.txt` 与 `fin-surge-ds.txt` 配合使用；域名集合文件不承载进程、IP 或逻辑表达式。DNS 文件只承载域名匹配及放行例外。

## 输入解析

- 小写 `src` 是 Mihomo 目的 IP 匹配器的来源方向参数；经真实 Mihomo 加载验证，大写 `SRC` 可以是策略名，不能因大小写归一化而将目标 IP 匹配器变成来源 IP。`IP-CIDR`／`IP-CIDR6`、`IP-SUFFIX`、`GEOIP`、`IP-ASN` 带 `src` 时转为相应 `SRC-*` 内部类型。任何目标不支持相应来源匹配时只跳过该目标，不能写成目的 IP 条件。独立 YAML provider 文件的 `payload:`／`rules:` 两种标题均使用无策略字段语法；普通有策略规则行及完整配置中的顶层 `rules:` 使用相应有策略入口。选项按消费入口验证，不能仅根据标题推断。普通行中单独第三字段小写 `src` 无法唯一确认来源意图时给出行号 warning，不猜测方向。
- `IP-SUFFIX` 的 `no-resolve` 是 Mihomo 支持的目标 IP 选项；Surge、Quantumult X 不因其支持 Mihomo 就接收到不支持的匹配器。`Rule.options` 去重继续有效；`keep` 下同一 matcher 的有、无 `no-resolve` 两种来源规则不擅自合并。
- 已知 QX 接口参数不能让 `HOST-SUFFIX` 等匹配器在解析阶段整条消失，包括官方示例的 `via-interface=pdp_ip0` 和历史配置的 `via-interface=en1`。官方远程文件仅有三字段直接示例，远程四字段参数是否有效尚未获得客户端证据。因此远程产物保留三字段 matcher 和 `LIST`，对未保留的接口参数记录明确的转换限制；不声称特殊出站接口仍然生效。确需接口参数的调用方可在 `[filter_local]` 使用官方示例。
- 逻辑子条件的合法空白、引号、逗号、端口比较／多端口不能在解析成功后丢失。复用现有字段解析器和顶层端口规范化，使 `AND`／`OR`／`NOT` 的子条件可递归验证和转换；不改变子规则顺序或把不支持的子条件删掉后输出残缺逻辑规则。
- HTML 错误页继续拒绝；正则中的 `(?<name>...)` 或字面 `<!doctype` 不能被误判成整份 HTML。Mihomo 的 `DOMAIN-REGEX` 与进程正则使用 `regexp2`，不以 Python `re.compile` 作为唯一有效性标准；已验证有效的 `\z`、命名组、反向引用、字面 `{` 与注释组不能被误拒，无效转义和过大量词不得使解析挂起或崩溃。`(?P<name>...)` 在现有 Mihomo v1.19.31 实测不支持，不据 Go 标准库语法强行保留。YAML `payload:` 的 plain、单引号和双引号标量须按来源语法识别注释与转义；不能把 Surge 的 `;`／`//` 行内注释规则套到 YAML plain 标量，也不能把单引号中的反斜杠当作转义。本项目 YAML 来源按独立 classical provider 规则文件解释，支持 `payload:`／`rules:` alias；完整客户端配置用于实际验证，不新增完整配置导入功能。provider 的 `PROCESS-NAME-REGEX,^Game,REJECT` 保留 `^Game,REJECT`，各逗号段边缘仅裁剪 ASCII space；完整配置顶层的相同规则将 `REJECT` 解释为策略。普通 provider 第二段为 payload，后续 params 按具体匹配器消费，IP 选项须保留方向与解析行为。整条 YAML 标量解码后，matcher 内层引号和反斜杠都是字面内容，不保护普通字段逗号，也不能再按 Surge 字段引号删除。double-quoted 标量按已核查客户端的固定 escape 集合解码，拒绝非法 Unicode 与不完整 escape。转义得到的 tab、控制字符和 Unicode 分隔字符在适用 matcher 中完整保留，Mihomo YAML 输出须安全转义，其他目标无法保真时分别跳过并计数。真实 HTML 文件即使带 UTF-8 BOM 也不得导入其中夹带的规则。

- 普通混合文本的正则字段若同时可解释为完整无策略 matcher，以及 matcher、任意自定义策略和尾注释，必须给出行号 ambiguity warning 并保留后续合法行。`purpose`、局部 `$`／`\z`、字面花括号配对、注释正文或候选能否编译不能提供缺失的来源信息。普通字段引号明确 matcher 范围，独立 provider 与逻辑叶子明确无策略范围；这些入口中的合法 matcher 完整保留，非法完整 matcher 完整拒绝。普通 PROXY／LIST／DIRECT 和已有 block action 的明确尾字段保留兼容语法，不能将这一约定套到 provider 或逻辑叶子。原本依赖裸字段猜测的测试同时覆盖准确 ambiguity warning 和引用后的完整 matcher，不删除保护类别。
- 来源范围先于 matcher 词法扫描确定。provider 标量解码后的字段使用其 native split/rejoin，普通来源使用字段引号与明确策略语法；无策略条件和条件列表只消费已经隔离的范围。`_fields` 不依据来源尾文本选择策略，也不允许策略或注释正文反向参与 matcher 状态。原生 provider 的逻辑字段语义使用默认值为 false 的 `Rule.native_fields` 保存，普通来源维持默认；该标志经白名单、normalize、所有 Rule 重建和生成依赖保留，在逻辑字段的 native／普通解释不同处消费。公共入口名称及原有调用保持兼容，不增加用户来源配置、完整配置导入或通用 parser 框架。

## 六种输出的转换

- Surge 完整 RULE-SET 和非 DOMAIN-SET 规则分别保留可表达的 `PROCESS-PATH-WILDCARD`、逻辑内 `NETWORK -> PROTOCOL`、进程别名及有引号的逗号值；URL 正则的逗号按 Surge 文档加引号。Mihomo classical 逻辑内先转换 `DEST-PORT -> DST-PORT`、`SRC-IP -> SRC-IP-CIDR`、`PROTOCOL(TCP/UDP) -> NETWORK`，再校验目标类型。
- Surge 字符类 wildcard 如 `api-[0-9].example.com` 在 Mihomo 转成等价的锚定 `DOMAIN-REGEX`，在 AdGuard DNS 转成等价的 `/REGEX/`；Mihomo 原生 YAML wildcard 仅将 `*`、`?` 当作通配符，`[0-9]` 是字面文本，不能误转为 Surge 字符类。Surge 域名规则大小写不敏感，Mihomo 的原生 keyword／wildcard 对未经规范化的大写 Host 已实测不命中；转换、白名单覆盖及逻辑子条件须保留可证明的来源匹配范围，不能扩大或删除不同来源的规则。Quantumult X `HOST-*` 的大小写语义尚无客户端证据，不因推测而丢弃它们。与 AdGuard DNS 正则兼容的 `DOMAIN-REGEX` 输出拦截和 `@@` 放行；不把 Mihomo 独有正则构造未经验证直接写入 DNS 列表。白名单当前支持的域名类型均保留对应例外；DNS 的合法 hostname 按已核查公开服务器代码先规范化再验证，不以裸 DNSEngine 的大写输入单独认定线上漏匹配。
- Surge `PROCESS-NAME` 可把 `*`／`?` 解释为 glob，Mihomo 原生 YAML 的 `PROCESS-NAME` 把它们视作字面字符。解析 YAML `payload:` 时保留这一来源语义，使 Mihomo 精确规则不被扩大为 wildcard；当前普通 Surge 来源仍按原 glob 转换。无法等价表达字面星号的目标不得输出范围扩大的规则。
- `no_resolve=add`、`strip`、`keep` 对顶层及任意层级逻辑表达式中的目标 IP 叶子一致生效：`add` 添加一次，`strip` 移除，`keep` 保留来源值；重复标志规范化成一次。Surge 支持 `IP-CIDR`、`IP-CIDR6`、`GEOIP`、`IP-ASN`，Mihomo 还支持 `IP-SUFFIX`。标志写在 IP 子规则括号内，不能写在逻辑父规则或来源 IP／域名子规则上。解析与渲染使用不依赖 Python 调用递归上限的遍历，保留已经由 Mihomo 加载验证的 600／1000 层合法逻辑条件；不得截断或删除深层规则。该标志只控制当前叶子是否主动解析域名，不保证整个请求绝无 DNS 查询。

## 验证与发布

每个确认的根因先在 `tests/test_rules.py`、`tests/test_formats.py` 或 `tests/test_generate.py` 加最小失败例，再实施修复并跑绿；更新现有断言中把漏转当作预期的用例。按六种文件检查 matcher 范围、例外、跳过计数、`no-resolve` 三态和 `src` 方向；为 HTML 页、无效正则、无效端口及来源选项分组保留负例。可使用本机 Mihomo 验证测试样例，不把客户端二进制加入构建依赖。运行完整 unittest 与 `git diff --check`，核对 `static/` 无变化；只暂存本次修改，提交并推送 `main`，检查 GitHub Actions 的 `test` 与 `update` 结果以及自动生成提交。若远端测试失败，修复后再次推送并核对，不把本地绿灯冒充远端成功。

依据：[Surge 逻辑规则](https://manual.nssurge.com/rules/logical.html)、[Surge IP 规则](https://manual.nssurge.com/rules/ip.html)、[Mihomo 规则](https://wiki.metacubex.one/en/config/rules/)、[AdGuard DNS 语法](https://adguard-dns.io/kb/general/dns-filtering-syntax/)、[Quantumult X 官方配置样例](https://github.com/crossutility/Quantumult-X/blob/master/sample.conf)。