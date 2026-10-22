# 单一 chunked Transfer-Encoding 的 ASCII OWS 修复设计

## 目标与依据

在基线 `4c1f29d55e47f939b96cf87a5284f947938191ed` 上修复 `fetch_https` 对合法 `Transfer-Encoding` 边缘 SP／HTAB 的识别。完整正文应返回移除 chunk framing 后的 bytes；缺少终止 zero chunk 或 chunk 数据截断时应停止整轮发布，保留旧产物。

已读取 `fetch_https`、全部生产调用、`generate`／`publish`、`sources`、既有 transport 测试、相关生成测试、README、四份历史设计及 `http-chunked-ows` 三个独立复核的全部 checks。生产唯一直接调用位于 CLI 的 `publish(generate(root, fetch_https))`；`generate` 的共享读取与 URL 缓存同时服务 source 和 remote whitelist。

已通读本次取得的 RFC 9112 与固定 Ubuntu `http/client.py` 内容。其中 [RFC 9112 §5.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-5.1) 规定提取字段值时去除边缘 OWS；[§6.1／§7.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1) 要求解析并解码 chunked；[§8](https://www.rfc-editor.org/rfc/rfc9112.html#section-8) 将缺少 zero chunk 的响应判为不完整。[已应用补丁的 Ubuntu Python 3.12.3 固定源码](https://git.launchpad.net/ubuntu/+source/python3.12/plain/Lib/http/client.py?id=f641d3123029c88838179c83a972bc2be28e6e60) 中，`HTTPResponse.begin` 用 `tr_enc.lower() == "chunked"` 缓存状态；`read` 在 `self.chunked` 为真时先进入标准库 chunk parser。本机 Windows Python 3.13.13 的对应分支也已直接检查。

唯一部署目标是 Ubuntu Actions。Debian WSL Python 3.13.5 用于本次 Linux 实际运行；固定 Ubuntu 3.12.3 源码检查不等于 GitHub runner 实机验收。Windows 只用于确认已有复现，不新增 Windows 兼容功能。

## 公共接口与检查边界

| 公共接口 | 观察结果 | 未覆盖的范围 |
| --- | --- | --- |
| `fetch_https(url: str) -> bytes` | 正确正文 bytes、URL／异常 cause、大小、状态、redirect、关闭行为 | 任意 HTTP framing 合规性、其他 transfer coding |
| `generate(root, fetch_https) -> dict[Path, str]` | source／white、缓存、六文件及诊断与 canonical chunked 一致 | 客户端实际匹配与生产全部上游状态 |
| `publish(outputs, root=root)` | 实际写入 bytes；生成失败时所有旧组文件及 static 输入不变 | 断电时的多文件原子性 |

这些接口由任务指定。测试通过公开入口运行，永久回归复用 `tests.test_functional_audit_transport._WireEndpoint`、`_wire`、`_redirect`。fixture 只隔离 TLS／外部端点，保留真实 `HTTPResponse.begin/read`、urllib handler 链及 gzip。额外以本地真实 TLS socket、临时证书和启用证书／hostname 校验的 SSLContext 验证集成；不替换 response.read，不运行客户端。

## 最小实现

在最终 HTTPS／200 检查后、第一次 `response.read(MAX_BYTES + 1)` 前，读取现有 response headers。仅当值经 `strip(' \t').lower()` 后恰为单个 `chunked` token 时，设置 `response.chunked = True` 和 `response.chunk_left = None`。继续执行原有读取、大小、Content-Length、gzip、空来源及异常处理。

`read` 的 chunked 分支优先于 `length`，本次单次读取不需要修改 `length` 或 `will_close`。只修改 header 字符串不能更改 `begin` 已缓存的状态。不手写 chunk decoder，不捕获后忽略 `IncompleteRead`，不在失败后重读或返回原正文。

## 支持边界

- 支持 canonical／混合大小写 `chunked`、尾 SP、尾 HTAB、两端 SP／HTAB；正文可以分多个 chunk，规则及白名单行可跨 chunk。
- `Content-Encoding` 的 plain、`gzip`、`x-gzip` 及既有 ASCII OWS 行为保持。先解 framing，再执行既有 gzip 解压和 CRC／截断检查。
- 保留原始正文及解压正文 `MAX_BYTES` 上限，恰好上限可接受，多一个 byte 拒绝；framing 不作为内容大小计入。
- 缺 zero chunk、chunk 数据短读继续由标准库抛出 `IncompleteRead`，沿现有包装保留 URL 和 cause。
- 最终状态仍须 200；206 拒绝；503／429／超时继续向外抛出，保持现有不重试行为；404 跳过与 URL 缓存保持。
- 保留 HTTPS 输入、证书和 hostname 验证、HTTPS-only redirect、标准库 redirect 状态／位置／循环规则、旧 redirect body 不读取及最终 response 关闭。
- 不增加其他 transfer coding、组合 coding、coding 参数、重复字段处理或 Unicode／VT 空白支持，不扩大为一般 HTTP parser。
- 不改变无效 remote whitelist 可跳过、本地 whitelist 严格拒绝、合法空组、冻结、发布回滚、root／static 保护或六目标局部 unsupported。
- 不改变 `no_resolve` 的 add／strip／keep、来源 IP 方向、来源身份、allow／white 语义。生成依赖仍读取实际 bytes，不新增 Rule 缓存、sidecar 或其他格式补回。

## 文件与调用影响

仅修改 `generate.py` 的 `fetch_https` 必要行，新增 `tests/test_chunked_ows_regressions.py`、本规格和 `docs/superpowers/plans/2026-10-22-chunked-ows.md`。不改共享 imports、后续路径／发布／依赖函数、rules、formats、既有测试、README、生产输入、配置、exports 或 Actions。现有调用方签名与返回值保持。

永久 fixture 使用 OS 临时目录；Linux 使用 `/tmp`。对照只固定时间这一系统边界，使 ADB header 可比较。真实 TLS 的脚本、证书及私钥仅供本次验证，结束时清理。

## 验收条件

1. 逐行为执行失败回归与最小修复，完整／截断 plain 和 gzip 的失败与正确 canonical 对照均有实际证据。新增测试逐项增加，不先批量写全部测试。
2. transport 回归覆盖 canonical／mixed-case、SP／HTAB、plain／gzip／x-gzip、跨 chunk、缺 zero／短 chunk、原始／解压边界、CRC、206／503、redirect 最终响应和关闭；非 ASCII 空白与组合 coding 不新增解码能力。
3. 公开 fetch -> generate -> publish 覆盖 source 和 remote whitelist、九种 purpose／no_resolve，比较 canonical 与 OWS 的全部产物 bytes 及诊断。所有六种产物的适用同轮 source／white 与非空 disk-only 依赖分别比较；同轮合法空与 disk-only 严格输入的区别保持。
4. 截断 source 或 remote white 时，包含前置健康组、当前组和下游组的全部旧六文件均不变，static 输入 bytes 不变。404／无效 remote white／冻结行为仍由既有规则决定。
5. 完成规格审查、最小实现与测试简化复查；运行相关既有测试和完整 Linux suite，不改旧 timeout，不以 mock 替代真实 TLS 集成。
6. `git diff --check` 通过，只提交四个拥有文件，使用英文提交，不 push／merge 主分支。最终记录实际测试结果、环境和未核查范围。
