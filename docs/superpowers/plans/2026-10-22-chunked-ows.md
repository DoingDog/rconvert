# 单一 chunked OWS 的实施计划

规格：`docs/superpowers/specs/2026-10-22-chunked-ows-design.md`。

## 范围与基线

- worktree：`C:/Users/user/Downloads/rconvert/.claude/worktrees/wf_dcf70dde-e2b-2`。
- branch：`worktree-wf_dcf70dde-e2b-2`。
- base：`4c1f29d55e47f939b96cf87a5284f947938191ed`，初始工作区干净。
- 拥有文件仅为 `generate.py` 的 fetch 区域、新增 `tests/test_chunked_ows_regressions.py`、规格和本计划；其他文件只读。
- 本任务处于主 workflow 的独立编码分支，其他独立任务由其余 worktree 并行执行，不在本 worktree 合并。

## 执行步骤及检查项

### 1. 规格与基线提交

已读取实际函数、全部生产调用、相关既有测试、README、四份历史规格及对应三视角复核。核对公共接口、异常与发布保护，记录唯一目标 Ubuntu、共享依赖接口和不修改范围。

检查：确认 cwd／worktree／HEAD；运行既有 transport 测试和 Linux 完整修改前基线；规格／计划覆盖任务全部条款；`git diff --check`；仅提交两份新文档。Linux 基线若仍在执行，继续独立的 TDD 工作，完成通知后记录实际结果。

### 2. 完整 chunked bytes 的 TDD

只新增一个通过 `fetch_https` 的测试，依次核 canonical、mixed-case、SP／HTAB 下普通及 gzip／x-gzip 的原始规则 bytes，正文分多个 chunk。

检查 RED：原实现泄漏 plain framing，OWS gzip 报 `BadGzipFile`；同一真实 TLS 验证脚本在 Windows／Debian 复现。随后在首次有界 read 前插入单一 token 判断及两个 HTTPResponse 状态赋值。

检查 GREEN：新增测试和既有 transport 模块通过；未修改 decoder、length、异常／大小路径、imports 或其他函数。

### 3. 截断和发布保护的 TDD

逐项追加缺 zero chunk／短 chunk 的公开 fetch 回归，再追加 source／white 截断的全组旧 bytes 保护测试。每个新增行为单独运行旧基线实现确认 RED，然后运行当前实现确认 GREEN；基线仅在独立 Python 进程内从 Git 原文加载，真实 urllib／HTTPResponse／gzip 不替换，受控文件不来回修改。

检查：RuntimeError 保留 URL 与 `IncompleteRead` cause；前置健康组、当前组和依赖组的旧产物全部保持，static 输入 bytes 保持。

### 4. 状态、大小、gzip 和 redirect 回归

逐项追加上限等值／多一 byte、CRC／gzip 截断、206／503、redirect 最终 OWS response 的回归，运行该项后再追加下一项。已有正常行为应持续 GREEN，属于同一根因的新失败项补基线 RED。

检查：原始／解压大小错误准确、gzip cause 保留、无新增重试、HTTPS-only、旧 redirect body 不读取、成功和失败的最终 response 关闭。非 ASCII／VT／组合 coding 不获新增 chunked 解码支持。

### 5. source／remote white 与依赖集成

逐项追加 canonical 与 OWS 对照：九种 purpose／no_resolve、plain／gzip／x-gzip；source 中包含目的／来源 IP、有／无 no-resolve、allow、不同来源身份及目标局部 unsupported，remote white 包含跨 chunk 规则。每个新场景单独确认原实现差异，再验证当前结果。

检查：固定时刻下六文件 bytes、诊断、URL 缓存、static 不变；六种产物分别经过同轮 source／white 和发布后的非空 disk-only source／white。含不支持 whitelist 类型时比较原有严格拒绝，不扩大其支持。合法空同轮依赖及 disk-only 严格拒绝、404 冻结和无效 remote white 区别保留。

执行中核实：block 的精确 DNS 例外 `@@|domain|` 会触发现有普通读取器的 invalid rule，属于现有产物重导入边界。六格式成功依赖 fixture 使用已支持的 suffix white 及其 `@@||domain^` 例外；本任务不修改该 parser。primary matrix 仍保留精确远端白名单的真实六文件输出比较。

### 6. 规格审查、简化和最终提交

逐条核对规格验收与测试覆盖；检查新增分支只处理 ASCII OWS 的单一 chunked token。检查是否有重复 parser、fallback、多余 helper、未使用 import 或无关改动，发现问题即修正并复审。

检查：Windows／Debian 真实 TLS 当前实现通过；相关 transport／generate 回归通过；完整 Linux `unittest discover -s tests -v` 通过，不改任何旧 timeout；`git diff --check`；核四文件所有权后英文提交。返回 base／head／commits、RED／GREEN／完整 suite 证据及未检查范围，保留待主 workflow 接收的 worktree 和分支。

完整 Linux 验收使用 `/tmp` 中逐文件核对 SHA-256 的当前 worktree 副本，复制全部受控文件及新增回归文件，不复制 `.git` 或旧临时目录。这样既有以仓库目录为临时目录 parent 的测试也在 Linux 文件系统执行，case-distinct 检查可实际运行。执行前后核对全部副本与原 worktree 文件 bytes，并清理本次副本；不修改既有测试、timeout 或系统设置。

## 验证命令

Windows 使用已有 `C:/Users/user/.local/bin/python.exe -I -B`，显式将本 worktree 加入 `sys.path`。Linux 使用 `wsl.exe -d Debian --cd /mnt/c/Users/user/Downloads/rconvert/.claude/worktrees/wf_dcf70dde-e2b-2 --exec python3 -I -B`，显式加入相同 Linux 路径；测试 fixture 位于 OS 临时目录。

`_WireEndpoint` 仅隔离外部 TLS 端点，不能替换 HTTPResponse.read 或正文 parser；真实 TLS 脚本使用本次临时证书和受信任 SSLContext。禁止启动任何客户端或下载执行外部代码。
