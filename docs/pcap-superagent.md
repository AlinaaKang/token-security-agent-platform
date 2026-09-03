# PCAP SuperAgent 操作与演示指南

## 能力边界

PCAP SuperAgent 是可选的“网络证据分诊”能力，默认关闭。未显式设置
`TOKEN_SECURITY_PCAP_ENABLED=true` 时，后端不构造 PCAP 授权、执行或任务协调组件，
`/super-agent` 仍默认进入原有 Prompt 模式，Prompt 分析、Entropy-CPD、处置动作和
`/challenge` 均保持原行为。

本版本只输出匿名捕获 ID、数量、协议计数、可见性、固定能力类别和固定错误代码。
它不向 Agent 或页面提供文件名、路径、载荷、摘要、网络端点或原始解析器错误。

## 启用前准备

隔离目录必须是仓库之外的绝对路径，并至少包含 `input` 子目录。PowerShell 也必须
配置为已存在文件的绝对路径。不要把 PCAP、输出报告、批次状态、取消标记或私有映射
放进仓库。

```powershell
$quarantineRoot = 'D:\token-security-pcap-quarantine'
New-Item -ItemType Directory -Force -Path (Join-Path $quarantineRoot 'input') | Out-Null

$env:TOKEN_SECURITY_PCAP_ENABLED = 'true'
$env:TOKEN_SECURITY_PCAP_QUARANTINE_ROOT = $quarantineRoot
$env:TOKEN_SECURITY_PCAP_POWERSHELL_EXECUTABLE = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
```

`D:\token-security-pcap-quarantine` 只是仓库外示例。实际路径仍须是本机绝对路径，
不能位于项目根目录、符号链接、junction 或其他 reparse point 下。批处理脚本和单文件
检查脚本固定使用仓库内已审核版本；不要用环境变量指向仓库外脚本。

## Docker 隔离门禁

先构建现有 inspector 镜像，再运行机械隔离验证器：

```powershell
docker build -f pcap-inspector/Dockerfile -t token-security-pcap-preflight:local .
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/verify_pcap_sandbox.ps1
```

只有验证器报告 `pcap_sandbox_verification=passed` 后才可进入真实文件演示。验证器使用
代码生成的无害合成 PCAP，检查容器无网络、非 root、只读根文件系统、只读单文件挂载、
全部 capability 丢弃、`no-new-privileges`、CPU/内存/PID 限制、无载荷泄漏和无残留容器。

## 启动与隐私验证

在同一个已配置环境中正常启动后端；前端仍按通常方式启动：

```powershell
$env:PYTHONPATH = (Resolve-Path 'backend').Path
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

Set-Location frontend
npm.cmd run dev
```

后端可用时，可从仓库根目录执行只输出固定聚合值的公共边界验证：

```powershell
python scripts/verify_pcap_agent_privacy.py --base-url http://127.0.0.1:8000 --repo-root .
```

验证器只读取两个 count-only PCAP 概览，并发送四个必然失败的验证请求：无效授权、
PCAP objective 混入 Prompt-only 字段的无效任务创建、未知任务恢复和未知任务取消。它不签发有效授权、不启动
任务，也不读取捕获内容。成功输出固定为：

```text
pcap_agent_privacy_verification=passed
checked_endpoint_count=6
privacy_violation_count=0
tracked_private_artifact_count=0
```

## 两次点击授权流程

1. 打开 `/super-agent`。默认的 `Prompt 安全调查` 不会请求 PCAP API。
2. 选择 `PCAP 证据分诊`，只检查“待处理文件”数量，不打开或读取任何捕获。
3. 将“本次最多处理文件数”设为 `1` 到 `20` 的整数，点击第一次授权步骤
   `准备开始`。这一步只展开确认区，不签发授权、不启动任务。
4. 核对数量后点击第二次授权步骤 `确认并开始`。只有这次点击会签发一次性授权并立即
   启动一个有界批次。
5. 轮询公开任务状态。需要停止时点击 `取消任务`；API 会立即确认停止请求，但公开状态
   在当前文件、进程和容器完成隔离清理前仍保持运行中，随后才进入 `cancelled` 终态。
6. 任务进入完成、取消或降级终态后，依次查看 Guard 语义侦探、CPD 曲线侦探和 Agent
   小队队长的公开证据汇报。

刷新页面时，前端只从会话存储恢复脱敏任务 ID 并继续轮询，不会重新签发授权。取消后
如需续跑，必须再次完成 `准备开始` 和 `确认并开始`，创建新的授权任务。外部批次状态会
跳过未改变的成功文件、重试失败文件并纳入新文件；任何真实续跑仍必须由新的 UI 授权
触发，不能直接调用批处理脚本代替确认。每次先排除未改变的成功文件，再按文件大小从小
到大选择最多 20 个可执行候选，因此较大文件和新增文件不会被既有成功断点长期阻塞。

## 结果含义

| 公开类别/状态 | 可以说明的含义 | 不可以推导的结论 |
| --- | --- | --- |
| `token_eligible` | 明文应用协议候选；协议条件允许申请后续内容恢复 | 不是 LLM 流量证明，不是 jailbreak、CPD 或 Token 异常 |
| `traffic_only` | 网络证据分诊结果；只形成流量层证据 | 不表示 Prompt 已恢复 |
| `insufficient_evidence` | 当前固定协议证据不足 | 不尝试绕过加密或猜测内容 |
| `completed` | 所选文件均已形成公开结果 | 不代表完成 Prompt/Token 分析 |
| `cancelled` | 用户取消后停止调度并完成清理 | 不会自动签发续跑授权 |
| `degraded` | 部分文件失败或工具未完整完成 | 只使用固定错误类别，可重新授权重试 |

## 比赛演示用语

对全部 traffic-only 结果统一说“网络证据分诊”。对 `token_eligible` 统一说
“明文应用协议候选”。可以使用下面的完整表述：

> 平台提供一个默认关闭、需要两次 UI 确认的网络证据分诊能力。它在无网络、非 root、
> 只读且资源受限的容器中逐文件检查，Agent 只接收匿名计数和固定能力类别。
> `token_eligible` 仅表示明文应用协议候选，不证明 LLM 流量、jailbreak、Entropy-CPD
> 或 Token 异常。

不得说“检测到 jailbreak”或“异常 Token”，也不得把网络结果表述为 Entropy-CPD、
异常起点或 Token 级定位。

实际 Prompt 恢复、CPD 分析和 Token 分析需要一个独立、能产生可审计内容证据的恢复
模块，并在恢复后重新经过既有模型检测链。该模块在第一版不可用；因此第一版不提供
Prompt 恢复、Entropy-CPD 或 Token 异常分析。

## 当前验收限制

自动测试和隐私验证可使用合成 HTTP 响应、禁用配置和合成 PCAP 完成。真实 20 文件批次、
文件间取消、新授权续跑与新增文件验收必须在后续获得一次新的明确 UI 确认后执行。在没有
该确认时，不得读取真实 PCAP，也不得直接运行批处理脚本作为替代。

## 分层侦察阶段门禁

分层侦察只回答“数据集的结构和协议可见性是否足以选择下一步检测器”，不检测攻击、
jailbreak、Prompt 或 Token。最小文件优先的 PCAP 分诊只能验证工具链和最小协议样本，
不能代表整个语料库：文件大小、封装、协议和失败率可能随规模变化，因此不能据此推断
总体分布或安全结论。侦察阶段固定抽取大小四分位的中点样本。先按大小排序并将零基
索引 `i` 分到 `min(3, floor(i*4/n))` 四分位；每个含 `m` 个文件的四分位最多抽取
五个样本，第 `k` 个样本（`k=0..r-1`，`r=min(5,m)`）使用零基位置
`floor((k+0.5)*m/r)`，重复位置拒绝。等价地，四分位边界的秩可用相邻的
`floor(q*n/4)-1` 和 `floor(q*n/4)` 取中点（`q=1,2,3`，边界夹到有效索引）描述；
实现必须使用前述局部公式以保证每个非空四分位覆盖。

每次真实侦察都必须从全新的 UI 两次确认流程签发一次性授权；刷新、取消或重试都不能
复用旧收据。只有现有 Docker 隔离器允许对单个完整文件做解析，且解析结果必须先经过
固定的聚合校验，再进入公开任务状态。公开 schema 只允许布尔值、计数、固定类别、协议
计数和固定错误代码；不包含文件名、路径、载荷、地址、时间戳、哈希、ID 或原始异常。

侦察观察结果只用于选择下一版检测器计划，不直接改变既有 Prompt、triage、challenge、
mascot、Token 或 CPD 行为。决策规则固定为：成功样本少于 16 个时先修复工具或数据质量
并重新侦察；明文样本不少于 8 个时优先规划应用层 Request 检查；顺序候选不少于 12 个
时纳入 Packet/Flow 行为检测并评估可选 CPD；加密样本不少于 12 个时优先规划元数据行为
检测并记录内容限制；明文和顺序两个条件同时满足时规划 Request 加顺序的混合检测；其余
情况选择由占主导的证据支持的最小方法并保留证据不足处理。这些是方法选择门槛，不是攻击
结论。文件名和路径不能
作为输入、标签或模型特征；它们是私有部署细节，必须在仓库外隔离并由聚合统计替代。

阶段报告使用 [PCAP 侦察报告模板](pcap-reconnaissance-report-template.md)，只写总体结构、
协议可见性、序列适用性、证据限制和下一步计划，不写任何逐文件行。
