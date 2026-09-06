# AI 安全攻防实验舱

`/lab` 是与基础页面隔离的调查工作区，顶部按输入类型分为 `Prompt 攻防` 与 `PCAP 攻防`。Prompt 模式复用现有语义 Guard、Entropy-CPD、固定融合和本地知识证据；PCAP 模式接收一个由用户明确选择的 `.pcap` 或 `.pcapng` 文件，并复用现有 Docker 隔离检测器。两种模式不会改变 `/analyze`、`/events`、`/evaluation` 或 `/challenge` 的请求、响应与处置逻辑，切换模式时 Prompt 表单与结果状态会保留。

## 启用方式

实验舱默认关闭。只有基础检测工作流已经 ready 时，设置以下环境变量并重启 API：

```powershell
$env:TOKEN_SECURITY_LAB_ENABLED="true"
```

可识别的开启值是 `1`、`true`、`yes`、`on`，大小写不敏感。其他值均视为关闭。关闭或依赖不可用时，仅 `/lab` 降级，基础健康状态与三个稳定页面不受影响。

## API

- `GET /api/v1/lab/scenarios`：返回可用场景描述，只包含受保护样本 ID，不包含原文。
- `POST /api/v1/lab/runs`：创建自定义或冻结样本调查。
- `GET /api/v1/lab/runs/{run_id}`：读取 15 分钟内的脱敏调查结果。
- `POST /api/v1/lab/runs/{run_id}/tools/{tool_id}/dry-run`：执行固定工具模拟。
- `GET /api/v1/lab/metrics`：返回最近有效窗口的聚合运行指标。
- `GET /api/v1/superagent/pcap/detection/upload-capability`：返回单文件上传是否可用、支持格式和大小上限。
- `POST /api/v1/superagent/pcap/detection/upload-authorizations`：为一个确定字节数的文件签发一次性上传授权。
- `POST /api/v1/superagent/pcap/detection/uploads`：以原始请求体流式上传一个已授权文件，并启动既有 PCAP 检测任务。

服务最多保留 32 条已脱敏运行，TTL 为 15 分钟。指标从同一窗口聚合，不生成按样本、攻击族或输入哈希展开的明细。

## PCAP 单文件实验

PCAP 模式默认不读取本机文件。选择文件只会在浏览器中显示原文件名、格式和大小；第一次点击“准备检测”只打开确认区，第二次点击“确认上传并检测”才会签发与精确字节数绑定的一次性授权并上传文件。原文件名不会进入请求，服务端使用随机内部名称，任务结束、取消或失败后清理隔离副本。

上传默认上限为 512 MiB，可通过 `TOKEN_SECURITY_PCAP_UPLOAD_MAX_BYTES` 在 1 到 2147483648 字节范围内调整。上传入口只有在本机 PCAP 后端、隔离目录、Docker 和检测镜像均可用时才启用；它不依赖 AutoDL。AutoDL 仅可用于 Prompt 模型推理，不能替代本机 Docker 对 PCAP 的隔离解析。

检测结论必须按以下方式理解：

- `发现异常候选` 表示现有规则或行为证据命中，并给出 Request/Packet 局部区间；它不是攻击已成功或主机已失陷的证明。
- `未发现可定位异常` 表示当前检测范围未命中，不等于文件“全部安全”。加密、非 HTTP、未知协议或规则覆盖不足都可能没有候选。
- `检测未完整完成` 或黄色失败表示工具没有形成可验证结果，需要排查 Docker、tshark、文件格式或超时后重新授权重试；失败不能计入安全样本。

`/lab` 适合临时上传一个待测文件；`/super-agent` 的 PCAP 工作区继续负责仓库外隔离目录中的匿名批次分诊、勘察与检测。两者共用结果卡片和检测内核，但授权范围和文件来源不同。

## 六类演示场景

1. 普通无害：验证双路正常时放行。
2. 无害格式突变：验证 CPD 对格式变化的敏感性，并观察语义证据如何避免把变化点直接等同于恶意。
3. 直接危险：验证没有优化后缀时，语义 Guard 仍可给出安全处置。
4. GCG：按冻结测试样本 ID 调用。
5. AutoDAN：按冻结测试样本 ID 调用。
6. AdvPrompter：按冻结测试样本 ID 调用。

受保护场景只允许发送 `sample_id`。Prompt、优化后缀和截断前缀始终留在受保护服务边界内，不进入浏览器、实验舱缓存、日志、报告或 Git。当前不声明 BEAST 与 AutoDAN-HGA 覆盖。

## 证据含义

语义 Guard 判断内容风险等级与类别；Entropy-CPD 使用 Token 序列的熵、NLL 和累计变化量给出异常候选及预测起点。CPD 是独立的分布变化与定位证据，不等同于语义恶意判定。

反事实检查只在存在有效预测起点时，将同一输入截断到 `char_start` 并使用相同工作流重新检测一次，知识模式固定为关闭。它只能说明结果对预测后缀是否敏感，不构成严格因果证明，也不会改写基础动作。

## 处置沙箱

实验舱只提供三个固定工具：

- `gateway_preview`
- `soc_case_preview`
- `evidence_export_preview`

它们不接受 URL、凭据、路径、命令或自由文本参数，不访问网络、文件系统或子进程。成功和失败均为确定性模拟；工具失败不会把 `block` 降级为 `review` 或 `allow`。

## 运行指标

“实验舱运行指标”包含最近窗口内的反事实执行覆盖、证据冲突、工具成功/失败、报告状态、基础动作不变性及 P50/P95 延迟。这些值用于说明链路覆盖与稳定性，不是冻结分类性能，不应与 `agent-ablation-v1`、F1、召回率或误报率混用。

`privacy_violation_count` 当前为响应边界状态指标；每个成功返回和缓存对象仍会经过递归禁用字段校验。禁用字段为：`prompt`、`suffix`、`token_text`、`token_id`、`query_text`、`raw_output`、`guard_raw_output`。

游戏化入口、50/20/30 评分、录制回放、隐私边界和演示步骤见 [Token 侦探挑战](token-detective-challenge.md)。挑战是全局侧栏中的独立入口，复用 Prompt 实验的脱敏结果，但不属于 `/lab` 的 Prompt/PCAP 输入切换，也不改变专业调查流程。

## 失败行为

- 实验舱关闭：返回 `lab_disabled`，HTTP 503。
- 依赖不可用：返回 `lab_unavailable`，HTTP 503。
- 运行不存在或已过期：返回固定的 `lab_run_not_found` 或 `lab_run_expired`。
- 调查创建失败：不保存部分结果，只返回固定的 `lab_run_failed`。
- 知识、反事实或工具阶段失败：保留或加强基础动作，不允许降级安全处置。

## 建议演示路径

路径一在 `Prompt 攻防` 中使用普通无害和无害格式突变，说明“分布变化不自动等于恶意”。路径二使用直接危险样本，说明语义 Guard 覆盖无明显后缀的内容风险。路径三依次选择 GCG、AutoDAN、AdvPrompter 的受保护 ID，展示 Token 定位、反事实敏感性、知识引用、模拟处置和脱敏报告。路径四切换到 `PCAP 攻防`，选择一个合成 PCAP，完成两次确认后展示上传进度、Docker 隔离边界和局部异常证据。

演示结论应限定为当前冻结样本和已记录运行，不声称 CPD 普遍提高分类 F1，也不把小样本功能抽测表述为总体准确率。

## 2026-08-27 验证记录

- 后端完整回归：`307 passed, 1 skipped`。跳过项为未配置 `TOKEN_SECURITY_GPU_TEST_MODEL` 的本机真实 GPU 集成测试。
- 前端完整回归：`21 passed`。
- 前端生产构建：TypeScript 与 Vite 成功，`1597 modules transformed`。
- Token 侦探挑战回归：前端完整套件 `78 passed`，生产构建 `1605 modules transformed`；桌面与手机视口的设置、回放、答题、揭晓、失败重试、键盘和减少动态效果检查通过。
- Token 侦探真实验收：三关与五关共 8 次运行，受保护族 GCG、AutoDAN、AdvPrompter 齐全，请求禁用字段命中 0、未知引用 0，延迟 P50/P95 为 197.592/248.344 ms，基础健康哈希前后不变。
- 隐私验证器：当前 Git 跟踪清单 `forbidden_key_hits=0`、`tracked_path_hits=0`、`json_errors=0`。
- 浏览器 QA：`1440x900` 与 `390x844` 下，`/analyze` 和 `/lab` 均无全局横向溢出或控制台错误；实验舱三条 SVG 曲线非空，移动端曲线只在局部容器滚动，键盘可切换调查标签并执行工具失败模拟。
- AutoDL：SSH 入口恢复后，在 RTX 4090 D 24GB、Qwen2.5-7B-Instruct、Qwen3Guard-Gen-0.6B 和 `qwen25-7b-cpd-paper-v2` 上完成三条受保护 ID 冒烟。GCG `sample_03d2d4b9c08702e0c531`、AutoDAN `sample_02283ca4e6b13524febb`、AdvPrompter `sample_000cda0dbe64c805c5fe` 均返回 `unsafe`、`token_anomaly_candidate` 和 `block`，CPD 预测起点分别为 68、122、133。
- 三条反事实检查均实际执行并返回 `risk_reduced`，但有效动作继续保持 `block`；证据一致 3、冲突 0，确定性报告生成 3、回退 0，未知知识引用 0。实验舱延迟 P50/P95 为 242.198/644.455 ms。
- 三条响应的禁用字段命中数为 0，实验舱 `privacy_violation_count=0`。基础 `/health` 响应在测试前后 SHA-256 均为 `0adc88a4dd4910d4383aea63ea799a3bccc2e14a67d1deb7724c3b613aa5e5f4`，说明冒烟没有改变基础组件状态。

上述浏览器检查仍只使用合成无害数据，不含攻击原文；AutoDL 调查只通过受保护 sample ID 发起，原文未进入浏览器、Git 或验收输出。三条结果是链路功能冒烟，不替代冻结准确率、召回率或 F1；当前仍不声明直接危险受保护场景、BEAST 或 AutoDAN-HGA 覆盖。

## 2026-09-06 PCAP 单文件验收

- 后端完整回归：`1038 passed, 4 skipped`。跳过项仍为未配置真实 GPU 模型，以及当前 Windows 账户无法创建文件符号链接。
- 前端完整回归：30 个测试文件、268 个用例全部通过；TypeScript 与 Vite 生产构建成功，`1627 modules transformed`。
- PowerShell 隔离门禁：25 项通过、1 项因当前 Windows 账户无法创建 junction 而跳过；`HttpDetection` 仅新增对隔离区 `uploads` 目录的许可，普通 Preflight 和隔离区外路径仍被拒绝。
- 真实浏览器上传：401 字节合成 SQL 注入 PCAP 经过两次确认、一次性授权和无网络 Docker 检测后返回“检测完成 / 发现异常候选”，定位为 `Packet 2-2`；测试不读取真实数据集文件。
- 浏览器 QA：`1440x900` 与 `390x844` 下无全局横向溢出；Prompt 默认选中，带空行的 Prompt 在 Prompt/PCAP 往返切换后完整保留，主内容区没有重复侦探挑战入口，现有检测小队展示保留。
