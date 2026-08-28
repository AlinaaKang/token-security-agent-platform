# 面向AI安全的Token流量异常检测智能体平台

本项目面向大模型应用入口，检测并定位附着在正常请求后的优化型 jailbreak 后缀。这里的“Token 流量异常”指模型内部 Token 序列的熵、负对数似然（NLL）及变化点，不是 API Token 用量或网络流量监控。

基础任务解决一个明确痛点：单一整句安全分类不能定位优化型后缀，单一 Token 变化点又不能识别没有分布突变的直接危险请求。平台分别保留两类独立证据：Qwen3Guard-Gen-0.6B 判断语义安全等级，Qwen2.5-7B-Instruct 的完整 logits 供 Entropy-CPD 检测异常候选与起点，最后由固定融合表给出处置。

## 已实现

- Web 工作区：安全分析、安全事件、评测中心、专业攻防实验舱、SuperAgent 自主处置和 Token 侦探挑战。
- 在线链路：Prompt -> Qwen3Guard 语义分类 -> Qwen Token 观测 -> Entropy-CPD -> 证据融合 -> 脱敏审计。
- 处置语义：语义危险直接拦截，争议内容进入复核；语义安全但 CPD 告警时，analysis 实验拦截、gateway 人工复核；两路均正常才放行。
- 隐私边界：Guard 原始输出只在内存中严格解析；SQLite 只保存 SHA-256、长度、归一化语义类别、检测统计、动作、模型和校准版本。
- 冻结评测：Global NLL、Window NLL、Entropy-CPD 使用相同 group-aware calibration/dev/test 划分。
- 智能体消融：Semantic-only、CPD-only、Fusion 使用同一 1,469 条冻结数据集和九个工作点，公开来源缺口、误报、定位与延迟。
- 真实演示：浏览器只接收冻结测试 sample ID、攻击族和脱敏 Token 序号，不接收攻击原文。
- 可选进阶层：离线官方知识快照、FTS5 Top-3 检索和有引用研判报告；知识证据在基础结论生成后附加，不能改写动作、分数或异常起点。
- 挑战任务：有界 SuperAgent 复用实验舱脱敏结果，按固定权限完成规划、观察、一次重规划、零到三次内部工具调用和结构化收口；不展示隐藏思维链，不声称外部安全设备联动。

PCAP、RAG、ReAct、BEAST 和 AutoDAN-HGA 不进入基础任务算法与冻结 CPD 指标。当前进阶任务单独实现了离线 RAG 证据层；PCAP 属于网络协议层证据，不能替代当前模型内部 Token 证据。

## 当前验证

- 后端：514 passed，1 个本机真实 GPU 集成测试因未配置模型而 skipped。
- 前端：136 个自动化测试，TypeScript 与 Vite 生产构建通过。
- AutoDL：RTX 4090 D 24GB，Qwen2.5-7B-Instruct + Qwen3Guard-Gen-0.6B；模型、检测器、语义 Guard、知识库、审计、评测、样本服务、实验舱和 SuperAgent 全部 ready，部署校准一致。
- 原始 CPD/NLL 基准：冻结测试 663 条，其中攻击 460、无害 203。
- 受保护融合验收：3 条直接危险、1 条普通安全、1 条争议上下文、1 条无害格式突变，语义与动作 6/6 符合预期。
- 真实 ID 抽测：GCG、AutoDAN、AdvPrompter 各 3 条，本轮 9/9 同时触发语义拦截和 CPD 异常候选，响应完全脱敏。
- 正式智能体消融：1,469 条总数据、838 条冻结 test、838/838 完成且失败 0。Semantic-only 的 Dev FPR 5% 档位在 test 上 F1 97.64%、FPR 1.24%；Fusion 同档位 F1 96.71%、FPR 10.25%，因此不声称融合全面优于单路。

6/6 与 9/9 都只用于功能链路验收，不代表独立语义准确率或总体 F1。完整冻结 CPD/NLL 指标见 [实验报告](docs/basic-task/experiment-report.md)。

最新三链路消融的来源、哈希、九个工作点、分域结果与限制见 [智能体冻结消融报告](docs/basic-task/ablation-report.md)。CPD 在当前系统中的可辩护价值是独立 Token 变化证据与异常起点定位，不是总体分类性能必然优于语义模型。

## 本地验证

正式环境使用 Python 3.11 或 3.12。

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
$env:PYTHONPATH=".localdeps"
python -m pytest -q

Set-Location frontend
npm.cmd install
npm.cmd test -- --run
npm.cmd run build
```

仅运行 Web 外壳时，未配置 GPU 的 API 会诚实返回降级健康状态。完整检测需要设置：

- `TOKEN_SECURITY_MODEL_PATH`
- `TOKEN_SECURITY_CALIBRATION_PATH`
- `TOKEN_SECURITY_GUARD_MODEL_PATH`
- `TOKEN_SECURITY_GUARD_MODEL_VERSION`
- `TOKEN_SECURITY_BENCHMARK_REPORT_PATH`
- `TOKEN_SECURITY_EVENT_DB_PATH`
- `TOKEN_SECURITY_DEMO_AUTODAN_CSV`
- `TOKEN_SECURITY_DEMO_ADVPROMPTER_CSV`
- `TOKEN_SECURITY_DEMO_GCG_CSV`
- `TOKEN_SECURITY_KNOWLEDGE_SNAPSHOT_PATH`
- `TOKEN_SECURITY_KNOWLEDGE_EVALUATION_REPORT_PATH`
- `TOKEN_SECURITY_AGENT_ABLATION_MANIFEST_PATH`
- `TOKEN_SECURITY_AGENT_ABLATION_REPORT_PATH`

开发模式 Web 默认通过 Vite 将 `/health` 和 `/api` 代理到 `http://127.0.0.1:18000`。

## 数据与署名

CPD 算法和首批数据唯一参考为 CPDonline，固定 commit：

`1a6c055865c44cc1d10dfbe5d014576c7331322e`

项目不把 CPD 算法本身表述为原创。Qwen3Guard-Gen-0.6B 是 Apache-2.0 第三方语义安全层，不表述为本项目训练的模型。原始 CSV 只存在于未跟踪的只读目录；Prompt、suffix、Token 文本和 Guard 原始输出不得进入 Git、测试、日志、报告、截图或事件数据库。

## 比赛合规

当前实现为自研平台。提交前必须将赛事方允许自研平台替代“基于深信服 AI 安全平台”的书面确认归档到团队材料库；仓库只记录归档要求，不保存私人聊天或账号信息。

详细材料：

- [系统设计](docs/basic-task/design.md)
- [开发与部署](docs/basic-task/development.md)
- [测试报告](docs/basic-task/test-report.md)
- [实验报告](docs/basic-task/experiment-report.md)
- [智能体冻结消融报告](docs/basic-task/ablation-report.md)
- [三分钟演示脚本](docs/basic-task/demo-script-3min.md)
- [进阶任务系统设计](docs/advanced-task/design.md)
- [进阶任务测试报告](docs/advanced-task/test-report.md)
- [进阶任务实验报告](docs/advanced-task/experiment-report.md)
- [AI 安全攻防实验舱](docs/security-lab.md)
- [Token 侦探挑战](docs/token-detective-challenge.md)
- [挑战任务：有界 SuperAgent](docs/challenge-task.md)
