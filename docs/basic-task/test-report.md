# 基础任务测试报告

报告日期：2026-08-26

## 1. 自动测试

| 范围 | 命令 | 结果 |
| --- | --- | --- |
| 后端全部单元/集成/回归 | `python -m pytest -q` | 194 passed，1 skipped |
| 前端交互 | `npm.cmd test -- --run` | 12 passed |
| 前端生产构建 | `npm.cmd run build` | 通过，1595 modules transformed |
| 界面规则扫描 | Impeccable bundled detector | 0 findings |

唯一 skipped 项是本机真实 GPU runtime 集成测试，因为本机未设置 `TOKEN_SECURITY_GPU_TEST_MODEL`。相同真实模型路径已经在 AutoDL 单独验收。

## 2. 覆盖行为

- CPD 稳定序列放行。
- Guard `unsafe` 在 CPD 正常时仍拦截，`controversial` 进入复核。
- Guard 无法解析或不可用时不默认 safe，gateway 采用 fail-safe 复核。
- Guard 原始输出不进入 API、SQLite 或 Web。
- 高分但未越过 `h` 的 analysis 与 gateway 均放行。
- analysis 告警返回 Token 异常候选和实验阈值拦截。
- gateway 告警返回 Token 异常候选和人工复核。
- SQLite 文件不包含测试 Prompt 或 Token 文本。
- 事件分页、筛选和审计失败状态。
- schema v2 三方法完整性、有限数值、计数一致性和 forbidden-key 递归拒绝。
- demo 只允许冻结 test attack ID，拒绝 benign、非 test 和未知 ID。
- demo 响应 `token_text=""`、`token_id=0`。
- Web 显示检测语义、审计、真实事件、三方法双工作点和未评测攻击族。

## 3. AutoDL 运行验收

部署环境：RTX 4090 D 24GB，Qwen2.5-7B-Instruct + Qwen3Guard-Gen-0.6B。

健康检查结果：

| 组件 | 状态 |
| --- | --- |
| model | ready |
| detector | ready，qwen25-7b-cpd-paper-v2 |
| semantic_guard | ready，ModelScope master + 权重 SHA-256 身份 |
| knowledge | ready，official-v1，12 cards |
| audit | ready，SQLite |
| evaluation | ready，schema v2，deployment match |
| demo | ready，460 个冻结攻击样本 ID |

无害普通问答实测：语义 `safe`、`no_token_anomaly`、动作 `allow`，审计写入成功；Guard 627 ms，端到端 697 ms（首次 API 请求）。

受保护融合烟测共 6 条：3 条直接危险原始指令、1 条普通安全请求、1 条争议上下文、1 条无害格式突变。返回语义分布为 unsafe 3、safe 2、controversial 1；动作分布为 block 3、allow 1、review 2；语义与动作预期均为 6/6，错误 0。该结果是功能验收，不是独立冻结语义准确率/F1。

真实 ID 抽测：GCG、AutoDAN、AdvPrompter 各 3 条，本轮 9 条均为语义 `unsafe`、CPD 异常候选和最终 `block`，并返回真实起点证据；9 条响应的 Token 文本和 Token ID 脱敏泄漏数为 0。该抽测只验证演示链路，不替代完整冻结指标。

资源测量：Guard 单独加载增加约 1,192,638,976 bytes CUDA allocated；完整双模型 API 空闲显存占用约 16,336 MiB，验收后约 16,492 MiB；OOM 计数 0。最终 6 条烟测 Guard P50/P95 为 176.226/280.514 ms，端到端 P50/P95 为 201.153/455.026 ms。该小样本延迟仅代表本次功能验收，不作为生产 SLA。

隐私复核：

- SQLite、API 日志与聚合报告中 6 条保护输入原文命中数均为 0。
- 聚合报告 forbidden key 命中数为 0，API 日志 Guard 原始两行输出命中数为 0。
- schema v2 报告 forbidden key 递归检查命中数为 0。
- 本地与 AutoDL 报告 SHA-256 均为 `8dffdd87a734740cbf71ddf8a85701a3a85f324373ad9f7855f7cd613ebd3c87`。

## 4. 视觉验收

在 1440x900 与 390x844 两个视口批量检查分析、事件、评测三页。已修复移动端短页面顶部空白、桌面样本按钮换行和移动端空事件提示偏移。宽评测表在手机上保留横向滚动，页面本身不产生无序重叠。

截图使用空输入和聚合报告，不包含攻击原文。

进阶界面另以安全合成数据复验 1440x900 与 390x844 的 analysis、events、evaluation 三页。6 个页面状态均无全局横向溢出，知识长标题和三段控制完整换行，宽表格只在自身容器滚动；知识区域保护检索词命中为 0。

## 5. 已知限制

- 尚未建立独立冻结语义数据集，因此不报告 Qwen3Guard 的准确率、召回率或 F1。
- CPD 告警仍只是 Token 异常候选，必须与语义证据分开展示。
- 本地 GPU 测试 skipped，由 AutoDL 实机结果补充。
- BEAST、AutoDAN-HGA 未评测。
- CPD 的低误报工作点在冻结 test 上 FPR 为 16.26%，尚不适合单证据生产封禁。
