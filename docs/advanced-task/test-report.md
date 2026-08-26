# 进阶任务测试报告

报告日期：2026-08-26

## 1. 自动验证

| 范围 | 结果 |
| --- | --- |
| 后端单元/集成/回归 | 194 passed，1 skipped |
| 前端交互 | 12 passed |
| TypeScript + Vite 构建 | 通过，1595 modules transformed |
| AutoDL FTS 跨线程回归 | 8 passed |
| 报告/失败路径定向测试 | 39 passed |

唯一 skipped 是本机未配置 `TOKEN_SECURITY_GPU_TEST_MODEL` 的真实 GPU runtime 测试；AutoDL 已完成真实双模型验收。

## 2. AutoDL 部署状态

环境：RTX 4090 D 24GB，Qwen2.5-7B-Instruct，Qwen3Guard-Gen-0.6B。

健康检查中 model、detector、semantic_guard、knowledge、audit、evaluation、demo 全部 ready；知识快照为 `official-v1`、12 cards，CPD 校准为 `qwen25-7b-cpd-paper-v2`，evaluation `deployment_match=true`。API 日志错误数为 0。

部署中发现并修复了一个真实并发问题：SQLite 内存 FTS 连接在启动线程创建、FastAPI 工作线程使用时触发 `sqlite3.ProgrammingError`。新增跨线程红测试后，连接改为允许跨线程并用锁串行化只读 FTS 查询；未改变权重、排序或 Top-3。

随后端到端代理验收又发现知识增强合并使用 `model_copy(update=model_dump())` 跳过嵌套类型重验证，API 展示正常但审计读取 `.knowledge_id` 时触发 `AttributeError`。新增工作流强类型红测试后，最终 `AnalysisResult` 在合并边界重新验证。真实请求复验 `audit_persisted=true`，事件记录的 request ID、`official-v1` 和 `fallback` 状态均匹配。

## 3. 冻结检索评测

冻结 fixture 36 条，覆盖 6 个风险域、9 个语义类别、CPD 有/无告警、Guard 不可用和 GCG/AutoDAN/AdvPrompter 标签。fixture 不含攻击指令或 Prompt。

| 指标 | 结果 |
| --- | ---: |
| Hit@1 | 94.44% |
| Hit@3 | 97.22% |
| MRR | 0.9583 |
| 引用有效率 | 100.00% |
| 动作一致率 | 100.00% |

测试后未调整检索权重或 fixture。Jailbreak 风险域有 1 条未命中 Top-3，该限制保留并公开。

## 4. 真实受保护验收

既有 6 条融合样本分别以 `off` 与 `report` 请求：完成 6/6 对，基础动作一致 6/6，错误 0，引用 17/17 有效。报告状态为 1 条模型生成、5 条模板回退。

冻结攻击 ID 验收为 GCG、AutoDAN、AdvPrompter 各 3 条：完成 9/9 对，基础动作一致 9/9，错误 0，引用 27/27 有效。9 条报告均在 3 秒边界后使用模板回退。

这两组结果验证链路和引用，不代表知识问答准确率、Guard 准确率或总体 jailbreak 检出率。

## 5. 性能与资源

| 项目 | P50 | P95 |
| --- | ---: | ---: |
| 6 条样本 FTS 检索 | 0.219 ms | 0.249 ms |
| 9 个攻击 ID FTS 检索 | 0.240 ms | 0.372 ms |
| 6 条报告生成 | 3015.675 ms | 3023.997 ms |
| 9 个攻击 ID 报告生成 | 3021.123 ms | 3024.372 ms |
| 6 条 report 端到端 | 3210.467 ms | 3316.867 ms |
| 9 个攻击 ID report 端到端 | 3256.764 ms | 3308.770 ms |

独立 100 次公开合成检索 P50/P95 为 0.041/0.045 ms。快照与索引的 Python 跟踪当前/峰值内存约 82,317/129,417 bytes。双模型空闲显存 16,336 MiB，验收后 16,508 MiB；OOM 计数 0。

## 6. 失败与隐私检查

- 快照副本缺失 manifest 时加载被拒绝，活动快照未移动或删除。
- 非法 JSON、未知引用和生成超时均由测试验证为模板回退。
- 15 条受保护 Prompt 在 SQLite、API 日志、两份聚合报告中的命中均为 0。
- 聚合报告禁止字段命中 0，Guard/report 原始输出未落盘。
- 3 个 demo API 响应的非空 Token 文本或非零 Token ID 泄漏数为 0。
- 原 schema v2 CPD 报告 SHA-256 仍为 `8dffdd87a734740cbf71ddf8a85701a3a85f324373ad9f7855f7cd613ebd3c87`。

## 7. Web 验收

使用安全合成 UI 数据检查 analysis、evaluation、events 三页的 1440x900 和 390x844，共 6 个页面状态。页面宽度均等于视口宽度；三段控制和知识长标题无溢出；宽表只在自身区域滚动；知识区域保护检索词命中 0。
