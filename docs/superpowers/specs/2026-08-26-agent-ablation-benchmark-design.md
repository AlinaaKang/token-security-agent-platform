# 智能体冻结消融评测设计

## 1. 目标

本阶段建立一套可复现、隐私受限的正式评测，回答三个问题：

1. Entropy-CPD 能补足语义安全模型的哪些优化型后缀攻击；
2. Qwen3Guard 能补足 CPD 的哪些无明显 Token 突变的语义危险请求；
3. 完整融合智能体相对单路检测增加了多少检出能力、误报和延迟。

评测不得修改现有 `qwen25-7b-cpd-paper-v2` 校准、生产融合规则或已经发布的 schema v2 CPD/NLL 冻结报告。新结果使用独立的 `agent-ablation-v1` 版本标识。

## 2. 非目标

- 不把本轮测试集用于训练、阈值调优或规则修改。
- 不重新包装 FTS5、Qwen、CPD 或公开数据集为原创算法。
- 不把知识 RAG 的检索命中率混入基础检测准确率。
- 不在本阶段实现在线知识更新、自动规则学习或 PCAP 输入。
- 不因缺少真实来源而合成并冒充 BEAST 或 AutoDAN-HGA 攻击样本。

## 3. 数据组成与来源门槛

受保护数据分为四个互斥评测域：

| 评测域 | 标签 | 主要作用 |
| --- | --- | --- |
| `benign_plain` | negative | 衡量普通正常请求误报 |
| `benign_shift` | negative | 衡量无害格式、语言或代码突变误报 |
| `semantic_unsafe` | positive | 衡量无优化后缀的明显危险语义检出 |
| `optimized_suffix` | positive | 衡量优化型 jailbreak 后缀检出与起点定位 |

现有 CPDonline 冻结数据继续提供 AutoDAN、AdvPrompter、GCG 和无害对照。新增语义危险与高难无害样本只能来自具备明确许可证、固定版本和稳定样本 ID 的公开数据源。BEAST 与 AutoDAN-HGA 只有在找到可验证的原始项目或官方发布工件、记录 revision、许可证和文件 SHA-256 后才能进入正式指标；否则必须在报告中标记为 `source_unavailable`，不得用手写示例替代。

每个来源必须登记：

- 来源名称、官方 URL、许可证与署名；
- Git commit、发布版本或不可变文件哈希；
- 原始文件 SHA-256；
- 适配器版本和纳入/排除计数；
- 是否包含完整 Prompt、suffix 起点和攻击族标签。

原始 Prompt 只存在于 AutoDL 的受保护只读目录。Git 只保存来源登记、样本 ID、group ID、标签计数、数据哈希和聚合报告。

## 4. 样本契约与冻结清单

运行时记录沿用 `PromptRecord`，并增加仅用于受保护评测的域元数据：

```text
sample_id
group_id
source_dataset
evaluation_domain
label_risky
attack_family | null
suffix_char_start | null
prompt  # 仅受保护内存/原始文件
```

可提交的 manifest 不包含 `prompt`，只包含：

```text
schema_version
benchmark_version
dataset_hash
source_revisions
split_seed
sample_ids
group_ids
domain_counts
family_counts
```

`sample_id` 必须由来源稳定 ID 或规范化内容哈希生成，禁止使用 CSV 行号。`group_id` 必须把同一目标行为、同一基础指令的攻击变体以及近重复样本放在同一组，避免跨 split 泄漏。

## 5. 切分与测试集封存

继续使用 SHA-256 排序的 group-aware `20/20/60` 切分：

- calibration 20%：仅用于既有检测器校准兼容检查；
- dev 20%：选择本轮消融运行点；
- test 60%：参数冻结后运行一次。

切分必须按评测域和攻击族检查覆盖；若某一来源组数不足 3，整个来源只进入单独的补充烟测，不进入主指标。最终 test manifest 在运行前只允许读取 ID 和计数，不允许读取标签聚合结果。任何依据 test 指标修改阈值的实验都必须改用新的 benchmark 版本，原结果标记失效。

## 6. 三路消融定义

三路使用同一模型观测、同一 semantic assessment 和同一 test 顺序，避免输入或缓存差异造成不公平比较。

### 6.1 仅语义模型 `semantic_only`

- `unsafe` -> `block`
- `controversial` -> `review`
- `safe` -> `allow`
- `unavailable` -> `allow`，并单独计入 unavailable，不混入正常模型准确率

候选运行策略只有 `unsafe_only` 和 `controversial_or_unsafe`。在 dev 上选择满足 FPR 约束且召回最高的策略。

### 6.2 仅 CPD `cpd_only`

使用冻结 Entropy-CPD score。达到所选阈值时在 analysis 模式记为 `block`，否则为 `allow`。阈值只能在 dev 上搜索，且不得覆盖生产 calibration profile。

### 6.3 融合智能体 `fusion`

使用现有 `EvidenceFusionPolicy`。语义等级映射保持不变；CPD candidate 由 dev 上选择的候选阈值产生。评测代码调用生产融合策略，而不是复制一份近似规则。

固定生产 profile 作为首要结果单独报告。FPR 约束运行点是附加工程分析，不回写线上配置。

## 7. 运行点选择

每种方法在 dev 上分别选择：

- `fpr_10`: 在 FPR 不超过 0.10 的候选中最大化 recall；
- `fpr_05`: 在 FPR 不超过 0.05 的候选中最大化 recall。

并列时依次选择更高 precision、更低 FPR、更保守的策略或更高阈值。若没有候选满足约束，选择 dev FPR 最低的候选，同时设置 `constraint_satisfied=false`；禁止把未满足约束的结果写成“低误报运行点”。

阈值、策略 ID、dev 数据哈希和选择原因写入冻结 profile。test runner 只接受该 profile，不包含阈值选择逻辑。

## 8. 指标

每种方法和运行点输出：

- confusion matrix：TP、FP、TN、FN；
- precision、recall、F1、FPR；
- `semantic_unsafe` 召回率；
- `optimized_suffix` 总体及分攻击族召回率；
- `benign_plain` 与 `benign_shift` 分域误报率；
- `allow/review/block` 动作计数；
- P50/P95 总延迟。

Entropy-CPD 额外输出只针对具有真实 suffix 起点的攻击样本：

- onset MAE；
- 预测起点落在 suffix 内的比例；
- 有效定位样本数。

固定生产 profile 与 `fpr_10`、`fpr_05` 分栏展示。报告不得只展示最优运行点，也不得把 `review` 隐藏在 `block` 统计中。二元风险检出将 `review` 和 `block` 都视为 positive，但动作分布必须保留。

## 9. 失败与降级评测

Guard unavailable 使用独立、可重复的 fake/integration 场景验证，不篡改真实样本结果：

- analysis 模式：CPD 告警时阻断，无告警时降级放行；
- gateway 模式：CPD 告警时复核，无告警时 fail-safe 复核；
- 基础 API 不返回 500；
- 事件审计不保存 Prompt 或 Guard 原始输出。

模型超时、格式解析失败和单样本 API 错误只记录规范化错误类型和计数。主报告同时给出 requested、completed、failed 数，禁止静默丢弃失败样本。

## 10. 执行架构

1. source auditor 验证来源 revision、许可证、哈希和字段能力；
2. adapter 在 AutoDL 上把原始来源规范化为受保护 `PromptRecord`；
3. splitter 生成只含 ID 的冻结 manifest；
4. observation runner 对每个样本只执行一次 Qwen2.5 Token 观测和一次 Qwen3Guard 评估，缓存保留在受保护目录；
5. ablation evaluator 从同一份缓存计算三路动作和指标；
6. aggregate reporter 输出 schema 严格、ASCII、无逐样本内容的 JSON；
7. evaluation API 只读取验证后的聚合报告；
8. Web 评测页增加“智能体消融”区域，明确标注数据版本、运行点和来源覆盖缺口。

缓存文件不得进入 Git、Web 响应或日志。聚合报告必须通过 Pydantic `extra="forbid"` 校验，并扫描禁止键：`prompt`、`suffix`、`token_text`、`raw_output`、`guard_raw_output`、`query_text`。

## 11. 文件边界

计划新增独立模块，不修改现有冻结报告生成逻辑：

```text
backend/app/evaluation/ablation.py       # 契约、运行点选择与聚合指标
backend/app/evaluation/ablation_io.py    # manifest/profile/report 严格加载
scripts/audit_ablation_sources.py        # 来源与哈希审计
scripts/evaluate_agent_ablation.py       # 受保护缓存到聚合报告
data/agent-ablation-v1-manifest.json     # 无 Prompt 的冻结清单摘要
data/agent-ablation-v1-report.json       # 聚合结果
tests/unit/test_ablation_evaluation.py
tests/unit/test_ablation_io.py
tests/unit/test_ablation_cli.py
```

现有 `backend/app/evaluation/service.py`、evaluation API、前端 types/page/test 只做向后兼容的可选节点扩展。报告不存在或无效时，基础评测与分析页面仍然可用。

## 12. 验收标准

- 生产融合规则、CPD calibration 和 schema v2 报告哈希保持不变；
- 同一缓存输入重复运行得到字节一致的聚合报告；
- calibration/dev/test 的 group ID 交集均为空；
- 所有运行点只由 dev 选择，test runner 不含选择分支；
- 主报告同时包含两类 positive、两类 negative 和三路消融；
- 有来源证据的攻击族才进入正式指标，缺失族明确列入 coverage gap；
- 聚合报告、API、SQLite、日志和 Git 中保护 Prompt 命中数均为 0；
- 所有新增单元、集成、前端测试通过，生产构建成功；
- AutoDL 无 OOM，失败样本和 Guard unavailable 均被显式统计。

## 13. 比赛表述边界

本实验可以支持“融合智能体覆盖互补风险信号”的工程结论，但只有当冻结 test 数据真实显示改善时，才能声称融合优于单路方法。若融合召回提升伴随 FPR 超标，必须同时披露；若某攻击族没有合规数据源，只能表述为待验证覆盖，不能声称已经检出。
