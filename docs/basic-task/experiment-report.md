# Entropy-CPD 基础任务实验报告

## 1. 实验问题

在大模型入口，Token entropy 的在线变化点能否检测并定位优化型 jailbreak 后缀？与整句和局部 NLL 基线相比，它的检测与定位能力分别如何？

## 2. 实验设置

- 模型：Qwen2.5-7B-Instruct
- GPU：RTX 4090 D 24GB
- 数据与算法参考：CPDonline
- 固定 commit：`1a6c055865c44cc1d10dfbe5d014576c7331322e`
- split seed：`competition-v1`
- 测试集：663 条，攻击 460、无害 203
- 攻击族：GCG 129、AutoDAN 150、AdvPrompter 181
- 未评测：BEAST、AutoDAN-HGA
- 报告校准版本：`qwen25-7b-cpd-paper-v2`
- 数据集聚合哈希：`sha256:04dafc596457da35efd8458fc51a3f3200602f5476d9b43ebcaaad563d9ff730`

所有方法复用同一批 `ModelObservation`。阈值和窗口只使用 calibration/dev；test 仅在参数冻结后评估。

## 3. 总体结果

F1 最优工作点：

| 方法 | F1 | AUROC | FPR |
| --- | ---: | ---: | ---: |
| Global NLL | 0.96996 | 0.99149 | 9.85% |
| Window NLL | 0.98158 | 0.99301 | 4.93% |
| Entropy-CPD | 0.83270 | 0.72016 | 75.86% |

开发集选择的低误报工作点在冻结 test 上：

| 方法 | F1 | Recall | FPR |
| --- | ---: | ---: | ---: |
| Global NLL | 0.96732 | 0.96522 | 6.90% |
| Window NLL | 0.98073 | 0.99565 | 7.88% |
| Entropy-CPD | 0.60340 | 0.46304 | 16.26% |

“低误报”表示阈值在 development 上按目标 FPR 选择，不表示 test 一定低于 10%。

## 4. 分攻击族召回

Entropy-CPD 的 F1 最优工作点：

| 攻击族 | 检出/总数 | Recall |
| --- | ---: | ---: |
| GCG | 129/129 | 100.00% |
| AutoDAN | 136/150 | 90.67% |
| AdvPrompter | 173/181 | 95.58% |

完整三方法逐族数据由 Web 评测中心直接读取 schema v2 报告。

## 5. 定位能力

只有 Entropy-CPD 产生变化点：

- onset MAE：39.68 Token
- trigger in suffix rate：62.61%

Global NLL 和 Window NLL 是 Prompt 级分数，不报告 CPD 起点定位。

## 6. 结论

本实验不支持“CPD 分类性能优于 NLL 基线”的表述。相反，Global NLL 与 Window NLL 在当前跨模型 CPDonline 数据上显著优于 Entropy-CPD 的整句分类，并且 CPD 的测试误报偏高。

Entropy-CPD 的独特价值是在线累积证据和 Token 级起点定位。因此基础创新应表述为：

> 把固定 system Prompt 熵基线的在线变化点检测接入大模型入口，形成 Token 异常定位、模式感知处置、脱敏审计和受保护真实样本演示闭环。

它不能表述为发明 CPD、准确识别所有 jailbreak 或低误报生产防火墙。

## 7. 语义融合功能验收

基础链路额外接入第三方 Qwen3Guard-Gen-0.6B，以解决“没有 Token 突变的直接危险请求可能被 CPD 放行”的缺口。固定策略不学习测试标签：unsafe 拦截，controversial 复核；safe 时再依据 CPD 与 analysis/gateway 模式处置。

AutoDL 受保护烟测包含 3 条直接危险、1 条普通安全、1 条争议上下文和 1 条无害格式突变，语义与动作预期 6/6，错误 0。另对 GCG、AutoDAN、AdvPrompter 各抽 3 个冻结 ID，9/9 得到语义拦截、CPD 候选和脱敏定位证据。

这些结果只证明链路按设计工作。当前没有独立冻结语义测试集，不能据此报告 Qwen3Guard 的准确率、召回率或 F1，也不能把第三方模型本身作为原创算法。

## 8. 后续进阶

进阶任务应建设独立冻结语义评测集，加入知识库证据、反事实复核或人工反馈闭环，重点量化误报并区分“无害分布突变”与“带攻击意图的异常后缀”。任何可学习融合权重仍需在 calibration/dev 冻结，不能根据 test 标签调参。

当前项目已完成其中第一阶段：离线官方知识快照、冻结检索评测和有引用报告。该层在基础动作之后运行，实测 off/report 动作一致率为 100%，因此不修改本报告任何 CPD/NLL 冻结指标。知识检索结果与限制见 `docs/advanced-task/experiment-report.md`。
