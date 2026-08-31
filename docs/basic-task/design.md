# 基础任务系统设计

## 1. 场景与单一痛点

场景是企业大模型应用、知识助手或 API 网关收到用户 Prompt 的入口。单一痛点是：入口防护缺少兼顾“直接危险语义拦截”和“优化型后缀 Token 定位”的统一证据链。整句分类能判断危险但不能指出起点，纯 CPD 能发现分布变化却可能放过没有突变的直接危险请求。

系统目标不是识别所有 jailbreak，而是：

> 先拦截直接危险语义，再用模型内部 Token 分布变化发现优化型后缀异常候选并定位起点，最后以固定融合策略给出处置和脱敏证据。

## 2. 为什么是安全智能体

普通对话 AI 的目标是生成回答。本系统的目标是执行安全任务闭环：接收请求、调用模型观测工具、运行检测工具、根据模式选择动作、记录审计证据并返回可解释结果。它具有目标、工具、状态、决策和动作，因此是安全智能体；自然语言生成不是基础任务的核心。

## 3. 数据流

```text
自定义 Prompt
  -> FastAPI 请求校验
  -> Qwen3Guard-Gen-0.6B 严格两行分类
  -> 规范化 safe / controversial / unsafe / unavailable
  -> Qwen2.5-7B-Instruct 单次前向
  -> 每个用户 Token 的 entropy / NLL
  -> Page-CUSUM Entropy-CPD
  -> alarm、score、onset
  -> 固定证据融合
     unsafe=拦截，controversial=复核
     safe+alarm: analysis=实验拦截，gateway=人工复核
     safe+no alarm=放行
  -> SQLite 脱敏事件

冻结 sample ID
  -> 服务端只读目录解析
  -> 同一检测工作流
  -> 清空 token_text、token_id=0
  -> 浏览器显示 T0/T1/... 与统计证据

冻结评测
  -> 同一批 ModelObservation
  -> Global NLL / Window NLL / Entropy-CPD
  -> 聚合 schema v2 报告
  -> 评测中心
```

## 4. 模块边界

| 模块 | 职责 | 不允许 |
| --- | --- | --- |
| Model runtime | 生成用户 Token logits、entropy、NLL | 决策与审计 |
| Semantic Guard | 生成规范化语义等级和九类安全标签 | 保存原始输出、替代 CPD 定位 |
| Entropy-CPD | 计算累计统计量、告警与起点 | 语义确认 |
| Evidence fusion | 按固定真值表组合两路证据 | 以测试标签动态调权 |
| Workflow | 调用两路检测各一次并执行融合动作 | 读取冻结报告 |
| Event store | 保存哈希、规范化语义和检测元数据 | Prompt、Token 文本、Guard 原文、模型回答 |
| Evaluation service | 验证并读取聚合 schema v2 | 原始 CSV |
| Demo service | 通过受保护 ID 调用工作流 | 任意路径和非 test 样本 |
| React Web | 操作、展示证据和状态 | 读取攻击原文 |

## 5. 判定语义

- `semantic_severity=unsafe`：直接拦截，CPD 是否告警不覆盖该动作。
- `semantic_severity=controversial`：进入人工复核。
- `semantic_severity=safe`：继续依据独立 CPD 状态处置。
- `no_token_anomaly`：CPD 未越过 `h`；仅在语义安全时放行。
- `token_anomaly_candidate`：CPD 越过 `h`，仅表示 Token 分布异常候选。
- analysis 的 CPD 告警展示“实验阈值拦截”；gateway 展示“人工复核”。
- Guard 不可用时 gateway fail-safe 进入复核；analysis 无 CPD 告警时允许降级放行并明确标记不可用。

## 6. 隐私与失败边界

Guard 原始输出只存在于单次调用的局部变量中，严格解析失败即 `unavailable`，不得默认 safe。事件表只含 request ID、UTC 时间、Prompt SHA-256、长度、Token 数、规范化语义等级与类别、score、`k/h`、起点、融合原因、动作、模式、模型版本和延迟。评测加载器递归拒绝 `prompt`、`suffix`、`token_text`、`signals` 等字段。审计失败时检测仍返回，但必须标记 `audit_persisted=false`。

## 7. 基础与进阶边界

基础任务已经完成第三方语义 Guard、Token 观测、CPD 定位、固定证据融合、模式处置、冻结对照、脱敏审计和 Web 演示。独立冻结语义准确率评测、ReAct、BEAST 和 AutoDAN-HGA 仍未实现，不能虚报。

PCAP 安全预检是独立的证据可用性鉴定器，不进入基础或进阶冻结指标，不恢复 Prompt，不运行 Entropy-CPD，也不改变任何既有动作。完整 PCAP 到 Prompt/Token 的关联尚未实现；网络协议层结论不能替代模型内部 Token 证据。

项目的进阶任务已另行完成离线知识库与 RAG 证据层。基础 `AnalysisResult` 必须先完整生成，知识层随后才可检索最多 3 张官方知识卡并生成带真实 `knowledge_id` 的报告。检索、JSON、引用校验或生成超时失败时，基础动作、CPD 分数、异常起点和语义结果均保持不变。该层不进入基础任务算法与冻结指标。
