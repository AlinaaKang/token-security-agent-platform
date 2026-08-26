# 语义 Guard 与 Entropy-CPD 双证据融合设计

## 目标

在现有基础任务中增加独立语义安全检测，使平台能够拦截语义明确但 Token 分布平稳的直接危险请求，同时保留 Entropy-CPD 对优化型后缀的 Token 级异常检测和起点定位。

该扩展不改变基础任务的单一场景：大模型应用入口安全。它把入口风险拆成两个互补问题：

1. 请求内容本身是否具有危险意图；
2. 请求的 Token 分布是否出现优化型后缀变化。

## 方案选择

采用 Qwen3Guard-Gen-0.6B 与 Qwen2.5-7B Entropy-CPD 双模型全量执行。

- 语义模型：官方 `Qwen/Qwen3Guard-Gen-0.6B`。
- 来源：ModelScope 官方 Qwen 组织。
- 许可证：Apache-2.0。
- 权重：BF16，约 1.50GB。
- 运行要求：`transformers>=4.51.0`；AutoDL 当前为 4.57.6。
- 输出：`Safe`、`Controversial`、`Unsafe` 与规范化危险类别。

不采用两个备选方案：

- Guard 命中后短路：会丢失恶意请求的 CPD 证据，不利于比较两种检测机制。
- 关键词规则或复用主 7B 作为裁判：前者容易绕过，后者延迟高且结构化输出不稳定。

## 架构

```text
AnalysisRequest
  -> SemanticGuard.score(prompt)
       -> severity
       -> normalized categories
       -> guard model/version/latency
  -> QwenTokenRuntime.score_prompt(prompt)
       -> entropy / NLL
       -> Entropy-CPD score / alarm / onset
  -> EvidenceFusionPolicy.decide(mode, semantic, cpd)
  -> AnalysisResult
  -> privacy-safe event audit
```

两个检测器对每个正常分析请求都执行。第一版按顺序运行，避免同一 GPU 上并发推理引入显存峰值和调度不确定性。后续只有在测得瓶颈后才考虑独立进程或并发。

冻结 demo sample ID 继续调用同一工作流，不使用特殊判定捷径。浏览器仍不得接收攻击原文或 Token 文本。

## 语义 Guard 接口

新增独立模块 `backend/app/semantic/`：

```python
class SemanticSeverity(StrEnum):
    SAFE = "safe"
    CONTROVERSIAL = "controversial"
    UNSAFE = "unsafe"
    UNAVAILABLE = "unavailable"

class SemanticAssessment(BaseModel):
    severity: SemanticSeverity
    categories: list[SemanticCategory]
    model_id: str
    model_version: str
    latency_ms: float

class SemanticGuard(Protocol):
    def assess(self, prompt: str) -> SemanticAssessment: ...
```

危险类别采用固定白名单：

- `violent`
- `non_violent_illegal_acts`
- `sexual_content`
- `pii`
- `suicide_self_harm`
- `unethical_acts`
- `politically_sensitive`
- `copyright_violation`
- `jailbreak`

Guard 生成结果只允许解析前两行：

```text
Safety: Safe|Controversial|Unsafe
Categories: <comma-separated official categories>|None
```

缺少 severity、出现未知 severity、出现未知类别、超时、OOM 或运行异常都转换为 `unavailable`。不得把无法解析的文本猜成 safe。

## 分析响应

`AnalysisResult` 保留现有 CPD 字段并增加：

- `semantic_severity`
- `semantic_categories`
- `semantic_model_id`
- `semantic_model_version`
- `semantic_latency_ms`
- `semantic_verification` 扩展为 `performed | unavailable`
- `fusion_reason`

`detector_status` 继续只描述 CPD：

- `no_token_anomaly`
- `token_anomaly_candidate`

不得把 `semantic_severity=unsafe` 写成 CPD 告警，也不得把 CPD 告警写成已经语义确认的 jailbreak。最终 UI 分别显示两路证据。

## 融合规则

融合优先级从高到低固定如下：

| Semantic Guard | CPD | analysis | gateway | 原因 |
| --- | --- | --- | --- | --- |
| unsafe | 任意 | block | block | 明确语义危险 |
| controversial | 任意 | review | review | 上下文相关风险 |
| safe | anomaly candidate | block | review | 实验 CPD 告警 |
| safe | no anomaly | allow | allow | 两路证据均未告警 |
| unavailable | anomaly candidate | block | review | CPD 降级处置 |
| unavailable | no anomaly | allow | review | gateway 缺少语义防线，fail-safe review |

`fusion_reason` 使用固定枚举式文本，不生成自由文本：

- `semantic_unsafe`
- `semantic_controversial`
- `cpd_candidate`
- `all_clear`
- `semantic_unavailable_cpd_candidate`
- `semantic_unavailable_gateway_fail_safe`
- `semantic_unavailable_analysis_degraded`

## 模型运行与配置

新增环境变量：

- `TOKEN_SECURITY_GUARD_MODEL_PATH`
- `TOKEN_SECURITY_GUARD_MODEL_VERSION`
- `TOKEN_SECURITY_GUARD_MAX_INPUT_TOKENS`，默认 4096
- `TOKEN_SECURITY_GUARD_MAX_NEW_TOKENS`，默认 32

Guard 使用 `AutoTokenizer.apply_chat_template` 和确定性生成：

- `do_sample=False`
- `max_new_tokens<=32`
- 输入长度超限时明确返回请求错误，不静默截断安全关键内容。

主模型和 Guard 模型分别报告 readiness。健康检查增加：

```json
{
  "semantic_guard": {
    "ready": true,
    "model_id": "...",
    "model_version": "..."
  }
}
```

完整比赛部署要求 Guard ready。未配置 Guard 时允许开发环境启动，但健康状态必须 degraded，分析响应按 unavailable 融合规则处理。

## 审计与隐私

事件数据库新增：

- `semantic_severity`
- `semantic_categories`，保存排序后的固定类别标识
- `semantic_model_id`
- `semantic_model_version`
- `semantic_latency_ms`
- `fusion_reason`

禁止保存：

- Guard 原始生成文本；
- Prompt、Prompt 摘要或 suffix；
- Token 文本；
- 模型回答；
- 对危险请求的自然语言复述。

服务日志只允许 request ID、异常类型、模型 readiness 和耗时。数据库迁移必须兼容现有事件文件，通过显式 `ALTER TABLE` 增加可空字段；不得删除旧事件。

## Web 展示

分析页将“检测结论”拆成三段证据：

1. 语义安全：安全、争议、危险或不可用；
2. Token 分布：无异常或异常候选，包含 CPD score 和 onset；
3. 融合处置：放行、人工复核或拦截，并显示固定融合原因的中文标签。

危险类别用紧凑标签展示。Token 风险轨道保持为页面的主要证据带。页面不得显示 Guard 原始输出，也不得使用“已确认 jailbreak”，除非 Guard 明确返回 `jailbreak` 类别；即使如此，文案使用“语义类别：Jailbreak”，不声称覆盖所有攻击。

事件页新增语义状态、类别和融合原因，不新增 Prompt 列。评测页保留 CPD/NLL 冻结结果，另增加“语义 Guard 功能验收”区域，但在没有独立冻结语义数据集前不展示准确率、F1 或覆盖率。

## 错误处理

- Guard OOM：本次 assessment 为 unavailable；记录异常类型，不记录输入；健康状态在连续失败后降级。
- Guard 输出无法解析：unavailable，不默认 safe。
- Guard 输入超长：API 返回明确的 422，不截断后放行。
- 主模型失败：维持现有检测错误行为，不能只靠 Guard 伪造 CPD 结果。
- 审计写入失败：返回检测结果但 `audit_persisted=false`。
- 主 CPD 模型不可用：analysis 与 gateway API 都返回 503；gateway 适配层不得继续向业务模型转发请求。
- Guard 与主 CPD 模型都不可用：同样返回 503，不伪造 review、allow 或检测证据。

## 测试策略

所有实现遵循测试先行。

### 单元测试

- Guard 官方输出的三种 severity 和全部类别解析。
- 未知标签、未知类别、空输出和重复类别。
- 完整融合决策表。
- Guard runtime 的确定性生成参数和长度拒绝。
- SQLite 迁移、语义字段写入和原文泄漏扫描。

测试只使用安全占位字符串和手工构造的 Guard 输出，不把危险 Prompt 写入仓库。

### 集成测试

- safe + no CPD -> allow。
- unsafe + no CPD -> block，证明明显语义危险不依赖熵突变。
- safe + CPD candidate -> analysis block / gateway review。
- controversial -> review。
- Guard unavailable 的 analysis/gateway 降级。
- demo 响应仍清空 Token 文本和 Token ID。
- health 同时报告主模型、CPD、Guard、审计、评测和 demo。

### AutoDL 验收

- 下载并校验官方 Qwen3Guard-Gen-0.6B。
- 记录模型 revision、文件 SHA-256、显存增量和 P50/P95 延迟。
- 使用不进入 Git、日志和事件原文的受保护 smoke suite 验证：
  - 明确危险请求被 Guard 拦截；
  - 普通安全请求放行；
  - 无害分布异常在 gateway 进入 review；
  - GCG、AutoDAN、AdvPrompter sample ID 仍产生 CPD 证据。
- 只报告聚合计数、类别、动作和延迟，不报告危险原文。

## 验收标准

1. 明确危险且 CPD 平稳的请求最终为 block。
2. 普通安全且 CPD 平稳的请求最终为 allow。
3. 现有三族 CPD 冻结指标不因 Guard 接入而改变。
4. Web 同时显示语义证据、CPD 证据和融合原因。
5. 事件数据库、报告、日志、测试和截图不包含危险 Prompt 或 Guard 原始输出。
6. Guard 不可用时不默认 safe，gateway 采取 fail-safe review。
7. 文档明确 Qwen3Guard 是第三方工程安全层，Entropy-CPD 定位与证据融合才是本项目的研究贡献。

## 比赛表述

可以表述：

> 平台采用语义安全模型与 Token 变化点检测双通道：语义 Guard 处理直接危险意图，Entropy-CPD 处理优化型后缀异常与起点定位，智能体融合两路证据执行放行、复核和拦截。

不得表述：

- Qwen3Guard 是本项目原创；
- Entropy-CPD 能理解危险语义；
- 接入 Guard 后已经覆盖所有危险内容；
- 未经独立冻结评测的 Guard 准确率或 F1。
