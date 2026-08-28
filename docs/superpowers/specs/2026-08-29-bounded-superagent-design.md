# 有界 SuperAgent 自主闭环设计

## 1. 目标

在不改动基础检测结论、不接触原始 Prompt、攻击 suffix、Token 文本或隐藏推理的前提下，为现有安全分析和攻防实验舱增加一个独立的 SuperAgent 任务入口。它接收脱敏场景和高层目标，自主组织证据分析、响应规划、平台内部工具执行、结果观察与一次确定性重规划，形成可审计闭环。

该能力对应赛题挑战任务中的复杂逻辑推理、跨组件协同、工具调用、观察反馈和 ReAct 闭环。当前实现是自研平台内部仿真闭环，不声明已连接深信服平台、防火墙、EDR、SIEM 或外部工单系统。

## 2. 方案选择

### 方案 A：固定顺序自动执行

完成检测后依次运行三个工具。实现简单，但没有根据观察结果调整计划，不能充分证明 ReAct 或自主协调。

### 方案 B：确定性有界 ReAct 状态机（采用）

先建立通用调查计划，调用现有语义、Token、知识和反事实链路，观察结构化结果，再根据不可变基础动作选择内部工具。工具执行后再次观察回执并形成闭环结论。状态机最多一次重规划、三个工具调用，行为可复现、可测试、可解释。

### 方案 C：自由 LLM Planner

由大模型自由生成计划和工具参数。展示效果强，但存在提示注入、越权调用、结果漂移和不可稳定复现的问题，不适合当前比赛原型的自动处置边界。

## 3. 范围

第一版支持现有实验舱的合成安全、无害格式突变、直接危险、GCG、AutoDAN 和 AdvPrompter 脱敏场景。用户只选择场景、工作模式和固定高层目标 `investigate_and_respond`，不向 SuperAgent 提交自由文本命令。

SuperAgent 复用以下真实组件：

- Qwen3Guard 语义安全证据；
- Qwen2.5-7B Entropy-CPD Token 分布证据；
- official-v2 知识证据与确定性报告回退；
- 反事实截断重检；
- 平台内部网关状态、安全工单和证据包工具；
- SQLite 工具回执和证据摘要。

不在本版本接入 PCAP、终端遥测、真实日志、在线搜索、外部网络工具或模型自由工具选择。跨域协同指平台内语义、Token、知识、反事实与响应工具的跨组件协同，不表述为真实企业多源设备联动。

## 4. 状态机

每个任务遵循固定阶段：

1. `plan`：协调员建立“收集语义、Token、知识和反事实证据，再根据基础动作选择处置工具”的初始计划。
2. `act`：调用现有 `LabService.create_run`，只提交场景 ID、场景种类和模式。
3. `observe`：记录脱敏检测状态、证据一致/冲突、反事实解释和知识状态。
4. `replan`：根据不可变基础动作生成最终工具序列。
5. `act`：以 SuperAgent 内部策略授权执行工具，每种工具至多一次，幂等键由任务 ID 和工具 ID 确定性派生。
6. `observe`：核验工具回执的来源动作、有效动作、状态和证据摘要；不读取外部系统状态。
7. `complete`：输出 `closed_safe`、`contained`、`review_required` 或 `degraded` 之一。

工具策略固定如下：

| 基础动作 | 自动工具序列 | 闭环状态 |
| --- | --- | --- |
| `allow` | 不执行处置工具 | `closed_safe` |
| `review` | `security_case`、`evidence_bundle` | `review_required` |
| `sanitize_recheck` | `security_case`、`evidence_bundle` | `review_required` |
| `block` | `gateway_enforcement`、`security_case`、`evidence_bundle` | 全部成功为 `contained`，否则为 `degraded` |

若任一工具失败，状态机不降低基础动作、不改为放行，也不无限重试；它记录失败观察并将最终状态设为 `degraded`。执行总数上限为 3，任务事件上限为 12。

## 5. 可审计轨迹

前端展示结构化决策轨迹，不展示模型隐藏思维链。每条事件只包含：顺序号、阶段、角色、摘要、依据代码、可选工具 ID 和结果状态。

角色固定为：

- `coordinator`：初始计划、重规划和闭环总结；
- `semantic_analyst`：语义等级和类别；
- `token_analyst`：CPD 状态和脱敏异常起点；
- `knowledge_analyst`：知识状态和真实 `knowledge_id`；
- `response_operator`：平台内部工具执行和回执观察。

摘要由确定性模板生成。API 不返回 Prompt、suffix、Token 文本/ID、检索词、模型原始输出、隐藏推理、私人路径或密钥。

## 6. API 与数据模型

新增接口：

- `POST /api/v1/superagent/missions`：创建并同步完成一个有界任务，返回 201；
- `GET /api/v1/superagent/missions/{mission_id}`：在内存 TTL 内恢复任务；
- `GET /api/v1/superagent/capabilities`：返回固定目标、状态机上限和 `internal_only=true` 能力声明。

`SuperAgentMissionRequest` 只包含 `scenario_kind`、`sample_id`、`mode` 和固定 `objective`。`SuperAgentMissionResult` 包含任务 ID、实验舱 run ID、阶段事件、初始与最终计划、基础动作、最终状态、执行回执引用和限制声明。

任务结果使用独立内存 TTL Store 保存，不把完整事件轨迹写入 SQLite。工具执行仍由现有 SQLite 回执存储。刷新恢复只依赖脱敏任务 ID。

## 7. Web 体验

新增独立 `/super-agent` 页面，主导航名称为“自主处置”。页面不替换 `/analyze`、`/lab` 或 `/challenge`。

页面包含：

- 场景、工作模式和固定任务目标选择；
- “启动自主任务”命令；
- 七阶段横向/纵向自适应轨迹；
- 五个角色的当前状态；
- 基础动作、最终状态、工具回执和限制说明；
- 明确的“平台内部仿真闭环”标识。

桌面端使用紧凑工作台布局，移动端改为单列时间线。动画只用于已返回事件的短暂入场，不冒充实时模型推理；`prefers-reduced-motion` 下全部关闭。

## 8. 错误处理

- 依赖未就绪：503 固定 `superagent_unavailable`；
- 场景不存在或过期：复用脱敏固定错误，不回传内部异常；
- 工具存储不可用：任务保留基础动作，最终状态为 `degraded`；
- 任务过期：410 `superagent_mission_expired`；
- 非法目标、未知字段和自由文本命令：422；
- 隐私断言失败：任务失败并只记录错误类型，不记录匹配值。

## 9. 验收标准

1. `allow` 场景不执行任何处置工具并结束为 `closed_safe`。
2. `block` 场景按固定顺序执行三种内部工具，回执均绑定同一基础动作。
3. `review` 和 `sanitize_recheck` 不执行网关封禁，只创建工单和证据包。
4. 工具失败时不降低动作、不重试超过上限，最终状态为 `degraded`。
5. 每个任务恰好包含计划、行动、观察、重规划和完成阶段，事件不超过 12 条。
6. 所有公开响应通过现有 `assert_public_payload` 和敏感键扫描。
7. `/analyze`、`/lab`、`/challenge` 的既有测试和浏览器流程无回归。
8. AutoDL 实测 model、detector、semantic guard、knowledge、lab 和 superagent 全部 ready。

## 10. 声明边界

页面与文档只能声明“平台内部仿真自主闭环”和“结构化可审计决策轨迹”。不得声明展示完整隐藏 CoT，不得声明已经控制外部防火墙、EDR、SIEM 或工单系统，不得声明覆盖 BEAST、AutoDAN-HGA，也不得把挑战任务 10 分能力包装成基础检测准确率提升。
