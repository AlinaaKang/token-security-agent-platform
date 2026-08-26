# 基础任务收口 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将已验证的 Entropy-CPD 研究基线完成为符合赛题基础任务要求的可运行、可评测、可审计、可脱敏演示安全智能体。

**Architecture:** 保持现有 Qwen 单次前向观测和 Entropy-CPD 不变，在 API 外围增加显式检测语义、SQLite 脱敏事件、隐私安全评测报告服务和受保护真实样本服务。冻结基准复用同一批 `ModelObservation` 同时计算 Global NLL、Window NLL 和 Entropy-CPD，前端三个页面只消费安全 API，不读取原始 CSV。

**Tech Stack:** Python 3.11/3.12、FastAPI、Pydantic v2、SQLite、PyTorch/Transformers、pytest、React 19、TypeScript、Vite、Vitest。

## Global Constraints

- 完整 Prompt、suffix 和 Token 文本不得进入 Git、测试 fixture、日志、评测报告、事件数据库和截图。
- CPDonline 是唯一署名的 CPD 算法与首批数据参考，commit 固定为 `1a6c055865c44cc1d10dfbe5d014576c7331322e`。
- calibration/dev/test 保持 group-aware 冻结隔离，test 标签不得用于选择阈值、窗口或 `k`。
- `score < h` 不得产生 CPD 告警或 CPD-only block。
- 页面必须把 `token_anomaly_candidate` 与已确认 jailbreak 区分；基础任务的语义确认固定为 `not_performed`。
- BEAST 和 AutoDAN-HGA 保持 `not_evaluated`。
- PCAP、RAG、语义复核、ReAct 和 NLL/Entropy 融合不进入本计划。
- 使用现有 `feature/basic-platform-foundation` 工作区，不撤销用户已有改动。
- Git 作者身份未配置时只保留文件级变更和验证证据，不编造身份提交。

---

### Task 1: 显式检测语义与模式感知处置

**Files:**
- Modify: `backend/app/schemas.py`
- Modify: `backend/app/agent/workflow.py`
- Modify: `tests/integration/test_basic_workflow.py`
- Modify: `tests/unit/test_schemas.py`

**Interfaces:**
- Produces: `DetectorStatus = Literal["no_token_anomaly", "token_anomaly_candidate"]`
- Produces: `AnalysisResult.detector_status`, `semantic_verification`, `detector_score`, `audit_persisted`
- Consumes: `AnalysisRequest.mode`, `CPDTrace.score`, `CPDTrace.alarm_index`

- [ ] **Step 1: 写模式与语义红灯测试**

在 `tests/integration/test_basic_workflow.py` 增加无害 synthetic token 测试：同一条达到 `h` 的观测在 `analysis` 模式返回 `block`，在 `gateway` 模式返回 `review`；两者均返回 `detector_status="token_anomaly_candidate"`、`semantic_verification="not_performed"` 和原始 `detector_score`。增加低于 `h` 时 `detector_status="no_token_anomaly"` 且不能 block 的断言。

```python
gateway = workflow.analyze(
    AnalysisRequest(prompt="A redacted test example", model_id="qwen-model", mode="gateway"),
    request_id="req-gateway",
)
assert gateway.decision.value == "review"
assert gateway.detector_status == "token_anomaly_candidate"
assert gateway.semantic_verification == "not_performed"
```

- [ ] **Step 2: 运行红灯测试**

Run:

```powershell
$env:PYTHONPATH='.localdeps'
python -m pytest tests/integration/test_basic_workflow.py tests/unit/test_schemas.py -q
```

Expected: FAIL，因为 `AnalysisResult` 尚无显式检测与语义字段，gateway 仍按分析模式 block。

- [ ] **Step 3: 实现最小模式感知工作流**

在 `schemas.py` 添加字段：

```python
detector_status: Literal["no_token_anomaly", "token_anomaly_candidate"]
semantic_verification: Literal["not_performed"] = "not_performed"
detector_score: float = Field(ge=0)
audit_persisted: bool = False
```

在 `workflow.py` 以 `trace.alarm_index is not None` 为唯一 CPD 告警事实；gateway 告警强制 `Action.REVIEW`，analysis 告警保留实验 `Action.BLOCK`，无告警最大只能 `Action.REVIEW`。

- [ ] **Step 4: 验证 Task 1**

运行 Task 1 测试和完整后端测试。Expected: 全部通过，本机 GPU 集成测试仅因未配置模型而 skip。

- [ ] **Step 5: 记录提交边界**

```powershell
git add backend/app/schemas.py backend/app/agent/workflow.py tests/integration/test_basic_workflow.py tests/unit/test_schemas.py
git commit -m "feat: distinguish token anomalies from verified jailbreaks"
```

若 Git 身份仍未配置，保留 staged 变更并记录阻塞，不设置虚假身份。

---

### Task 2: SQLite 脱敏安全事件审计

**Files:**
- Create: `backend/app/audit/__init__.py`
- Create: `backend/app/audit/models.py`
- Create: `backend/app/audit/store.py`
- Create: `backend/app/api/events.py`
- Create: `tests/unit/test_event_store.py`
- Create: `tests/integration/test_events_api.py`
- Modify: `backend/app/api/analyze.py`
- Modify: `backend/app/main.py`
- Modify: `backend/app/bootstrap.py`
- Modify: `.gitignore`

**Interfaces:**
- Produces: `SecurityEvent`, `EventPage`, `SQLiteEventStore.append(event)`、`SQLiteEventStore.list_events`
- Produces: `GET /api/v1/events?limit=50&offset=0&decision=&detector_status=`
- Consumes: `AnalysisResult.detector_score`, Prompt SHA-256、`AnalysisRequest.mode`

- [ ] **Step 1: 写事件隐私和分页红灯测试**

使用仅含安全占位文本的请求，断言数据库行包含 `prompt_sha256`、长度、score、status、decision、calibration version，但数据库文件字节中不包含 Prompt、`token_text` 或信号文本。插入三条事件后断言分页稳定按 `created_at DESC, request_id DESC`。

```python
assert page.total == 3
assert len(page.items) == 2
assert "SAFE_PRIVATE_PROMPT" not in database_path.read_bytes().decode("utf-8", errors="ignore")
```

- [ ] **Step 2: 运行红灯测试**

Run: `python -m pytest tests/unit/test_event_store.py tests/integration/test_events_api.py -q`

Expected: collection FAIL，因为 `app.audit` 和事件路由不存在。

- [ ] **Step 3: 实现事件模型与 SQLite store**

`SecurityEvent` 仅定义设计文档允许的字段。`SQLiteEventStore` 使用参数化 SQL，初始化单表和索引，`append` 每次事务提交，`list_events` 对 `limit` 限制 `1..100`、`offset >= 0`，筛选值使用枚举校验。

公开签名固定为 `append(self, event: SecurityEvent) -> None` 和
`list_events(self, *, limit: int, offset: int, decision: Decision | None = None, detector_status: DetectorStatus | None = None) -> EventPage`。

- [ ] **Step 4: 在分析路由写入审计**

工作流返回后，由 route 使用 `hashlib.sha256(payload.prompt.encode("utf-8"))` 创建事件。写入成功用 `result.model_copy(update={"audit_persisted": True})` 返回；写入失败返回检测结果但 `audit_persisted=false`，服务日志只记录 request ID 和异常类型。

- [ ] **Step 5: 初始化 store 和健康状态**

`ServiceConfig` 增加 `event_db_path: Path = Path("tmp/security-events.sqlite3")`，可由 `TOKEN_SECURITY_EVENT_DB_PATH` 覆盖。lifespan 创建 store、挂到 `app.state.event_store`，health 增加 `audit: {ready, storage}`。

- [ ] **Step 6: 验证 Task 2**

运行事件单元/集成测试、分析 API 测试和完整后端测试；再扫描测试数据库确认安全占位 Prompt 不存在。

- [ ] **Step 7: 记录 Task 2 提交边界**

暂存 `backend/app/audit/`、事件路由、bootstrap/main、相关测试和 `.gitignore`；Git 身份可用时提交 `feat: add privacy-safe security event audit`，否则保留验证记录。

---

### Task 3: 隐私安全评测报告服务与 API

**Files:**
- Create: `backend/app/evaluation/service.py`
- Create: `backend/app/api/evaluation.py`
- Create: `tests/unit/test_evaluation_service.py`
- Create: `tests/integration/test_evaluation_api.py`
- Modify: `backend/app/main.py`
- Modify: `backend/app/bootstrap.py`
- Modify: `backend/app/evaluation/reporting.py`

**Interfaces:**
- Produces: `EvaluationSummary`, `EvaluationReportService.load()`
- Produces: `GET /api/v1/evaluation/summary`
- Consumes: `benchmark_report.json` schema v2 and active calibration version

- [ ] **Step 1: 写安全加载红灯测试**

用手工安全 JSON fixture 断言 loader 返回 counts、methods、families、not_evaluated、provenance。分别注入任意层级的 `prompt`、`suffix_text`、`token_text` key，要求 `UnsafeReportError`。校准版本不同时返回 `deployment_match=false`。

```python
with pytest.raises(UnsafeReportError, match="forbidden field"):
    EvaluationReportService(path).load(active_calibration_version="cal-v2")
```

- [ ] **Step 2: 运行红灯测试**

Run: `python -m pytest tests/unit/test_evaluation_service.py tests/integration/test_evaluation_api.py -q`

Expected: collection FAIL，因为 service 和 route 不存在。

- [ ] **Step 3: 实现递归安全校验和 schema**

loader 先递归拒绝 forbidden keys，再用 Pydantic 验证 schema v2、有限数值、非负 counts 和唯一 method ID。`TOKEN_SECURITY_BENCHMARK_REPORT_PATH` 未配置或文件不存在时 API 返回 `503 evaluation_unavailable`，不伪造空数据。

- [ ] **Step 4: 接入 main 与 health**

lifespan 初始化 `evaluation_service`，health 增加 `evaluation: {ready, report_version, deployment_match}`。评测接口每次读取不可变小 JSON，保证远端替换报告后无需重启模型。

- [ ] **Step 5: 验证 Task 3**

运行 Task 3 测试、health 测试和完整后端测试；使用当前安全报告验证旧 schema 会明确拒绝或由兼容迁移函数转换，不能静默丢失方法字段。

- [ ] **Step 6: 记录 Task 3 提交边界**

暂存评测 service、route、schema/reporting 改动及测试；Git 身份可用时提交 `feat: expose privacy-safe evaluation results`。

---

### Task 4: 三方法冻结基准与 schema v2 报告

**Files:**
- Create: `backend/app/evaluation/methods.py`
- Create: `tests/unit/test_evaluation_methods.py`
- Modify: `backend/app/detection/baselines.py`
- Modify: `backend/app/evaluation/reporting.py`
- Modify: `scripts/benchmark_cpdonline.py`
- Modify: `tests/unit/test_benchmark_cli.py`
- Modify: `tests/unit/test_reporting.py`
- Modify: `data/README.md`

**Interfaces:**
- Produces: `MethodProfile(method_id, threshold, low_fpr_threshold, window_size)`
- Produces: `fit_global_nll`、`fit_window_nll`、`score_method`
- Produces: report schema v2 `methods.global_nll`, `methods.window_nll`, `methods.entropy_cpd`
- Consumes: calibration/dev/test `ModelObservation` already calculated by benchmark

- [ ] **Step 1: 写方法选择红灯测试**

用手工 NLL 序列证明 Global NLL 在 calibration 选 F1 threshold；Window NLL 只能从 `(8, 16, 32)` 中用 development F1、较低 FPR、较大窗口依次 tie-break；test 参数不出现在 fit 函数签名。

```python
profile = fit_window_nll(calibration, calibration_labels, development, development_labels)
assert profile.window_size in {8, 16, 32}
```

- [ ] **Step 2: 运行红灯测试**

Run: `python -m pytest tests/unit/test_evaluation_methods.py -q`

Expected: collection FAIL，因为 `app.evaluation.methods` 不存在。

- [ ] **Step 3: 实现确定性方法 profile**

Global NLL 使用 mean NLL；Window NLL 使用最大固定窗口 mean NLL。每个 calibration 候选用现有 `select_f1_threshold`；低 FPR 阈值只在 development 用 `select_threshold_at_max_fpr(max_fpr=0.10)` 选择。拒绝空、非有限和混合 runtime identity 观测。

- [ ] **Step 4: 写 schema v2 红灯测试**

扩展 `test_reporting.py`，断言三个 method 都有 overall 双工作点和逐族 recall；只有 Entropy-CPD 有 localization；序列化结果不包含测试 Prompt 与 suffix。

- [ ] **Step 5: 扩展 benchmark CLI**

复用一次模型观测：calibration/dev/test 不增加模型 forward。先 fit 三个 method profile，再统一 test scoring；写入：

```json
{
  "schema_version": 2,
  "methods": {
    "global_nll": {},
    "window_nll": {},
    "entropy_cpd": {}
  }
}
```

CLI stdout 仅输出 paths、counts、method metrics、checksums，不输出异常文本。

- [ ] **Step 6: 本地验证 Task 4**

运行 methods、reporting、CLI 和完整后端测试；递归扫描生成 fixture，forbidden key count 必须为 0。

- [ ] **Step 7: AutoDL 重跑冻结基准**

同步代码后运行一次 benchmark。运行前记录现有报告 hash；运行中监控进程；失败时先诊断再重跑。验证 split ID 零交集、数据 hash 不变、三方法 test count 均为 663、CPD 指标与 v1 允许浮点精度内一致。

- [ ] **Step 8: 记录 Task 4 提交边界**

暂存 methods、baseline/reporting/benchmark 改动、测试和数据说明；Git 身份可用时提交 `feat: benchmark cpd against frozen nll baselines`。

---

### Task 5: 受保护真实样本 ID 演示

**Files:**
- Create: `backend/app/demo/__init__.py`
- Create: `backend/app/demo/service.py`
- Create: `backend/app/api/demo.py`
- Create: `tests/unit/test_demo_service.py`
- Create: `tests/integration/test_demo_api.py`
- Modify: `backend/app/main.py`
- Modify: `backend/app/bootstrap.py`
- Modify: `backend/app/schemas.py`

**Interfaces:**
- Produces: `DemoSampleSummary`, `DemoAnalysisResult`, `DemoSampleService`
- Produces: `GET /api/v1/demo-samples`
- Produces: `POST /api/v1/demo-samples/{sample_id}/analyze`
- Consumes: CPDonline raw paths、report provenance hashes、现有 `BasicSecurityWorkflow`

- [ ] **Step 1: 写目录约束与脱敏红灯测试**

安全 synthetic CSV 使用占位内容。断言只列出 frozen test attack IDs；未知 ID、benign ID、非 test ID 均返回 404；分析响应所有 `signal.token_text == ""`，序列化结果不含源 Prompt/suffix。

- [ ] **Step 2: 运行红灯测试**

Run: `python -m pytest tests/unit/test_demo_service.py tests/integration/test_demo_api.py -q`

Expected: collection FAIL，因为 demo service 不存在。

- [ ] **Step 3: 实现只读样本服务**

复用 CPDonline adapters 和 `split_by_group(seed="competition-v1")`。初始化时验证三个 source file SHA-256 与报告 provenance 完全一致，只保留 test attack 记录的 sample ID 映射。服务方法不接受路径参数：

公开签名固定为
`list_samples(self, *, family: str | None, limit: int) -> list[DemoSampleSummary]`
和 `analyze(self, sample_id: str, workflow: BasicSecurityWorkflow) -> DemoAnalysisResult`。

- [ ] **Step 4: 实现脱敏 route**

route 调用同一 workflow 后，用 `model_copy(update={"token_text": ""})` 清空所有 signal 文本；返回 sample ID、family、split、dataset commit 和分析结果。演示调用不写普通事件库。

- [ ] **Step 5: 配置与降级**

只有三个 `TOKEN_SECURITY_DEMO_*_CSV` 和评测报告均配置时启用。未配置返回 `503 demo_unavailable`，health 独立报告 `demo.ready=false`，不影响主分析。

- [ ] **Step 6: 验证 Task 5**

运行 demo 测试和完整后端测试；对序列化响应和日志执行 Prompt/suffix/token text 泄漏扫描。

- [ ] **Step 7: 记录 Task 5 提交边界**

暂存 demo service、route、schemas/bootstrap/main 改动和测试；Git 身份可用时提交 `feat: add redacted frozen-sample demonstrations`。

---

### Task 6: 三个 Web 页面接入真实功能

**Files:**
- Create: `frontend/src/api.ts`
- Create: `frontend/src/types.ts`
- Create: `frontend/src/pages/AnalyzePage.tsx`
- Create: `frontend/src/pages/EventsPage.tsx`
- Create: `frontend/src/pages/EvaluationPage.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/App.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: Task 1/2/3/5 API schemas
- Produces: 可访问的分析、事件、评测页面和真实样本选择器

- [ ] **Step 1: 写前端红灯测试**

mock 完整真实响应，断言：分析页显示“Token 异常候选”和“未进行语义确认”；gateway 只显示人工复核；事件页显示 hash 前缀、score、动作且不出现 Prompt；评测页显示 663、三种方法、两种工作点和 `not_evaluated`；demo 选择器仅显示 sample ID/family。

- [ ] **Step 2: 运行红灯测试**

Run: `npm.cmd test -- --run`

Expected: FAIL，因为事件和评测仍是占位表，分析响应没有新语义字段。

- [ ] **Step 3: 拆分 API、types 和页面**

`api.ts` 统一处理非 2xx 的 `{error:{code,message}}`；三个 page 各自管理 loading/error/empty 状态。`App.tsx` 只保留 Shell、navigation 和 Routes，避免继续扩大单文件。

- [ ] **Step 4: 实现评测和事件视图**

评测表并列三方法的 F1、AUROC、FPR、逐族 recall；明确低 FPR 阈值“在开发集选择”。事件表不显示 Prompt 列，只显示时间、request ID、hash 前 12 位、状态、score、动作和校准版本。

- [ ] **Step 5: 实现分析与 demo 视图**

普通输入保留 Token 风险轨道；demo 结果使用编号块和统计量，不渲染 token text。页面把实验 `block` 展示为“实验阈值拦截”，并单列“语义确认：未执行”。

- [ ] **Step 6: 响应式与可访问性验证**

运行 Vitest 和 Vite build；启动 preview 后用 Playwright 在 1440x900、390x844 截图，检查无重叠、表格可滚动、按钮文本不溢出、键盘焦点可见。截图只能使用安全 synthetic Prompt，禁止真实攻击原文。

- [ ] **Step 7: 记录 Task 6 提交边界**

暂存前端 API、types、pages、App、样式和测试；Git 身份可用时提交 `feat: connect competition workflows to live evidence`。

---

### Task 7: 文档、部署和基础任务最终验收

**Files:**
- Modify: `README.md`
- Create: `docs/basic-task/design.md`
- Create: `docs/basic-task/development.md`
- Create: `docs/basic-task/test-report.md`
- Create: `docs/basic-task/experiment-report.md`
- Create: `docs/basic-task/demo-script-3min.md`
- Modify: `docker-compose.yml`
- Modify: `data/README.md`

**Interfaces:**
- Consumes: 最终 API、schema v2 报告、AutoDL 聚合结果
- Produces: 与系统一致的比赛文档和三分钟演示脚本

- [ ] **Step 1: 更新 README 事实状态**

删除“模型与检测器尚未接入”，写明本地 Web、AutoDL 模型、环境变量、三方法基准命令、隐私边界和当前限制。不得把 CPD alarm 称为 confirmed jailbreak。

- [ ] **Step 2: 编写四类提交文档**

设计文档描述模块与数据流；开发文档列出 Python/Node/AutoDL 运行步骤；测试报告记录自动测试命令和最新通过数量；实验报告记录数据 hash、split、三方法结果、逐族指标、FPR、定位和未评测族。

开发文档单列“平台合规边界”：附赛事方允许自研平台替代的书面确认位置；在未取得可归档凭证前，不写成已经满足“基于深信服 AI 安全平台”的原始要求。

- [ ] **Step 3: 编写三分钟演示脚本**

时间分配固定为：20 秒痛点、30 秒架构、60 秒普通/真实 ID 对照、40 秒 Token 定位、30 秒三方法评测、20 秒局限与进阶。真实攻击只显示 sample ID、family 和统计结果。

- [ ] **Step 4: AutoDL 部署**

设置 calibration、benchmark report、event DB 和 demo CSV 环境变量；重启 API；确认 health 的 model/detector/audit/evaluation/demo 全部 ready。保持 SSH tunnel 和前端代理可用。

- [ ] **Step 5: 最终验证**

依次运行：

```powershell
$env:PYTHONPATH='.localdeps'
python -m pytest -q
Set-Location frontend
npm.cmd test -- --run
npm.cmd run build
```

再验证 `/health`、普通安全分析、gateway anomaly review、事件分页、评测 summary、三族真实 demo 各三次。递归检查报告、数据库、日志和截图没有 raw Prompt/suffix/token text。

- [ ] **Step 6: 完成标准审计**

逐条核对 spec 的六个基础任务门槛和赛题提交材料。任何失败项保持未完成，不用页面占位或文字包装替代功能。

- [ ] **Step 7: 记录 Task 7 提交边界**

暂存 README、基础任务文档、compose 和数据说明；Git 身份可用时提交 `docs: complete basic-task delivery evidence`。
