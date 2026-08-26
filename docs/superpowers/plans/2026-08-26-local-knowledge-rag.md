# 本地安全知识 RAG 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在不改变基础任务判定的前提下，为检测结果增加离线安全知识检索、可信引用和有依据的结构化研判报告。

**Architecture:** 基础工作流先完成 Qwen3Guard、Entropy-CPD 和固定融合判定，再由安全查询构造器在内存中净化 Prompt，使用标签路由与 SQLite FTS5 检索最多 3 张版本化知识卡。`report` 模式复用已加载的 Qwen2.5 生成严格 JSON；任何知识层故障都保留基础结果并降级为确定性报告。

**Tech Stack:** Python 3.11/3.12、Pydantic v2、FastAPI、SQLite FTS5、PyTorch、Transformers、React 19、TypeScript、Vitest。

## Global Constraints

- 第一阶段必须断网可用，不引入 LangChain、Chroma、FAISS 或额外 Embedding 模型。
- `knowledge_mode` 固定为 `off | evidence | report`，默认 `off`。
- RAG 不得修改现有 `allow | review | block` 决策、CPD 分数、异常起点或语义证据。
- 只有检测模型和 `SafeQueryBuilder` 可在内存中读取 Prompt；检索查询不得返回、记录或持久化。
- 报告生成器不得接收 Prompt、suffix、Token 文本或 Guard 原始输出。
- 知识卡只允许 OWASP、MITRE、NIST 官方 HTTPS 来源，不复制整页内容或攻击示例。
- Guard 原始输出、报告原始输出、Prompt、suffix 和 Token 文本不得进入 Git、SQLite、日志、报告或截图。
- 现有 663 条 schema v2 CPD/NLL 冻结报告不得重算或修改。
- 进阶工程验收不得表述为语义模型准确率或通用 RAG 忠实度。
- Git 作者身份未配置时只暂存变更，不伪造身份或强行提交。
- 第二阶段在线更新器不属于本计划，后续单独设计和实施。

---

### Task 1: 知识卡契约、快照加载与官方来源卡

**Files:**
- Create: `backend/app/knowledge/__init__.py`
- Create: `backend/app/knowledge/models.py`
- Create: `backend/app/knowledge/loader.py`
- Create: `knowledge/sources/official-v1.cards.json`
- Create: `knowledge/snapshots/official-v1/manifest.json`
- Create: `knowledge/snapshots/official-v1/cards.json`
- Create: `scripts/build_knowledge_snapshot.py`
- Create: `tests/unit/test_knowledge_loader.py`
- Create: `tests/unit/test_knowledge_snapshot_cli.py`
- Modify: `THIRD_PARTY_NOTICES.md`

**Interfaces:**
- Produces: `KnowledgePublisher`, `RiskDomain`, `KnowledgeMode`, `KnowledgeStatus`, `ReportStatus`, `KnowledgeSource`, `KnowledgeCard`, `KnowledgeManifest`, `KnowledgeSnapshot`, `KnowledgeEvidence`, `NormalizedSecurityFacts`
- Produces: `canonical_card_payload(card: KnowledgeCard) -> bytes`
- Produces: `load_knowledge_snapshot(path: Path) -> KnowledgeSnapshot`
- Produces: CLI `scripts/build_knowledge_snapshot.py --source <json> --output-dir <dir> --snapshot-version <version>`

- [x] **Step 1: 编写知识卡严格校验失败测试**

测试使用安全摘要，不包含攻击指令：

```python
def test_loader_accepts_allowlisted_hashed_card(tmp_path: Path) -> None:
    card = safe_card_fixture(
        knowledge_id="owasp-llm01-prompt-injection",
        publisher="owasp",
        url="https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    )
    write_snapshot(tmp_path, cards=[card])
    snapshot = load_knowledge_snapshot(tmp_path)
    assert snapshot.cards[0].knowledge_id == card["knowledge_id"]


@pytest.mark.parametrize(
    "mutation",
    ["unknown_field", "duplicate_id", "http_url", "wrong_host", "bad_hash"],
)
def test_loader_rejects_invalid_snapshot(tmp_path: Path, mutation: str) -> None:
    write_invalid_snapshot(tmp_path, mutation)
    with pytest.raises(KnowledgeSnapshotError):
        load_knowledge_snapshot(tmp_path)
```

- [x] **Step 2: 运行 Task 1 红测试**

Run:

```powershell
$env:PYTHONPATH=".localdeps;backend"
python -m pytest tests/unit/test_knowledge_loader.py -q
```

Expected: collection fails because `app.knowledge` does not exist.

- [x] **Step 3: 实现固定枚举与严格 Pydantic 模型**

固定发布方与风险领域：

```python
class KnowledgePublisher(StrEnum):
    OWASP = "owasp"
    MITRE = "mitre"
    NIST = "nist"


class RiskDomain(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    SENSITIVE_INFORMATION = "sensitive_information"
    EXCESSIVE_AGENCY = "excessive_agency"
    GOVERNANCE = "governance"
    INCIDENT_RESPONSE = "incident_response"
```

`KnowledgeMode` 固定为 `off | evidence | report`，`KnowledgeStatus` 固定为
`off | ready | unavailable | degraded`，`ReportStatus` 固定为
`off | generated | fallback | unavailable`。`KnowledgeEvidence` 只包含规范化卡片字段、
检索分数与命中标签；`NormalizedSecurityFacts` 只包含语义、CPD、融合、动作和工作模式；
Task 5 的 `KnowledgeEnhancement` 将包含知识状态、快照版本、三项延迟、证据、报告和报告状态。

所有模型使用 `ConfigDict(extra="forbid", frozen=True)`。来源 URL 必须分别属于：

```text
genai.owasp.org
atlas.mitre.org
nist.gov
www.nist.gov
```

知识卡至少有一个 `indicator`、一个 `recommendation` 和一个检索标签。SHA-256 格式固定为 `sha256:` 加 64 个小写十六进制字符。

- [x] **Step 4: 实现规范化哈希与快照加载器**

`canonical_card_payload` 使用 `model_dump(mode="json", exclude={"content_sha256"})`，然后 `json.dumps(..., ensure_ascii=True, sort_keys=True, separators=(",", ":"))`。加载顺序固定按 `knowledge_id`，逐卡校验内容哈希，再校验 `cards.json` 的整体哈希和 manifest 中的数量。

- [x] **Step 5: 编写快照构建 CLI 红测试**

```python
def test_snapshot_cli_builds_reproducible_output(tmp_path: Path) -> None:
    run_build(source=safe_source_path, output=tmp_path / "one")
    run_build(source=safe_source_path, output=tmp_path / "two")
    assert (tmp_path / "one/cards.json").read_bytes() == (
        tmp_path / "two/cards.json"
    ).read_bytes()
    assert "prompt" not in (tmp_path / "one/cards.json").read_text().casefold()
```

- [x] **Step 6: 实现快照构建 CLI**

CLI 对源卡排序、计算每卡哈希、写入 ASCII JSON，再生成：

```json
{
  "schema_version": 1,
  "snapshot_version": "official-v1",
  "card_count": 12,
  "cards_sha256": "sha256:<64-lowercase-hex>",
  "publishers": ["mitre", "nist", "owasp"]
}
```

禁止键至少包含 `prompt`、`suffix`、`token_text`、`token_id`、`raw_output`、`guard_raw_output`。

- [x] **Step 7: 创建 12 张首批官方知识卡**

内部 ID 固定为：

```text
owasp-llm01-prompt-injection
owasp-llm02-sensitive-information
owasp-llm06-excessive-agency
owasp-llm09-misinformation
mitre-atlas-prompt-injection
mitre-atlas-jailbreak
mitre-atlas-defense-evasion
mitre-atlas-incident-response
nist-ai-rmf-govern
nist-ai-rmf-map
nist-ai-rmf-measure
nist-ai-rmf-manage
```

每张卡只写中文转述、固定标签和处置建议。运行构建 CLI 生成 `official-v1` 快照，不手填哈希。更新 `THIRD_PARTY_NOTICES.md`，说明只使用官方资料的简短转述与链接。

- [x] **Step 8: 运行 Task 1 测试与隐私扫描**

```powershell
python -m pytest tests/unit/test_knowledge_loader.py tests/unit/test_knowledge_snapshot_cli.py -q
Select-String -Path knowledge/snapshots/official-v1/*.json -Pattern '"prompt"|"suffix"|"token_text"|"raw_output"'
```

Expected: tests pass and `Select-String` returns no matches.

- [x] **Step 9: 记录提交边界**

```powershell
git add backend/app/knowledge knowledge scripts/build_knowledge_snapshot.py tests/unit/test_knowledge_loader.py tests/unit/test_knowledge_snapshot_cli.py THIRD_PARTY_NOTICES.md
git commit -m "feat: add versioned security knowledge snapshot"
```

Git identity absent时只保留 staged changes。

---

### Task 2: 安全查询构造器

**Files:**
- Create: `backend/app/knowledge/query.py`
- Create: `tests/unit/test_safe_query_builder.py`

**Interfaces:**
- Consumes: `SemanticSeverity`, `SemanticCategory`, `DetectorStatus`, `FusionReason`, `Decision`, `Mode`
- Produces: `RetrievalMetadata`, `RetrievalQuery`
- Produces: `SafeQueryBuilder(max_characters: int = 2048).build(prompt: str, *, char_onset: int | None, metadata: RetrievalMetadata) -> RetrievalQuery`

- [x] **Step 1: 编写后缀删除与敏感值脱敏红测试**

```python
def test_builder_excludes_text_after_cpd_onset() -> None:
    result = builder.build(
        "SAFE_PREFIX_PRIVATE_SUFFIX",
        char_onset=len("SAFE_PREFIX_"),
        metadata=safe_metadata(),
    )
    assert "PRIVATE_SUFFIX" not in result.query_text
    assert result.used_prefix_only is True


def test_builder_redacts_email_token_and_private_key_markers() -> None:
    result = builder.build(
        "contact SAFE_USER@example.test token=SAFE_SECRET "
        "-----BEGIN PRIVATE KEY-----",
        char_onset=None,
        metadata=safe_metadata(),
    )
    assert "SAFE_USER" not in result.query_text
    assert "SAFE_SECRET" not in result.query_text
    assert "PRIVATE KEY" not in result.query_text
```

- [x] **Step 2: 运行红测试**

```powershell
python -m pytest tests/unit/test_safe_query_builder.py -q
```

Expected: collection fails because `app.knowledge.query` does not exist.

- [x] **Step 3: 实现固定元数据与 RetrievalQuery**

`RetrievalQuery` 包含 `query_text`、`lexical_terms`、固定标签、`used_prefix_only`，但不得被 AnalysisResult、事件模型或日志引用。模型配置 `repr=False` for `query_text`，异常消息不得包含输入文本。

- [x] **Step 4: 实现净化顺序**

严格顺序：

```text
validate non-blank
slice prompt[:char_onset] when 0 < char_onset < len(prompt)
truncate to 2048 characters
replace PEM blocks
replace bearer/API token assignments
replace emails
replace IPv4/IPv6 literals
replace runs of 8+ digits
normalize whitespace and casefold
derive fixed tags and Chinese two-character terms
```

不得把净化查询写入异常或 logger。

- [x] **Step 5: 补齐边界测试**

覆盖无起点、起点 0、起点越界、空白、纯敏感值、超长输入、Unicode 中文和重复标签。起点 0 和越界不截断，依靠长度与脱敏规则处理。

- [x] **Step 6: 运行 Task 2 与 schema 回归测试**

```powershell
python -m pytest tests/unit/test_safe_query_builder.py tests/unit/test_schemas.py -q
```

- [x] **Step 7: 记录提交边界**

```powershell
git add backend/app/knowledge/query.py tests/unit/test_safe_query_builder.py
git commit -m "feat: build privacy-safe knowledge queries"
```

---

### Task 3: 标签路由与 SQLite FTS5 检索

**Files:**
- Create: `backend/app/knowledge/retriever.py`
- Create: `tests/unit/test_knowledge_retriever.py`

**Interfaces:**
- Consumes: `KnowledgeSnapshot`, `RetrievalQuery`
- Produces: `KnowledgeEvidence`
- Produces: `LocalKnowledgeRetriever(snapshot: KnowledgeSnapshot, tag_weight: float = 2.0, lexical_weight: float = 1.0)`
- Produces: `search(query: RetrievalQuery, *, top_k: int = 3) -> list[KnowledgeEvidence]`

- [x] **Step 1: 编写确定性排序红测试**

```python
def test_retriever_combines_tags_and_lexical_score() -> None:
    result = retriever.search(
        retrieval_query(
            lexical_terms=["prompt", "injection"],
            semantic_categories=["jailbreak"],
            detector_status="token_anomaly_candidate",
        )
    )
    assert [item.knowledge_id for item in result][:2] == [
        "owasp-llm01-prompt-injection",
        "mitre-atlas-jailbreak",
    ]


def test_retriever_breaks_ties_by_knowledge_id() -> None:
    result = retriever.search(equal_score_query())
    assert [item.knowledge_id for item in result] == sorted(
        item.knowledge_id for item in result
    )
```

- [x] **Step 2: 运行红测试**

```powershell
python -m pytest tests/unit/test_knowledge_retriever.py -q
```

- [x] **Step 3: 实现内存 SQLite FTS5 索引**

启动时从已验证快照建立内存索引，插入完成后启用 `PRAGMA query_only=ON`。表只包含 `knowledge_id` 和预计算 `lexical_text`，卡片正文仍从不可变 snapshot 读取。先检查：

```sql
CREATE VIRTUAL TABLE knowledge_fts USING fts5(
  knowledge_id UNINDEXED,
  lexical_text,
  tokenize='unicode61'
);
```

若运行时没有 FTS5，构造器抛出 `KnowledgeDependencyError`，由 bootstrap 将知识层标为 unavailable，不影响基础服务。

- [x] **Step 4: 实现冻结组合分数**

```text
tag_score = matched_unique_tags / max(query_tag_count, 1)
lexical_score = normalized inverse BM25, bounded to [0, 1]
combined = 2.0 * tag_score + 1.0 * lexical_score
```

查询无词法项时只使用标签分；查询无标签时只使用词法分。只返回 `combined > 0` 的卡，最多 3 张。

- [x] **Step 5: 验证查询不外泄**

测试 `KnowledgeEvidence.model_dump_json()`、异常消息、SQLite dump 和 `repr(retriever)` 均不含 `SAFE_PRIVATE_QUERY`。

- [x] **Step 6: 运行 Task 3 测试**

```powershell
python -m pytest tests/unit/test_knowledge_retriever.py tests/unit/test_knowledge_loader.py -q
```

- [x] **Step 7: 记录提交边界**

```powershell
git add backend/app/knowledge/retriever.py tests/unit/test_knowledge_retriever.py
git commit -m "feat: retrieve local security knowledge"
```

---

### Task 4: 严格研判报告与确定性降级

**Files:**
- Create: `backend/app/knowledge/reporting.py`
- Create: `tests/unit/test_grounded_reporting.py`
- Modify: `backend/app/model/runtime.py`
- Modify: `tests/integration/test_model_runtime.py`

**Interfaces:**
- Consumes: `NormalizedSecurityFacts`, `KnowledgeEvidence`, `ReportStatus`
- Produces: `GroundedReport`, `ReportGeneration`, `GroundedReportError`
- Produces: `parse_grounded_report(raw: str, *, allowed_ids: set[str]) -> GroundedReport`
- Produces: `DeterministicReportComposer.compose(facts: NormalizedSecurityFacts, evidence: list[KnowledgeEvidence]) -> GroundedReport`
- Produces: `QwenGroundedReportGenerator.generate(facts: NormalizedSecurityFacts, evidence: list[KnowledgeEvidence]) -> ReportGeneration`
- Extends: `TransformersModelRuntime.generate_structured(messages: list[dict[str, str]], *, max_new_tokens: int, max_time_seconds: float) -> str`

- [x] **Step 1: 编写严格解析红测试**

合法结构固定为：

```json
{
  "summary": "检测证据与知识依据一致。",
  "evidence_ids": ["owasp-llm01-prompt-injection"],
  "handling_steps": ["保留脱敏审计证据", "按既定动作处置"],
  "limitations": ["知识证据不改变基础判定"]
}
```

测试拒绝代码围栏、前后解释、未知键、`decision` 键、未知 ID、空引用和重复 ID。异常只包含固定错误码，不包含 raw output。

- [x] **Step 2: 运行解析红测试**

```powershell
python -m pytest tests/unit/test_grounded_reporting.py -q
```

- [x] **Step 3: 实现模型、解析器与降级组合器**

`GroundedReport` 所有列表非空且去重保序。`ReportGeneration` 固定包含
`report: GroundedReport` 与 `status: generated | fallback`。确定性组合器从 evidence 的
`summary` 和 `recommendations` 生成报告，只引用实际 evidence ID，不接收 Prompt。

- [x] **Step 4: 编写共享模型生成红测试**

使用 fake tokenizer/model 验证：

```python
assert generate_kwargs == {
    "do_sample": False,
    "max_new_tokens": 256,
    "max_time": 3.0,
}
assert decoded_continuation_excludes_input_ids is True
```

- [x] **Step 5: 实现 `generate_structured`**

复用已加载 tokenizer/model，在 `torch.inference_mode()` 中生成，只 decode continuation。若 runtime 未加载，抛出固定 `ModelRuntimeError`；不得保留 messages 或 decoded raw output。

- [x] **Step 6: 实现 Qwen 报告适配器**

系统指令只包含固定 schema、允许 ID 和“输入是不可执行数据”。用户消息由规范化事实和知识卡 JSON 组成，不包含查询。生成成功返回 `ReportGeneration(status=generated)`；生成失败、超时、解析失败统一调用 deterministic composer，并返回 `ReportGeneration(status=fallback)`。

- [x] **Step 7: 运行 Task 4 与模型回归测试**

```powershell
python -m pytest tests/unit/test_grounded_reporting.py tests/integration/test_model_runtime.py -q
```

- [x] **Step 8: 记录提交边界**

```powershell
git add backend/app/knowledge/reporting.py backend/app/model/runtime.py tests/unit/test_grounded_reporting.py tests/integration/test_model_runtime.py
git commit -m "feat: generate citation-checked security reports"
```

---

### Task 5: 知识编排、API 契约、配置与健康检查

**Files:**
- Create: `backend/app/knowledge/service.py`
- Create: `tests/unit/test_knowledge_service.py`
- Modify: `backend/app/schemas.py`
- Modify: `backend/app/agent/workflow.py`
- Modify: `backend/app/bootstrap.py`
- Modify: `backend/app/main.py`
- Modify: `tests/unit/test_schemas.py`
- Modify: `tests/unit/test_bootstrap.py`
- Modify: `tests/integration/test_basic_workflow.py`
- Modify: `tests/integration/test_analyze_api.py`
- Modify: `tests/integration/test_health_api.py`

**Interfaces:**
- Produces: `KnowledgeService.enhance(*, prompt: str, result: AnalysisResult, mode: KnowledgeMode, attack_family: str | None = None, work_mode: Mode = "analysis") -> KnowledgeEnhancement`
- Extends: `AnalysisRequest.knowledge_mode: KnowledgeMode = KnowledgeMode.OFF`
- Extends: `AnalysisResult` with `knowledge_status`, `knowledge_snapshot_version`, `knowledge_latency_ms`, `knowledge_retrieval_latency_ms`, `knowledge_report_latency_ms`, `knowledge_evidence`, `grounded_report`, `report_status`
- Configures: `TOKEN_SECURITY_KNOWLEDGE_SNAPSHOT_PATH`, `TOKEN_SECURITY_KNOWLEDGE_MAX_RESULTS=3`, `TOKEN_SECURITY_KNOWLEDGE_REPORT_MAX_NEW_TOKENS=256`, `TOKEN_SECURITY_KNOWLEDGE_REPORT_MAX_TIME_SECONDS=3.0`

- [x] **Step 1: 编写知识服务行为红测试**

覆盖五个具名测试：`off` 模式断言 query builder、retriever、generator 调用数均为 0；
`evidence` 模式断言前两者各调用一次且 generator 为 0；`report` 模式断言三者各调用一次；
检索异常断言返回 `knowledge_status=unavailable`；动作不变测试逐项比较基础结果。

最后一个测试保存基础 result 的 `decision`、`detector_score`、`suspicious_span`、`semantic_severity`，增强后逐项相等。

- [x] **Step 2: 运行知识服务红测试**

```powershell
python -m pytest tests/unit/test_knowledge_service.py -q
```

- [x] **Step 3: 实现 KnowledgeService**

服务捕获知识层的普通异常并返回 `unavailable`；`KeyboardInterrupt`、`SystemExit` 不捕获。
内部测量 query 耗时，但响应只返回 retrieval/report/total 三项非负延迟，不记录输入。
`evidence` 模式报告状态为 `off`。

- [x] **Step 4: 编写 schema 与 workflow 红测试**

验证缺省请求与旧客户端行为不变：

```python
request = AnalysisRequest(prompt="SAFE_PLACEHOLDER", model_id="model")
assert request.knowledge_mode == "off"
assert workflow.analyze(request).decision == baseline.decision
assert workflow.analyze(request).knowledge_status == "off"
```

`report` 模式断言 knowledge service 只在基础 result 创建后调用一次。

- [x] **Step 5: 扩展 schema 与 workflow**

先创建完整基础 `AnalysisResult`，再调用 `knowledge_service.enhance`，最后使用 `model_copy(update=...)` 附加知识字段。知识异常不得进入 FastAPI 500 路径。

- [x] **Step 6: 编写配置与健康红测试**

配置路径为空时知识层为可选 unavailable；配置路径不存在或快照无效时应用仍启动且 `/health.knowledge.ready=false`。配置有效时：

```json
{
  "ready": true,
  "snapshot_version": "official-v1",
  "card_count": 12,
  "generator_ready": true
}
```

- [x] **Step 7: 连接 bootstrap 与 main**

复用主模型 runtime 构造报告生成器，不重复加载 Qwen2.5。知识 snapshot 和 retriever 在应用启动时构建一次。未配置知识层不影响现有 health.status；完整比赛部署要求 knowledge ready。

- [x] **Step 8: 运行 Task 5 与全后端回归**

```powershell
python -m pytest tests/unit/test_knowledge_service.py tests/unit/test_schemas.py tests/unit/test_bootstrap.py tests/integration/test_basic_workflow.py tests/integration/test_analyze_api.py tests/integration/test_health_api.py -q
python -m pytest -q
```

- [x] **Step 9: 记录提交边界**

```powershell
git add backend/app/knowledge/service.py backend/app/schemas.py backend/app/agent/workflow.py backend/app/bootstrap.py backend/app/main.py tests
git commit -m "feat: orchestrate optional knowledge enhancement"
```

---

### Task 6: 隐私安全的知识审计迁移

**Files:**
- Modify: `backend/app/audit/models.py`
- Modify: `backend/app/audit/store.py`
- Modify: `backend/app/api/analyze.py`
- Modify: `tests/unit/test_event_store.py`
- Modify: `tests/integration/test_events_api.py`
- Modify: `tests/integration/test_analyze_api.py`

**Interfaces:**
- Extends: `SecurityEvent` with nullable `knowledge_snapshot_version`, `knowledge_mode`, `knowledge_status`, `knowledge_card_ids`, `report_status`, `knowledge_latency_ms`
- Preserves: idempotent legacy SQLite migration

- [x] **Step 1: 编写旧数据库迁移与隐私红测试**

创建当前 semantic schema 数据库，初始化新 store 两次，断言旧行保留、新列只增加一次。新事件 round-trip 只保存规范化 ID：

```python
assert event.knowledge_card_ids == [
    "mitre-atlas-jailbreak",
    "owasp-llm01-prompt-injection",
]
assert event.report_status == "generated"
```

扫描数据库 bytes，断言不含 `SAFE_PRIVATE_QUERY`、知识卡正文、报告正文和 raw output fixture。

- [x] **Step 2: 运行红测试**

```powershell
python -m pytest tests/unit/test_event_store.py tests/integration/test_events_api.py tests/integration/test_analyze_api.py -q
```

- [x] **Step 3: 实现幂等迁移与规范化序列化**

使用 `PRAGMA table_info` 后逐列 `ALTER TABLE`。卡 ID 去重排序后以 compact JSON 保存；读取时校验固定字符串格式和最大 3 个 ID。旧行返回 null。

- [x] **Step 4: 更新 analyze 审计映射**

只从 `AnalysisResult` 复制规范化字段。禁止把 `knowledge_evidence`、`grounded_report` 或 query 传给 store。

- [x] **Step 5: 运行 Task 6 测试与数据库扫描**

```powershell
python -m pytest tests/unit/test_event_store.py tests/integration/test_events_api.py tests/integration/test_analyze_api.py -q
```

- [x] **Step 6: 记录提交边界**

```powershell
git add backend/app/audit backend/app/api/analyze.py tests/unit/test_event_store.py tests/integration/test_events_api.py tests/integration/test_analyze_api.py
git commit -m "feat: audit normalized knowledge evidence"
```

---

### Task 7: 冻结检索评测与聚合报告

**Files:**
- Create: `backend/app/evaluation/knowledge.py`
- Create: `data/knowledge-evaluation-v1.json`
- Create: `data/knowledge-evaluation-report-v1.json`
- Create: `scripts/evaluate_knowledge.py`
- Create: `tests/unit/test_knowledge_evaluation.py`
- Create: `tests/unit/test_knowledge_evaluation_cli.py`
- Modify: `backend/app/api/evaluation.py`
- Modify: `backend/app/evaluation/service.py`
- Modify: `tests/integration/test_evaluation_api.py`

**Interfaces:**
- Produces: `KnowledgeEvaluationCase`, `KnowledgeEvaluationReport`
- Produces: `evaluate_knowledge(snapshot: KnowledgeSnapshot, cases: list[KnowledgeEvaluationCase]) -> KnowledgeEvaluationReport`
- Produces: CLI `scripts/evaluate_knowledge.py --snapshot <dir> --fixture <json> --output <json>`

- [x] **Step 1: 编写指标与隐私红测试**

```python
def test_hit_at_three_and_citation_validity_are_aggregate_only() -> None:
    report = evaluate_knowledge(snapshot, safe_cases)
    assert report.hit_at_3 == 1.0
    assert report.citation_validity == 1.0
    assert "query_text" not in report.model_dump_json()
```

测试还覆盖 fixture 重复 case ID、未知期望知识 ID、空期望集合、禁止键和非有限指标。

- [x] **Step 2: 运行红测试**

```powershell
python -m pytest tests/unit/test_knowledge_evaluation.py -q
```

- [x] **Step 3: 实现评测模型与指标**

fixture 只保存 `safe_terms` 和规范化 detector metadata，不包含 `prompt` 字段。报告只包含总数、Hit@1/3、MRR、逐风险域聚合、引用有效率、动作一致率、快照/fixture 哈希和延迟分位数。

- [x] **Step 4: 创建冻结 fixture**

创建 36 个安全合成 case，覆盖 6 个风险领域、9 个语义类别、CPD candidate/no anomaly、Guard unavailable 和 3 个攻击族标识。每个 case 指定 `expected_any_ids`，不使用攻击原文。

- [x] **Step 5: 编写并实现 CLI 红绿测试**

CLI 读取 snapshot 和 fixture，输出 ASCII JSON。stdout 只显示：

```text
knowledge evaluation completed cases=<N> hit_at_3=<value>
```

禁止输出 query、知识卡正文和逐样本结果。

- [x] **Step 6: 生成冻结工程报告并连接 evaluation API**

报告输出到 `data/knowledge-evaluation-report-v1.json`。Evaluation service 严格验证 schema、哈希和禁止键；Web API 将其作为独立 `knowledge` 节点返回，不修改现有 schema v2 方法指标。

- [x] **Step 7: 运行 Task 7 测试**

```powershell
python -m pytest tests/unit/test_knowledge_evaluation.py tests/unit/test_knowledge_evaluation_cli.py tests/integration/test_evaluation_api.py -q
```

只有 Hit@3 >= 0.90、citation validity=1.0、decision invariance=1.0 才允许进入 Web 展示。

- [x] **Step 8: 记录提交边界**

```powershell
git add backend/app/evaluation data/knowledge-evaluation-v1.json data/knowledge-evaluation-report-v1.json scripts/evaluate_knowledge.py tests
git commit -m "feat: evaluate grounded knowledge retrieval"
```

---

### Task 8: Web 知识证据与评测展示

**Files:**
- Modify: `frontend/src/types.ts`
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/pages/AnalyzePage.tsx`
- Modify: `frontend/src/pages/EvaluationPage.tsx`
- Modify: `frontend/src/pages/EventsPage.tsx`
- Modify: `frontend/src/App.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: Task 5/6/7 API contracts
- Produces: segmented knowledge mode control, unframed knowledge band, knowledge evaluation metrics

- [x] **Step 1: 编写前端红测试**

覆盖：

```typescript
expect(screen.getByRole("group", { name: "知识增强模式" })).toBeInTheDocument();
expect(await screen.findByText("OWASP GenAI Security Project")).toBeInTheDocument();
expect(screen.getByText("知识证据不改变基础判定")).toBeInTheDocument();
expect(screen.getByText("模板降级报告")).toBeInTheDocument();
expect(screen.queryByText("SAFE_PRIVATE_QUERY")).not.toBeInTheDocument();
```

增加 off/evidence/report 请求参数、unavailable/degraded、来源链接、移动端换行、事件列和 Evaluation Hit@3/引用有效率用例。

- [x] **Step 2: 运行前端红测试**

```powershell
Set-Location frontend
npm.cmd test -- --run
```

- [x] **Step 3: 扩展 TypeScript 契约与 API**

固定所有枚举和中文 label map；未知来源、状态和 report 字段不得直接显示任意后端字符串。`api.analyze` 增加 `knowledgeMode` 参数，默认 `off`。

- [x] **Step 4: 实现知识模式控制与证据带**

使用三段式控制，不使用下拉菜单。知识证据区域放在 Token track 之后，采用全宽 unframed band；每条来源包含外链图标、发布方、标题和建议。报告状态明确为“模型生成”或“模板降级”。不把知识证据塞进现有三路证据卡内部。

- [x] **Step 5: 扩展评测与事件页**

评测页单独展示 fixture 数、Hit@3、MRR、引用有效率、动作一致率和快照哈希，并显示“仅为冻结工程检索评测”。事件表只增加快照版本与报告状态列。

- [x] **Step 6: 运行测试与生产构建**

```powershell
npm.cmd test -- --run
npm.cmd run build
```

- [x] **Step 7: 执行一次有界视觉验收**

使用安全合成 UI 数据，在 1440x900 与 390x844 检查 analysis/evaluation/events。要求无重叠、来源 URL 可识别、长标题换行、知识区域不嵌套卡片、表格仅自身横向滚动、无 Prompt 或 raw output。最多一轮修复和一轮确认。

- [x] **Step 8: 记录提交边界**

```powershell
git add frontend/src
git commit -m "feat: present grounded knowledge evidence"
```

---

### Task 9: AutoDL 部署、真实验收与材料收尾

**Files:**
- Modify: `README.md`
- Modify: `THIRD_PARTY_NOTICES.md`
- Modify: `docs/basic-task/design.md`
- Modify: `docs/basic-task/development.md`
- Modify: `docs/basic-task/test-report.md`
- Modify: `docs/basic-task/experiment-report.md`
- Modify: `docs/basic-task/demo-script-3min.md`
- Create: `docs/advanced-task/design.md`
- Create: `docs/advanced-task/test-report.md`
- Create: `docs/advanced-task/experiment-report.md`
- Create: `scripts/smoke_knowledge_rag.py`
- Create: `tests/unit/test_knowledge_smoke_cli.py`

**Interfaces:**
- Consumes: protected external JSONL/sample IDs and running API
- Produces: aggregate-only knowledge smoke report, resource measurements, privacy scan

- [x] **Step 1: 编写聚合烟测隐私红测试**

烟测报告只允许模式计数、knowledge status、card ID counts、report status、citation validity、decision invariance、错误类型和延迟分位数。测试 fake API 即使返回 `prompt`、`query_text`、`raw_output`，报告也不得包含。

- [x] **Step 2: 实现知识烟测 CLI**

参数固定为：

```text
--input-jsonl <protected path>
--api-base <URL>
--output-json <untracked path>
--expected-snapshot-version official-v1
```

每个受保护样本分别请求 `off` 与 `report`，比较基础动作、分数、起点和语义结果完全一致。只在内存中保存请求正文。

- [x] **Step 3: 同步代码与知识快照到 AutoDL**

不得覆盖模型、CPD calibration、schema v2 report、原始数据和事件库。新增环境：

```bash
TOKEN_SECURITY_KNOWLEDGE_SNAPSHOT_PATH=/root/autodl-tmp/token-security-agent-platform/knowledge/snapshots/official-v1
TOKEN_SECURITY_KNOWLEDGE_REPORT_MAX_NEW_TOKENS=256
TOKEN_SECURITY_KNOWLEDGE_REPORT_MAX_TIME_SECONDS=3.0
TOKEN_SECURITY_KNOWLEDGE_MAX_RESULTS=3
```

重启后要求 model、detector、semantic_guard、knowledge、audit、evaluation、demo 全部 ready。

- [x] **Step 4: 运行安全与受保护验收**

至少覆盖：safe+no anomaly、safe+CPD candidate、unsafe+no anomaly、unsafe+CPD candidate、controversial、Guard unavailable fake integration，以及 GCG/AutoDAN/AdvPrompter 各 3 个冻结 ID。验证 off/report 动作一致率 100%、引用 ID 全部来自 Top-K、demo Token 继续脱敏。

- [x] **Step 5: 测量资源与失败路径**

记录 knowledge snapshot 内存、FTS 检索 P50/P95、报告生成 P50/P95、端到端 P50/P95、GPU 显存 before/after、OOM 数和 fallback 数。临时移走 snapshot 的副本路径进行 unavailable 测试，不删除 active snapshot；用 fake generator API 测试非法引用与超时，避免破坏运行模型。

- [x] **Step 6: 执行最终隐私与冻结完整性扫描**

只输出计数：保护 Prompt 在 SQLite/API log/aggregate report 中为 0；forbidden keys 为 0；Guard/report raw output 为 0。确认原 CPD 报告哈希仍为：

```text
8dffdd87a734740cbf71ddf8a85701a3a85f324373ad9f7855f7cd613ebd3c87
```

- [x] **Step 7: 更新进阶任务与基础任务文档**

基础文档只增加“可选知识增强层”，不修改冻结指标。进阶报告公开快照、fixture、Hit@3、MRR、引用有效率、动作一致率、延迟、fallback 和限制。三分钟演示加入知识模式，但不展示保护 Prompt。

- [x] **Step 8: 最终本地验证**

```powershell
$env:PYTHONPATH=".localdeps;backend"
python -m pytest -q
Set-Location frontend
npm.cmd test -- --run
npm.cmd run build
Set-Location ..
git diff --check
git diff --cached --check
```

- [x] **Step 9: 记录提交边界**

```powershell
git add README.md THIRD_PARTY_NOTICES.md docs scripts/smoke_knowledge_rag.py tests/unit/test_knowledge_smoke_cli.py
git commit -m "docs: validate local knowledge rag"
```

Git identity absent时报告确切阻塞并保留全部已验证 staged changes。
