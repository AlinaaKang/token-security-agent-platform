# 基础任务开发与部署

## 1. 环境

- Python 3.11 或 3.12
- Node.js 与 npm
- CUDA GPU，建议 24GB 显存
- 可输出完整 logits 的 Qwen2.5-7B-Instruct 本地权重
- Qwen3Guard-Gen-0.6B 本地权重

## 2. 后端验证

```powershell
Set-Location E:\Codex\token-security-agent-platform
$env:PYTHONPATH=".localdeps"
python -m pytest -q
```

标准安装方式：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q
```

## 3. 前端验证

```powershell
Set-Location frontend
npm.cmd install
npm.cmd test -- --run
npm.cmd run build
npm.cmd run dev -- --host 127.0.0.1 --port 5174
```

浏览器入口：`http://127.0.0.1:5174/analyze`。

## 4. GPU API 配置

```bash
export TOKEN_SECURITY_MODEL_PATH=/path/to/Qwen2.5-7B-Instruct
export TOKEN_SECURITY_CALIBRATION_PATH=/path/to/calibration.json
export TOKEN_SECURITY_GUARD_MODEL_PATH=/path/to/Qwen3Guard-Gen-0.6B
export TOKEN_SECURITY_GUARD_MODEL_VERSION='modelscope-master+sha256:<model.safetensors-sha256>'
export TOKEN_SECURITY_GUARD_MAX_INPUT_TOKENS=4096
export TOKEN_SECURITY_GUARD_MAX_NEW_TOKENS=32
export TOKEN_SECURITY_BENCHMARK_REPORT_PATH=/path/to/benchmark_report.json
export TOKEN_SECURITY_EVENT_DB_PATH=/path/to/runtime/security-events.sqlite3
export TOKEN_SECURITY_DEMO_AUTODAN_CSV=/readonly/path/full_prompt_dataset.csv
export TOKEN_SECURITY_DEMO_ADVPROMPTER_CSV=/readonly/path/llama2_7B_foo_opt_624.csv
export TOKEN_SECURITY_DEMO_GCG_CSV=/readonly/path/gcg_llamaguard_bypass.csv
export TOKEN_SECURITY_MAX_INPUT_TOKENS=4096
export TOKEN_SECURITY_KNOWLEDGE_SNAPSHOT_PATH=/path/to/knowledge/snapshots/official-v1
export TOKEN_SECURITY_KNOWLEDGE_EVALUATION_REPORT_PATH=/path/to/data/knowledge-evaluation-report-v1.json
export TOKEN_SECURITY_KNOWLEDGE_REPORT_MAX_NEW_TOKENS=256
export TOKEN_SECURITY_KNOWLEDGE_REPORT_MAX_TIME_SECONDS=3.0
export TOKEN_SECURITY_KNOWLEDGE_MAX_RESULTS=3

.venv/bin/uvicorn app.main:app \
  --app-dir backend \
  --host 127.0.0.1 \
  --port 8000
```

远端端口通过 SSH 隧道映射到本机 `127.0.0.1:18000`，Vite 将 `/health` 和 `/api` 代理到该地址。私钥路径、账号凭据和原始数据目录不得写入仓库或比赛截图。

## 5. 健康检查

```powershell
Invoke-RestMethod http://127.0.0.1:18000/health |
  ConvertTo-Json -Depth 8
```

完整演示要求以下状态均为 ready：

- model
- detector
- semantic_guard
- audit
- evaluation
- demo

任一可选服务未配置时，API 必须明确返回不可用状态，不能用前端假数据补齐。

ModelScope 默认修订只返回 `master` 时，`TOKEN_SECURITY_GUARD_MODEL_VERSION` 必须同时包含权重 SHA-256；不得把可变分支名表述为不可变 commit。当前验收权重哈希见 `THIRD_PARTY_NOTICES.md`。

知识快照缺失或校验失败时，API 仍应启动并把 `knowledge.ready` 置为 false；不得用空白知识卡或网络搜索替代。受保护验收使用 `scripts/smoke_knowledge_rag.py`，只写聚合报告：

```bash
PYTHONPATH=backend .venv/bin/python scripts/smoke_knowledge_rag.py \
  --input-jsonl /protected/input.jsonl \
  --api-base http://127.0.0.1:8000 \
  --output-json /untracked/aggregate.json \
  --expected-snapshot-version official-v1
```

## 6. 冻结基准

运行命令与数据隔离顺序见 `data/README.md`。必须先冻结 calibration/dev 参数，再计算 test；三方法复用同一批模型观测，测试标签不能用于选择 `k`、`h`、窗口或阈值。

## 7. 比赛合规检查

本项目使用自研平台。提交材料必须附赛事方允许替代“基于深信服 AI 安全平台”的书面确认。建议在团队只读材料库归档 PDF 或截图并记录确认日期、赛事联系人和适用赛题；不得在公共仓库保存私人聊天内容。
