# 进阶任务测试报告

报告日期：2026-08-29

## 1. 自动验证

| 范围 | 本轮结果 |
| --- | --- |
| 后端单元/集成/回归 | 515 passed，1 skipped，0 failed |
| 前端交互 | 138 passed，0 failed |
| TypeScript + Vite 构建 | 通过，1609 modules transformed |
| `/lab` 聚焦前端 | 20 passed |
| Windows PowerShell 5.1 API 隐私回归 | 1 passed |

后端全量测试使用项目 Python 环境并显式设置 `PYTHONPATH=backend`。唯一 skipped 是本机未配置 `TOKEN_SECURITY_GPU_TEST_MODEL` 的真实 GPU runtime 集成测试；真实模型链路由 AutoDL 浏览器验收覆盖。

## 2. AutoDL 部署状态

环境为 RTX 4090 D 24GB、Qwen2.5-7B-Instruct 和 Qwen3Guard-Gen-0.6B。通过本机 SSH 隧道访问远端 `127.0.0.1:8000`，未开放公网 API。

健康检查实测：model、detector、semantic_guard、knowledge、audit、evaluation、demo、lab 全部 ready；知识快照 `official-v2`、18 cards，`deployment_match=true`，实验舱 `tool_storage=sqlite`。当前 API 由 Git 跟踪文件归档部署，未上传密钥、截图、SQLite 或受保护数据。

## 3. 工具端到端验收

Chromium 在 1440x900 下创建了一个无害场景和一个受保护 GCG 场景，并完成：

- 三种工具逐一预览，均显示“预览完成”；
- 打开确认对话框后取消一次，回执数保持 0；
- 分别执行网关、工单、证据包，形成 3 条平台内部回执；
- 用同一 UUID 重放一次网关执行，首次 201、重放 200，`execution_id` 相同且无重复；
- 下载 evidence JSON，在浏览器重新计算 SHA-256，与回执 `evidence_sha256` 一致；
- 整页刷新后重新进入工具页，服务端执行历史和证据回执可恢复。

上述工具只改变平台内部 SQLite 状态，没有网络、子进程或外部安全设备副作用。

## 4. 隐私验证

浏览器流程完成后，使用 Windows PowerShell 5.1 对真实 AutoDL 隧道运行隐私验证：

```text
privacy_verification=passed
forbidden_key_hits=0
tracked_path_hits=0
json_errors=0
sqlite_violations=0
api_requests=9
api_violations=0
```

九个 HTTP 表面包括健康、场景、创建/读取 run、工具预览、确认执行、执行列表、证据下载和固定 422。扫描器只输出表面、类别与计数，不打印匹配值、响应正文或私人路径。PowerShell 7 与 Windows PowerShell 5.1 均有自动回归测试。

## 5. 桌面与移动浏览器 QA

| 项目 | 结果 |
| --- | --- |
| 1440x900 `/lab` | 无重叠，确认、回执和下载可操作 |
| 390x844 `/lab` | 文档宽度 390、视口宽度 390，无横向溢出 |
| 移动端知识证据 | 每行 `scrollWidth <= clientWidth`，链接、建议和 ID 可换行 |
| 命令标签 | 无裁切，预览与确认按钮保持稳定尺寸 |
| 减少动效 | 持续旋转被关闭，文字忙碌状态仍可理解 |
| 浏览器控制台 | 0 errors |

`/analyze` 仍显示“检测服务已连接”和“开始检测”主流程；`/challenge` 仍可进入三关互动挑战，并依次点击语义侦探、曲线侦探和小队队长后显示本关线索。基础页面未被工具执行中心替换。

## 6. 现场发现与修复

1. Windows PowerShell 5.1 不会自动加载 `System.Net.Http`，真实隐私命令曾返回固定 `unhandled_error`。新增 5.1 HTTP 红测试后显式加载程序集。
2. `/lab` 的 run 只存在 React 内存，刷新后 UI 无法恢复回执。现在会话中只保存脱敏 run ID，再通过服务端 run 和 SQLite 恢复；不保存 Prompt 或 Token。
3. 移动端知识链使用九列 `max-content`，页面本身不超宽但内容被内部裁剪。现在改为可换行证据链，并用浏览器宽度断言复核。
4. 证据 artifact 声明摘要与 payload、execution 回执此前未在写入边界三方绑定。现在 artifact 对象、artifact ID 与回执摘要必须同存同空；三者存在时写入前强制摘要一致，下载时继续复算。四条回归测试覆盖双向缺失和两种摘要不一致。
5. 运行指标曾用 dry-run 结果和空集合 `all()` 计算“基础动作不变率”。现在只统计 SQLite 已确认执行，显示明确分子、分母；零执行时页面显示 `N/A`。
6. official-v2 已支持 CAC 和三个新增风险域，但前端类型与标签仍停在 v1。现在四个发布方和九个风险域均有穷尽类型、中文标签与未知值回退，并用真实 CAC 卡片回归。
7. 场景或指标接口失败曾阻断刷新恢复。现在三个启动任务使用独立失败边界，两种辅助失败路径均能恢复脱敏 run。

## 7. 未实现与不声明

- 未接入深信服平台、外部防火墙、EDR、SIEM 或工单系统。
- 不声明 BEAST、AutoDAN-HGA 检测覆盖。
- 报告动作不变性有效状态为 `legacy_unverified`，目标未达标。
- 自研平台参赛仍以赛事方书面允许替代为合规前提。

## 8. 挑战任务增量

新增 `/super-agent` 自主处置工作台和独立后端 API。一次任务复用一个实验舱 run，以五个固定角色生成 `PLAN / ACT / OBSERVE / REPLAN / COMPLETE` 结构化轨迹；最多重规划一次、调用三个平台内部工具、产生十二条公开事件。

基础动作不可变：安全放行不执行处置工具，复核类动作只创建脱敏案件和证据包，拦截动作依次执行内部网关状态、脱敏案件和证据包。任一工具失败时进入 `degraded`，不降低动作、不无限重试。

隐私扫描新增能力、任务创建、任务恢复和固定 422 四个响应面。页面和 API 均不返回原始 Prompt、攻击 suffix、Token 文本或 ID、检索词、模型原始输出或隐藏推理。完整边界与使用方式见 [挑战任务说明](../challenge-task.md)。

## 9. SuperAgent AutoDL 验收

最新后端已通过 Git 跟踪文件归档同步；未上传模型、受保护数据、SQLite、密钥、冻结报告或截图。归档在本地与远端解包后的三项关键源码 SHA-256 完全一致。

健康检查满足 model、detector、semantic guard、knowledge、audit、evaluation、demo、lab 和 superagent 全部 ready；知识快照为 `official-v2`、18 cards，`deployment_match=true`，SuperAgent 声明 `internal_only=true`、最多三个工具和十二条事件。

在线验收结果：安全任务以 `closed_safe` 收口，9 条事件、0 次工具；受保护拦截任务以 `contained` 收口，12 条事件，内部网关状态、安全案件和证据包按固定顺序各执行一次。两个任务响应的禁用字段递归扫描命中为 0。

独立隐私扫描器覆盖 13 个 API 表面：

```text
privacy_verification=passed
forbidden_key_hits=0
tracked_path_hits=0
json_errors=0
sqlite_violations=0
api_requests=13
api_violations=0
```

Playwright 在 1440x900 和 390x844 验证 `/super-agent`，文档宽度分别等于视口宽度；安全回执为 0，整页刷新后通过脱敏 mission ID 恢复且回执仍为 0；拦截回执为 3，减少动效下事件动画为 `none`。同时回归 `/analyze`、`/lab` 和 `/challenge`，四个路由控制台均为 0 error。验收截图只保留在未跟踪临时目录，未写入报告或 Git。

## 10. PCAP SuperAgent 合成验收

2026-09-02 在当前分支使用项目 Python 3.12.13，并将 `PYTHONPATH` 显式指向当前
worktree 的 `backend`，观察到后端全量 `751 passed，4 skipped，0 failed`。四个跳过项
分别是未配置真实 GPU 模型、当前 Windows 账户不能创建一个 inspector 文件符号链接，
以及两个 executor 文件符号链接用例；无需该权限的 junction 边界用例已执行并通过。

新增 PCAP Agent 隐私验证器测试观察到 `6 passed，0 failed`。验证器单独连接本机合成
HTTP fixture 时只输出以下聚合：

```text
pcap_agent_privacy_verification=passed
checked_endpoint_count=6
privacy_violation_count=0
tracked_private_artifact_count=0
```

前端全量观察到 `23` 个测试文件、`229 passed，0 failed`；生产构建观察到
`1622 modules transformed` 并成功生成产物。现有 Docker 机械隔离验证器观察到无网络、
只读根文件系统、非 root、全部 capability 丢弃、`no-new-privileges`、资源限制全部通过，
`payload_leaks=0` 且 `residual_containers=0`。

缓存 Playwright 与本机构建产物的合成浏览器验收覆盖 `/analyze`、`/super-agent` 和
`/challenge` 三个路由。原三关挑战完成 `3/3`；PCAP 在 `1440x900` 与 `390x844` 下均完成
两次点击授权、取消和三公仔证据回放，两个视口的横向溢出均为 `0`，浏览器控制台错误为
`0`。所有浏览器 API 响应均为合成公开字段，未连接真实 PCAP 服务。

本轮没有新的明确 UI 授权，因此未读取或处理真实 PCAP，未执行真实 20 文件批次，也未
验收真实文件间取消、成功跳过、失败重试或新增文件续跑。这些项目保持 pending，必须在
后续获得一次新的 `确认并开始` UI 授权后执行；不得直接调用批处理脚本替代授权。第一版
仍不提供 Prompt 恢复、Entropy-CPD 或 Token 分析，不声明 PCAP 检测到 jailbreak 或
异常 Token。
