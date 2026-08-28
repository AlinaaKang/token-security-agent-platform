# 进阶任务测试报告

报告日期：2026-08-29

## 1. 自动验证

| 范围 | 本轮结果 |
| --- | --- |
| 后端单元/集成/回归 | 483 passed，1 skipped，0 failed |
| 前端交互 | 131 passed，0 failed |
| TypeScript + Vite 构建 | 通过，1608 modules transformed |
| `/lab` 聚焦前端 | 18 passed |
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

## 7. 未实现与不声明

- 未接入深信服平台、外部防火墙、EDR、SIEM 或工单系统。
- 不声明 BEAST、AutoDAN-HGA 检测覆盖。
- 报告动作不变性有效状态为 `legacy_unverified`，目标未达标。
- 自研平台参赛仍以赛事方书面允许替代为合规前提。
