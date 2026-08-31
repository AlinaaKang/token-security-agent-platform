# PCAP 安全预检操作指南

## 1. 用途与边界

PCAP 安全预检是独立的证据可用性鉴定器。它回答“这份抓包能否为后续分析提供明文应用协议证据”，不回答“是否存在 jailbreak”，也不从抓包恢复 Prompt、suffix 或 Token。

预检只输出文件摘要、大小、格式、包数、时长、链路类型、白名单协议计数、可见性和三档能力结论。报告不包含原始文件名、域名、IP、端口、URL、请求路径、Cookie、Authorization、应用载荷、Prompt、suffix 或 Token 文本。

TShark 会在隔离容器内部解析包字节，但启动器只请求时间、封装类型和协议栈三个固定字段。应用载荷不会被提取、显示、搜索、保存、记录或传给 Web/API。

## 2. 为什么分成这些步骤

```text
安装并启动 Docker Desktop
  -> 构建固定分析镜像（仅构建阶段可能联网下载工具）
  -> 用无害合成 PCAP 机械验证隔离边界
  -> 用户把一个 PCAP 放入仓库外 input
  -> 运行无网络、单文件只读预检
  -> 阅读三档能力结论
  -> 只有 token_eligible 且再次授权时，才设计第二阶段
```

先验证隔离再接触用户文件，是为了避免把“Docker 参数写在脚本里”等同于“运行时限制已经生效”。真实文件始终位于 Git 仓库外，不上传 GitHub，不发送到 AutoDL，也不进入现有 Web 服务。

## 3. 首次准备

以下命令都在本机 PowerShell 中执行，不在 AutoDL 终端执行。先启动 Docker Desktop，再进入项目根目录。

```powershell
$docker = "$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin\docker.exe"
& $docker version
& $docker build --quiet -f pcap-inspector\Dockerfile -t token-security-pcap-preflight:local .
```

镜像使用固定摘要的 MCR 基础镜像，默认以 UID/GID `65532:65532` 运行，不声明端口或卷，也不给 `dumpcap` 捕获能力。

随后运行机械隔离验证：

```powershell
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts\verify_pcap_sandbox.ps1
```

只有看到以下唯一成功摘要，才进入真实文件预检：

```text
pcap_sandbox_verification=passed network_none=1 readonly_root=1 non_root=1 cap_drop_all=1 no_new_privileges=1 resource_limits=1 payload_leaks=0 residual_containers=0
```

验证器只生成一个无害 HTTP 健康检查包，使用文档保留地址。它不会读取 `E:\Codex\pcap-quarantine` 中的任何用户文件。

## 4. 放置与预检一个文件

在仓库外创建以下目录：

```text
E:\Codex\pcap-quarantine\input\
E:\Codex\pcap-quarantine\output\
```

每次只把一个待检 `.pcap` 或 `.pcapng` 文件放入 `input`。不要把文件放进项目仓库，也不要上传 GitHub。

在项目根目录运行：

```powershell
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts\inspect_pcap.ps1 `
  -Path 'E:\Codex\pcap-quarantine\input\待检文件.pcap'
```

启动器会执行以下固定边界：

- `--network none`
- `--read-only`
- `--cap-drop ALL`
- `--security-opt no-new-privileges=true`
- `--cpus 1`
- `--memory 512m`
- `--pids-limit 64`
- 16 MiB、`noexec,nosuid,nodev` 的临时目录
- 只把选中的一个文件只读挂载到 `/input/capture`

成功后，报告写入：

```text
E:\Codex\pcap-quarantine\output\pcap-preflight-<SHA-256前16位>.json
```

原始文件名不会写入报告或报告名。

## 5. 三档能力结论

| capability | 含义 | 下一步 |
| --- | --- | --- |
| `token_eligible` | 观察到 HTTP、HTTP/2 或 WebSocket 等明文应用协议 | 只表示可以申请第二阶段；尚未证明是大模型 API，也未运行 Token 分析 |
| `traffic_only` | 观察到受支持的流量，但没有 HTTP、HTTP/2 或 WebSocket 明文候选；包括 TLS/QUIC、DNS 及网络层协议 | 仅作为流量侧辅助证据，不能定位异常 Token |
| `insufficient_evidence` | 无包或没有受支持协议 | 记录证据不足，不做本机解密、原生解析或自动上传 |

即使得到 `token_eligible`，本阶段仍不读取 HTTP body，不恢复 Prompt，不调用 Qwen，不运行 Entropy-CPD。第二阶段需要重新评估数据授权、脱敏方式和比赛必要性后再单独设计。

## 6. 失败处理

启动器失败时只返回固定分类，例如：

- `docker_unavailable`：Docker Desktop 未启动或未找到；启动 Docker 后重试。
- `input_outside_quarantine`：文件不在固定 `input` 目录；移动到正确目录后重试。
- `input_not_regular_file` / `input_reparse_point`：输入不是普通文件或是链接；改用明确的本地普通文件。
- `unsupported_capture_extension`：扩展名不是 `.pcap` 或 `.pcapng`。
- `docker_failed` / `docker_timeout`：容器失败或超过 150 秒；停止预检并检查 Docker，不回退到宿主机 TShark。
- `invalid_report_schema`：容器报告不符合严格白名单；拒绝保存。
- `input_changed`：运行后摘要与容器报告不一致；隔离该文件并重新取得可信副本。

任何失败都不得改用本机 Wireshark/TShark 自动解析、放宽挂载、启用容器网络、上传 AutoDL 或把报告写到其他目录。

## 7. 比赛表述

建议使用以下准确表述：

> 平台在模型内部 Token 安全链路之外，增加了一个网络证据可用性预检智能体。它在无网络、非 root、只读和资源受限的容器中，对单个 PCAP 做固定字段协议鉴定，输出 `token_eligible`、`traffic_only` 或 `insufficient_evidence`。该模块不进入基础或进阶冻结指标，不恢复 Prompt，不运行 Entropy-CPD，也不改变任何既有动作。完整 PCAP 到 Prompt/Token 的关联尚未实现。

不能表述为“PCAP 已定位异常 Token”“加密流量已恢复 Prompt”或“网络流量使用 Entropy-CPD 检测”。

## 8. 2026-08-31 验证证据

- PCAP 核心聚焦测试：92 passed，1 skipped；验证器原生 stderr 失败路径测试：1 passed。跳过项是当前 Windows 账户无创建符号链接权限时的重解析点用例。
- 全量后端：614 passed，2 skipped。另一跳过项是未配置本机真实 GPU 测试模型。
- 全量前端：199 passed；TypeScript 与 Vite 生产构建通过。
- Docker：客户端/引擎 29.7.2，Docker Desktop 4.88.1；镜像配置用户为 `65532:65532`。
- 机械隔离：`network_none=1`、`readonly_root=1`、`non_root=1`、`cap_drop_all=1`、`no_new_privileges=1`、`resource_limits=1`、`payload_leaks=0`、`residual_containers=0`。
- 本轮只使用代码生成的无害合成 PCAP，没有读取用户真实 PCAP。
- 已知限制：完整 PCAP 到 Prompt/Token 的关联、加密载荷恢复和 PCAP 上的 Entropy-CPD 均未实现；`token_eligible` 仍需单独授权第二阶段。
