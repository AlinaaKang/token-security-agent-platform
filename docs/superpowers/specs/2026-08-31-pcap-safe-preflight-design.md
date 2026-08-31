# PCAP 安全预检容器设计

## 1. 目标

在不影响现有 Web 平台、模型服务和 Entropy-CPD 链路的前提下，为来源未知或可能含有恶意载荷的 PCAP/PCAPNG 文件提供第一阶段安全预检。预检只回答文件是否有效、基本捕获属性、协议可见性以及是否具备后续分析条件，不恢复 Prompt，不定位 Token，也不把普通网络异常表述为 Token 异常。

本阶段的成功标准是：使用一个临时、无网络、非 root、最小权限的 Docker 容器，只读挂载单个明确文件，生成固定字段的脱敏 JSON 报告，并能用无害合成抓包验证全部隔离约束。

## 2. 范围与边界

### 2.1 本阶段包含

- 校验输入路径、扩展名、文件存在性和普通文件类型；
- 在容器内计算 SHA-256、文件大小和捕获格式；
- 统计包数、捕获时间跨度、链路层类型和有限协议计数；
- 判断是否观察到 HTTP、TLS 或其他可识别协议；
- 输出 `token_eligible`、`traffic_only` 或 `insufficient_evidence` 三档能力结论；
- 验证容器无网络、根文件系统只读、非 root、无 Linux capabilities、禁止权限提升且资源受限；
- 使用无害微型抓包完成自动化和人工验收。

### 2.2 本阶段不包含

- 提取、保存、显示、搜索或记录应用层 Payload；
- 输出 Prompt、攻击 suffix、Token 文本、Cookie、Authorization、URL 参数、域名、IP、端口或请求路径；
- TCP 流重组、TLS 解密、HTTP 正文恢复、Tokenizer 或 Entropy-CPD；
- 将 PCAP 上传到 Git、GitHub、Web API、AutoDL 或第三方服务；
- 运行抓包中的脚本、附件、对象或任何文本指令；
- 修改现有分析页面、基础任务指标或进阶任务动作。

协议识别工具会在容器内部解析数据包以识别协议。这里的“不得读取 Payload”精确定义为：不得提取、保存、显示、搜索或向报告传播应用层正文；不能错误表述为工具完全不解析数据包字节。

## 3. 方案选择

采用“独立取证容器 + 本机 PowerShell 启动脚本”。不把 TShark 或 PCAP 依赖加入现有后端镜像，也不在 Windows 主机直接安装和执行分析工具。

选择原因：

- 与现有 `api` 和 `web` 服务解耦，基础页面和 GPU 链路不受影响；
- 每次只向容器暴露一个明确文件，不暴露项目目录或用户目录；
- 容器运行权限和资源限制可以被机械验证；
- 后续若增加 Prompt 恢复，可以作为独立第二阶段评审，而不是暗中扩大预检权限。

## 4. 目录与组件

### 4.1 仓库内文件

- `pcap-inspector/Dockerfile`：构建最小分析镜像；
- `pcap-inspector/inspect.py`：调用固定参数的元数据和协议统计工具，验证并输出白名单 JSON；
- `scripts/inspect_pcap.ps1`：解析单个本机路径，创建受限临时容器并保存报告；
- `scripts/verify_pcap_sandbox.ps1`：用无害测试文件验证隔离约束；
- `tests/unit/test_pcap_preflight.py`：测试报告模型、结论映射、解析失败和输出白名单；
- `docs/pcap-safe-preflight.md`：面向使用者的运行说明与能力边界。

### 4.2 仓库外隔离目录

默认使用：

```text
E:\Codex\pcap-quarantine\
├── input\
└── output\
```

该目录不属于 Git 仓库。启动脚本每次仅把用户明确指定的一个普通文件挂载为 `/input/capture`，并设置只读。容器不会挂载 `output`；固定字段 JSON 通过标准输出返回，再由本机脚本写入 `output`，避免容器获得任何主机写权限。

## 5. 容器安全边界

运行命令必须等价地包含以下约束：

- `--network none`；
- `--read-only`；
- `--cap-drop ALL`；
- `--security-opt no-new-privileges=true`；
- 镜像内固定非 root UID/GID；
- `--cpus 1`；
- `--memory 512m`；
- `--pids-limit 64`；
- `/tmp` 使用限量、禁执行的 `tmpfs`；
- `--rm`，运行结束自动删除容器；
- 仅一个 `type=bind`、`readonly` 的文件挂载；
- 不挂载 Docker socket、项目目录、用户目录、凭据目录或输出目录。

镜像构建阶段可以访问软件源以安装固定分析工具；运行真实 PCAP 时必须无网络。构建日志和运行日志不得包含输入文件内容。

## 6. 数据流

```text
用户指定单个文件
  -> PowerShell 解析绝对路径并验证普通文件
  -> Docker 只读挂载为固定容器路径
  -> 容器计算哈希与捕获元数据
  -> 受限协议层级统计
  -> 白名单字段校验
  -> 标准输出单个 JSON 文档
  -> PowerShell 再校验字段并写入隔离 output
```

输入文件在整个过程中保持只读。报告文件名由 SHA-256 前缀和固定后缀生成，不沿用原始 PCAP 文件名。

## 7. 报告模型

报告仅允许以下字段：

- `schema_version`；
- `sha256`；
- `size_bytes`；
- `capture_format`；
- `packet_count`；
- `duration_seconds`；
- `link_types`；
- `protocol_counts`：只允许固定协议枚举和非负计数；
- `visibility`：`http_observed`、`tls_observed`、`unknown_observed`；
- `capability`；
- `reasons`：固定枚举，不包含抓包原文；
- `tool_versions`。

禁止额外字段。所有字符串使用长度和枚举约束；数值必须有限且非负。工具异常、格式非法、输出解析失败或未知字段都采用失败关闭策略，不生成部分可信报告。

## 8. 能力结论

### `token_eligible`

仅表示观察到明文 HTTP 等可在第二阶段进一步鉴定的协议条件。第一阶段无法确认流量是否属于大模型 API；该结论不表示已经恢复 Prompt、具备 Token 检测条件或完成 Token 检测。第二阶段仍需单独授权和内容级验证。

### `traffic_only`

文件有效，但只观察到 TLS 或普通网络协议，当前证据只能支持会话或流量级分析。不得生成 Token 起点、Token 风险或 Entropy-CPD 结论。

### `insufficient_evidence`

格式不支持、抓包为空、工具无法形成可信统计，或协议条件不足。报告给出固定原因，并建议获取 TLS 会话密钥、反向代理日志、服务端审计日志或更完整抓包；不猜测内容。

## 9. 错误处理

- 路径不存在、目录输入、符号链接/重解析点或扩展名不允许：主机脚本在启动容器前拒绝；
- 文件在分析期间被替换或哈希不一致：拒绝保存报告；
- 容器超时、退出码非零、内存不足或工具崩溃：只返回固定错误类别；
- 标准输出不是唯一 JSON、含未知字段或敏感字段：拒绝保存；
- Docker 不可用：提示启动 Docker Desktop，不回退到主机直接分析；
- output 写入失败：不修改输入，不在其他目录自动落盘。

错误信息不得回显 Payload、协议字段值或原始文件名。为便于用户定位本机文件，交互式 PowerShell 错误可以显示用户自己输入的本机路径，但该路径不得进入 JSON 报告、测试快照、日志或 Git。

## 10. 验证

自动验证至少覆盖：

1. 报告白名单和未知字段拒绝；
2. 三档能力结论的确定性映射；
3. 空文件、非 PCAP、截断文件和工具失败；
4. 哈希、大小、包数和格式的正确性；
5. 输出不含测试 Payload、文件名、IP、域名、端口和路径；
6. 容器 UID 非 0；
7. 容器没有网络接口出口；
8. 根文件系统不可写，输入文件不可写；
9. Linux capabilities 为空且无法提权；
10. CPU、内存和 PID 限制符合设计；
11. 运行结束没有残留容器；
12. 现有后端测试、前端测试和生产构建不受影响。

无害测试抓包只能包含合成地址和无敏感文本。真实 PCAP 不进入自动测试、截图、Git 或报告示例。

## 11. 后续阶段门槛

只有在第一阶段报告为 `token_eligible`，并且用户再次明确授权内容级分析后，才设计第二阶段：TCP 重组、可见 HTTP 请求识别、Prompt 字段恢复、Tokenizer、Entropy-CPD 和 Token 到数据包序号映射。

第二阶段必须继续区分：明文或可解密流量可以尝试 Token 级检测；无法解密的 HTTPS 只能做流量级检测。第一阶段的实现不得预留会绕过该授权门槛的隐藏 Payload 输出。

## 12. 比赛表述

安全表述为：平台增加了 PCAP 证据可用性鉴定器，智能体先判断网络证据是否满足后续 Token 分析条件，再选择 Token 检测、流量检测或证据不足路径。

不得表述为：平台能够从任意 PCAP 提取 Prompt、解密 HTTPS、定位异常 Token，或使用 Entropy-CPD 检测普通网络攻击。
