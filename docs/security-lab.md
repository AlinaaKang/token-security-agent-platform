# AI 安全攻防实验舱

`/lab` 是与基础页面隔离的调查工作区。它复用现有语义 Guard、Entropy-CPD、固定融合和本地知识证据，但不会改变 `/analyze`、`/events` 或 `/evaluation` 的请求、响应与处置逻辑。

## 启用方式

实验舱默认关闭。只有基础检测工作流已经 ready 时，设置以下环境变量并重启 API：

```powershell
$env:TOKEN_SECURITY_LAB_ENABLED="true"
```

可识别的开启值是 `1`、`true`、`yes`、`on`，大小写不敏感。其他值均视为关闭。关闭或依赖不可用时，仅 `/lab` 降级，基础健康状态与三个稳定页面不受影响。

## API

- `GET /api/v1/lab/scenarios`：返回可用场景描述，只包含受保护样本 ID，不包含原文。
- `POST /api/v1/lab/runs`：创建自定义或冻结样本调查。
- `GET /api/v1/lab/runs/{run_id}`：读取 15 分钟内的脱敏调查结果。
- `POST /api/v1/lab/runs/{run_id}/tools/{tool_id}/dry-run`：执行固定工具模拟。
- `GET /api/v1/lab/metrics`：返回最近有效窗口的聚合运行指标。

服务最多保留 32 条已脱敏运行，TTL 为 15 分钟。指标从同一窗口聚合，不生成按样本、攻击族或输入哈希展开的明细。

## 六类演示场景

1. 普通无害：验证双路正常时放行。
2. 无害格式突变：验证 CPD 对格式变化的敏感性，并观察语义证据如何避免把变化点直接等同于恶意。
3. 直接危险：验证没有优化后缀时，语义 Guard 仍可给出安全处置。
4. GCG：按冻结测试样本 ID 调用。
5. AutoDAN：按冻结测试样本 ID 调用。
6. AdvPrompter：按冻结测试样本 ID 调用。

受保护场景只允许发送 `sample_id`。Prompt、优化后缀和截断前缀始终留在受保护服务边界内，不进入浏览器、实验舱缓存、日志、报告或 Git。当前不声明 BEAST 与 AutoDAN-HGA 覆盖。

## 证据含义

语义 Guard 判断内容风险等级与类别；Entropy-CPD 使用 Token 序列的熵、NLL 和累计变化量给出异常候选及预测起点。CPD 是独立的分布变化与定位证据，不等同于语义恶意判定。

反事实检查只在存在有效预测起点时，将同一输入截断到 `char_start` 并使用相同工作流重新检测一次，知识模式固定为关闭。它只能说明结果对预测后缀是否敏感，不构成严格因果证明，也不会改写基础动作。

## 处置沙箱

实验舱只提供三个固定工具：

- `gateway_preview`
- `soc_case_preview`
- `evidence_export_preview`

它们不接受 URL、凭据、路径、命令或自由文本参数，不访问网络、文件系统或子进程。成功和失败均为确定性模拟；工具失败不会把 `block` 降级为 `review` 或 `allow`。

## 运行指标

“实验舱运行指标”包含最近窗口内的反事实执行覆盖、证据冲突、工具成功/失败、报告状态、基础动作不变性及 P50/P95 延迟。这些值用于说明链路覆盖与稳定性，不是冻结分类性能，不应与 `agent-ablation-v1`、F1、召回率或误报率混用。

`privacy_violation_count` 当前为响应边界状态指标；每个成功返回和缓存对象仍会经过递归禁用字段校验。禁用字段为：`prompt`、`suffix`、`token_text`、`token_id`、`query_text`、`raw_output`、`guard_raw_output`。

## 失败行为

- 实验舱关闭：返回 `lab_disabled`，HTTP 503。
- 依赖不可用：返回 `lab_unavailable`，HTTP 503。
- 运行不存在或已过期：返回固定的 `lab_run_not_found` 或 `lab_run_expired`。
- 调查创建失败：不保存部分结果，只返回固定的 `lab_run_failed`。
- 知识、反事实或工具阶段失败：保留或加强基础动作，不允许降级安全处置。

## 建议演示路径

路径一使用普通无害和无害格式突变，说明“分布变化不自动等于恶意”。路径二使用直接危险样本，说明语义 Guard 覆盖无明显后缀的内容风险。路径三依次选择 GCG、AutoDAN、AdvPrompter 的受保护 ID，展示 Token 定位、反事实敏感性、知识引用、模拟处置和脱敏报告。

演示结论应限定为当前冻结样本和已记录运行，不声称 CPD 普遍提高分类 F1，也不把小样本功能抽测表述为总体准确率。

## 2026-08-27 验证记录

- 后端完整回归：`306 passed, 1 skipped`。跳过项为未配置 `TOKEN_SECURITY_GPU_TEST_MODEL` 的真实 GPU 集成测试。
- 前端完整回归：`21 passed`。
- 前端生产构建：TypeScript 与 Vite 成功，`1597 modules transformed`。
- 隐私验证器：当前 Git 跟踪清单 `forbidden_key_hits=0`、`tracked_path_hits=0`、`json_errors=0`。
- 浏览器 QA：`1440x900` 与 `390x844` 下，`/analyze` 和 `/lab` 均无全局横向溢出或控制台错误；实验舱三条 SVG 曲线非空，移动端曲线只在局部容器滚动，键盘可切换调查标签并执行工具失败模拟。
- AutoDL：本次未执行新实验舱的受保护 ID 冒烟。SSH 入口 `connect.westb.seetacloud.com:28129` 在验证时拒绝连接，待实例恢复或端口更新后再执行 GCG、AutoDAN、AdvPrompter 各一条 ID 级检查。

上述浏览器检查使用合成无害数据，不含攻击原文。AutoDL 未完成项不得写成已通过，也不影响本地回归结论。
