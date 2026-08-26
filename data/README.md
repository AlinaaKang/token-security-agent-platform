# 数据目录与隔离规则

本目录只保存本地实验数据和生成物，不在 Git 中提交 Prompt 正文。

```text
data/
  raw/          # 下载或挂载的原始数据，只读使用
  processed/    # 规范化记录和 dataset_card.json
  splits/       # 仅含 sample_id/group_id 的划分清单
```

## 接入顺序

1. 在 `configs/datasets.yaml` 登记官方来源、许可证、版本或 commit，以及文件 checksum。
2. 将原始文件放入 `data/raw/`，或通过只读环境变量指向外部目录。
3. 用对应数据源适配器转换为 `PromptRecord`，不得用 CSV 行号生成 `sample_id` 或 `group_id`。
4. 先做一致性、重复 ID 和后缀坐标检查，再按 group 生成 calibration/dev/test 清单。
5. 清单冻结后只追加新版本，不覆盖旧版本；最终测试集在阈值冻结前不得查看指标。

## 当前来源

| 数据源 | 用途 | 许可证 | 当前状态 |
| --- | --- | --- | --- |
| CPDonline main / Optimization / Guard-bypass | AutoDAN、AdvPrompter、GCG 与无害对照 | MIT | 已冻结评测并部署只读引用 |

CPDonline 署名：`Copyright (c) 2026 cpdonline`。项目后续复制或改编其代码时，必须同步更新根目录 `THIRD_PARTY_NOTICES.md`。

## 论文兼容校准与冻结评测

旧的 20 条无害 Prompt 校准入口已停用。部署 profile 必须由带标签、分组隔离的 CPDonline benchmark 生成：

```powershell
$env:PYTHONPATH="backend"
python scripts/benchmark_cpdonline.py `
  --model-path "Qwen/Qwen2.5-7B-Instruct" `
  --autodan-csv "data/raw/cpdonline/full_prompt_dataset.csv" `
  --advprompter-csv "data/raw/cpdonline/llama2_7B_foo_opt_624.csv" `
  --gcg-csv "data/raw/cpdonline/gcg_llamaguard_bypass.csv" `
  --source-commit "1a6c055865c44cc1d10dfbe5d014576c7331322e" `
  --output-dir "data/processed/cpd-paper-v2" `
  --version "qwen25-7b-cpd-paper-v2"
```

执行顺序固定为：

1. 按 `group_id` 生成 calibration/dev/test 清单；
2. 使用固定 system prompt 的 Token entropy 建立 median/MAD 基线；
3. 在 calibration 上分别为 `k=0`、`k=0.5` 选择 F1 最优 `h`；
4. 使用同一批 calibration/dev 模型观测拟合 Global NLL 和 Window NLL；
5. Window NLL 的窗口仅从 `8/16/32` 中按 dev 指标选择；
6. 在 dev 上为三种方法确定目标 FPR 不高于 10% 的分析阈值；
7. 参数冻结后才计算 test 指标。

低 FPR 工作点在报告中命名为 `low_fpr_selected_on_dev`。该名称只表示阈值在 dev 上按目标 FPR 选择，不代表冻结 test 必然达到 10% FPR。

安全输出只有：

- `splits/*.json`：sample ID、group ID、数据哈希；
- `calibration.json`：模型身份、system prompt 哈希、baseline、`k`、`h`；
- `benchmark_report.json`：Global NLL、Window NLL、Entropy-CPD 的总体和分攻击家族聚合指标；只有 Entropy-CPD 包含后缀起点定位指标。

在 profile 冻结前读取 test 标签指标、依据 test 结果改阈值，或把 Prompt 正文加入报告，都会使该轮实验无效。

## 隐私边界

- 不在测试、日志、截图、报告和 Git 历史中保存完整攻击 Prompt。
- 事件默认只保存请求哈希、脱敏摘要、Token 坐标和检测证据。
- `dataset_card.json` 只保存计数、哈希、来源与许可证，不保存 Prompt。
- 现场真实攻击演示只使用受保护 sample ID；浏览器不接收攻击 Prompt 或 Token 文本。
