# PCAP 分层侦察报告模板

> 本模板只接受合成或已获 UI 授权的聚合结果。不得填入文件名、路径、地址、载荷、哈希、
> 时间戳、任务/收据 ID 或逐文件记录。

## corpus structure

- `eligible_file_count`:
- `sample_limit`:
- `sampling_method`: `size_quartile_v1`
- 总体大小/封装分布（仅聚合计数或区间）:

## protocol visibility

- 可见性类别计数（`token_eligible`、`traffic_only`、`insufficient_evidence`）:
- 协议/链路类型计数（固定枚举）:
- 解析成功、失败和降级计数:

## sequence suitability

- 是否存在足够的顺序/会话证据:
- 是否适合进入下一阶段检测器:
- 仍缺失的聚合证据:

## evidence limits

- 本阶段不能证明的事项（攻击、jailbreak、Prompt、Token、身份）:
- Docker 隔离和完整文件解析边界:
- 隐私校验结果（只填通过/失败及计数）:

## next-plan decision

- 由上述观察选择的下一检测器计划:
- 需要的新 UI 授权或配置:
- 保持不变的既有行为（Prompt、triage、challenge、mascot、Token、CPD）:
