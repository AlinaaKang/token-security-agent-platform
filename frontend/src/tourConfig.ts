import type { GuidedTourStep } from "./components/GuidedTour";

export const CHALLENGE_SETUP_STEPS: GuidedTourStep[] = [
  { id: "challenge-setup", target: "challenge-setup", title: "进入挑战设置", description: "挑战与专业实验舱相互独立，这里只配置互动演示。" },
  { id: "challenge-rounds", target: "challenge-rounds", title: "选择关卡组", description: "三关适合快速体验，五关会加入更多攻击家族。", advanceOnClick: true },
  { id: "challenge-method", target: "challenge-method", title: "选择调查方式", description: "互动调查要求先查看三类证据再研判；自动演示会依次回放脱敏结果。", advanceOnClick: true },
  { id: "challenge-command", target: "challenge-command", title: "开始侦探挑战", description: "由你进入挑战；引导不会泄露答案、Token 内容或隐藏推理。" },
];

export const CHALLENGE_INVESTIGATION_STEPS: GuidedTourStep[] = [
  { id: "challenge-input", target: "challenge-input", title: "先确认公开输入", description: "这里只展示场景允许公开的输入信息；受保护内容仍保持脱敏。" },
  { id: "challenge-team", target: "challenge-team", title: "按顺序完成调查", description: "依次点击 Guard 语义侦探、CPD 曲线侦探、Agent 小队队长。每位角色完成汇报后，下一位才会解锁。" },
];

export const CHALLENGE_ANSWER_STEPS: GuidedTourStep[] = [
  { id: "challenge-clues", target: "challenge-clues", title: "综合两路线索", description: "先比较 Guard 语义状态和 CPD 分布状态，再形成证据关系判断。" },
  { id: "challenge-onset", target: "challenge-onset", title: "标记异常起点", description: "观察红色 CPD 累积线，选择最早开始持续变化的位置，不是曲线最高点。" },
  { id: "challenge-evidence", target: "challenge-evidence", title: "选择证据关系", description: "判断风险来自语义、分布、双路，或两路均正常；不适用时系统会明确标记。" },
  { id: "challenge-action", target: "challenge-action", title: "给出处置动作", description: "根据已经查看的公开证据选择放行、人工复核或拦截。" },
  { id: "challenge-submit", target: "challenge-submit", title: "提交后再揭晓", description: "只有你主动提交后，页面才会展示系统答案和得分明细。" },
];

export const CHALLENGE_REVEAL_STEPS: GuidedTourStep[] = [
  { id: "challenge-reveal", target: "challenge-reveal", title: "复盘本关判断", description: "对比玩家答案、系统结果和各项得分；本关分数衡量答案一致性，不是模型准确率。" },
];

export const TOURS: Partial<Record<string, GuidedTourStep[]>> = {
  "/analyze": [
    { id: "analyze-input", target: "analyze-input", title: "准备待检测内容", description: "在这里输入需要进行语义安全与 Token 分布检测的内容。" },
    { id: "analyze-knowledge", target: "analyze-knowledge", title: "选择知识增强", description: "可关闭知识增强，或只引用证据，也可生成带依据的报告。", advanceOnClick: true },
    { id: "analyze-mode", target: "analyze-mode", title: "选择工作模式", description: "安全分析用于观察结果；在线防护会按策略给出处置动作。", advanceOnClick: true },
    { id: "analyze-command", target: "analyze-command", title: "开始安全检测", description: "准备好后由你点击开始；远程模型未连接时仍可跳过本步。" },
  ],
  "/events": [
    { id: "events-summary", target: "events-summary", title: "先看审计范围", description: "这里汇总已记录的检测事件。记录经过脱敏，只包含哈希、证据状态和处置元数据。" },
    { id: "events-table", target: "events-table", title: "逐列读取处置证据", description: "同一行串联语义状态、Token 状态、最终动作与校准版本；它是审计记录，不是原始 Prompt 回放。" },
  ],
  "/evaluation": [
    { id: "evaluation-scope", target: "evaluation-scope", title: "确认评测范围", description: "样本量与报告版本界定了这些数字适用于哪一份冻结测试集。" },
    { id: "evaluation-methods", target: "evaluation-methods", title: "比较方法与工作点", description: "先比较 F1、AUROC 与 FPR，再确认阈值是在开发集选择，避免用测试集调参。" },
    { id: "evaluation-limits", target: "evaluation-limits", title: "区分能力与边界", description: "分类指标衡量是否检出；CPD 定位指标衡量异常起点误差，两者不能互相替代。" },
  ],
  "/lab": [
    { id: "lab-input-kind", target: "lab-input-kind", title: "选择攻防输入", description: "Prompt 攻防验证模型输入，PCAP 攻防检测一个本地网络抓包。", advanceOnClick: true },
    { id: "lab-active-input", target: "lab-active-input", title: "准备实验输入", description: "当前区域只读取你主动选择的 Prompt 场景或单个 PCAP 文件。" },
    { id: "lab-active-boundary", target: "lab-active-boundary", title: "确认实验边界", description: "Prompt 使用既有检测链路；PCAP 只在本地无网络 Docker 中解析。" },
    { id: "lab-active-command", target: "lab-active-command", title: "手动开始实验", description: "只有你点击最终操作后，系统才会运行调查或上传检测。" },
  ],
  "/super-agent": [
    { id: "superagent-task", target: "superagent-task", title: "选择任务类型", description: "Prompt 调查与 PCAP 分诊属于同一个自主处置智能体的两种任务模式。" },
    { id: "superagent-scope", target: "superagent-scope", title: "限定任务范围", description: "选择任务场景与工作模式，智能体只在当前范围内工作。" },
    { id: "superagent-bounds", target: "superagent-bounds", title: "查看执行边界", description: "工具调用和重规划次数受到固定上限约束，过程会留下结构化审计轨迹。" },
    { id: "superagent-command", target: "superagent-command", title: "授权自主任务", description: "启动或 PCAP 授权始终由你确认；外部服务不可用时可以跳过本步。" },
  ],
  "/challenge": CHALLENGE_SETUP_STEPS,
};
