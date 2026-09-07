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
  "/pcap-profile": [
    { id: "pcap-profile-scope", target: "pcap-profile-scope", title: "选择画像范围", description: "可使用快速或推荐档位、自定义样本数，也可覆盖全部可选文件；系统只返回聚合统计。" },
    { id: "pcap-profile-command", target: "pcap-profile-command", title: "授权生成画像", description: "点击后再次确认只读、无网络的隔离扫描边界，再启动画像任务。" },
    { id: "pcap-profile-results", target: "pcap-profile-results", title: "读取聚合结果", description: "协议、Packet 数、持续时间和可见性用于选择后续检测方法，不等于攻击结论。" },
  ],
  "/pcap-evaluation": [
    { id: "pcap-evaluation-scope", target: "pcap-evaluation-scope", title: "确认评测边界", description: "这里展示内置合成脱敏回归结果，不代表真实生产网络总体准确率。" },
    { id: "pcap-evaluation-metrics", target: "pcap-evaluation-metrics", title: "查看核心指标", description: "同时比较 Precision、Recall、F1、误报率和 Packet 定位命中率。" },
    { id: "pcap-evaluation-ablation", target: "pcap-evaluation-ablation", title: "比较检测贡献", description: "规则、行为与融合三行使用同一冻结数据，便于解释每类检测方法的贡献。" },
  ],
  "/lab": [
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

const AGENT_PROMPT_STEPS: GuidedTourStep[] = [
  { id: "agent-prompt-context", target: "agent-context", title: "开始 Prompt 安全对话", description: "这里既能进行普通交流和安全知识问答，也能创建需要检测工具的 Prompt 调查。" },
  { id: "agent-prompt-conversation", target: "agent-conversation", title: "查看连续对话", description: "你的消息显示在右侧，智能体的解释、计划和结果显示在左侧；历史任务可以继续追问。" },
  { id: "agent-prompt-composer", target: "agent-composer", title: "输入问题或调查目标", description: "直接提问不会自动运行工具；只有检测与处置任务才会进入授权和执行流程。" },
  { id: "agent-prompt-inspector", target: "agent-inspector", title: "核对案件证据", description: "右侧检查器分别展示 Guard、Token、假设、工具和报告，帮助验证智能体回复。" },
];

const AGENT_PCAP_STEPS: GuidedTourStep[] = [
  { id: "agent-pcap-context", target: "agent-context", title: "开始 PCAP 数据调查", description: "上传本机 PCAP 或描述调查目标，智能体会把检测过程和结论组织成连续对话。" },
  { id: "agent-pcap-conversation", target: "agent-conversation", title: "阅读调查过程", description: "上传进度、Packet 证据和最终结论都保留在对话中，检测完成后仍可继续追问。" },
  { id: "agent-pcap-composer", target: "agent-composer", title: "上传或继续追问", description: "可以添加 PCAP，也可以询问 Packet 含义、攻击目的、证据边界和处置建议。" },
  { id: "agent-pcap-inspector", target: "agent-inspector", title: "复核 PCAP 证据", description: "右侧检查器展示 mission 状态、Packet 证据、工具过程和报告边界。" },
];

const RESOURCE_TOURS: Record<string, GuidedTourStep[]> = {
  knowledge: [
    { id: "resource-knowledge-header", target: "resource-header", title: "了解安全知识库", description: "这里展示智能体用于解释与报告引用的离线安全知识快照。" },
    { id: "resource-knowledge-content", target: "resource-content", title: "核对知识条目", description: "每条知识标明发布方、版本与风险领域；知识不会绕过检测证据直接改变结论。" },
    { id: "resource-knowledge-return", target: "resource-return", title: "返回安全对话", description: "回到对话后可询问知识内容，或让智能体在当前案件中引用相关条目。" },
  ],
  connectors: [
    { id: "resource-connectors-header", target: "resource-header", title: "了解数据连接器", description: "这里核对智能体当前能够读取哪些真实、仿真或降级数据源。" },
    { id: "resource-connectors-content", target: "resource-content", title: "检查连接状态", description: "连接器状态决定任务能否执行；未接入的数据源不会被描述成真实联动。" },
    { id: "resource-connectors-return", target: "resource-return", title: "返回安全对话", description: "回到对话创建与当前可用连接器匹配的调查任务。" },
  ],
  reports: [
    { id: "resource-reports-header", target: "resource-header", title: "了解调查报告", description: "这里集中展示已完成任务生成的公开报告，并保留任务摘要和生成时间。" },
    { id: "resource-reports-content", target: "resource-content", title: "查看可审计结果", description: "报告区分任务来源、最终状态与证据引用；工具失败不会被包装成安全结论。" },
    { id: "resource-reports-return", target: "resource-return", title: "返回安全对话", description: "回到对应调查继续追问，或创建新的 Prompt 与 PCAP 对话。" },
  ],
};

export function resolveTour(pathname: string, search: string): { route: string; steps: GuidedTourStep[] } | null {
  if (pathname !== "/super-agent") {
    const steps = TOURS[pathname];
    return steps ? { route: pathname, steps } : null;
  }
  const params = new URLSearchParams(search);
  const resource = params.get("resource");
  if (resource && RESOURCE_TOURS[resource]) {
    return { route: `/super-agent:resource:${resource}`, steps: RESOURCE_TOURS[resource] };
  }
  const mode = params.get("mode") === "pcap" ? "pcap" : "prompt";
  return { route: `/super-agent:${mode}`, steps: mode === "pcap" ? AGENT_PCAP_STEPS : AGENT_PROMPT_STEPS };
}
