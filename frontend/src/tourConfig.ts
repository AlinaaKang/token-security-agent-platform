import type { GuidedTourStep } from "./components/GuidedTour";

export const TOURS: Partial<Record<string, GuidedTourStep[]>> = {
  "/analyze": [
    { id: "analyze-input", target: "analyze-input", title: "准备待检测内容", description: "在这里输入需要进行语义安全与 Token 分布检测的内容。" },
    { id: "analyze-knowledge", target: "analyze-knowledge", title: "选择知识增强", description: "可关闭知识增强，或只引用证据，也可生成带依据的报告。", advanceOnClick: true },
    { id: "analyze-mode", target: "analyze-mode", title: "选择工作模式", description: "安全分析用于观察结果；在线防护会按策略给出处置动作。", advanceOnClick: true },
    { id: "analyze-command", target: "analyze-command", title: "开始安全检测", description: "准备好后由你点击开始；远程模型未连接时仍可跳过本步。" },
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
  "/challenge": [
    { id: "challenge-setup", target: "challenge-setup", title: "进入挑战设置", description: "挑战与专业实验舱相互独立，这里只配置互动演示。" },
    { id: "challenge-rounds", target: "challenge-rounds", title: "选择关卡组", description: "三关适合快速体验，五关会加入更多攻击家族。", advanceOnClick: true },
    { id: "challenge-method", target: "challenge-method", title: "选择调查方式", description: "互动调查要求先查看三类证据再研判；自动演示会依次回放脱敏结果。", advanceOnClick: true },
    { id: "challenge-command", target: "challenge-command", title: "开始侦探挑战", description: "由你进入挑战；引导不会泄露答案、Token 内容或隐藏推理。" },
  ],
};
