export type PcapChallengeCase = {
  id: string;
  title: string;
  scenario: string;
  captureSummary: string;
  clues: Array<{
    packet: string;
    timestamp: string;
    protocol: string;
    direction: string;
    excerpt: string;
    observation: string;
  }>;
  packetOptions: string[];
  attackOptions: string[];
  purposeOptions: string[];
  answer: { packet: string; attack: string; purpose: string };
  explanation: string;
};

export const PCAP_CHALLENGE_CASES: PcapChallengeCase[] = [
  {
    id: "http-sql-01",
    title: "登录接口异常请求",
    scenario: "一段经过脱敏的 HTTP 会话中出现了短促但集中的异常请求，请结合小队公开线索完成研判。",
    captureSummary: "HTTP · 9 个 Packet · 明文请求边界可见",
    clues: [
      { packet: "Packet 1-3", timestamp: "00:00.000-00:00.083", protocol: "HTTP", direction: "10.0.8.21 -> auth.demo.local", excerpt: "GET /login HTTP/1.1\nGET /assets/login.css HTTP/1.1", observation: "正常基线：登录页与静态资源请求，未出现额外参数。" },
      { packet: "Packet 4-4", timestamp: "00:00.084", protocol: "HTTP POST", direction: "10.0.8.21 -> auth.demo.local", excerpt: "POST /login HTTP/1.1\nusername=admin%27+OR+%271%27%3D%271&password=x", observation: "待研判：账号字段出现编码后的引号、OR 与布尔条件组合，与前序正常请求明显不同。" },
      { packet: "Packet 5-7", timestamp: "00:00.101-00:00.164", protocol: "HTTP", direction: "auth.demo.local -> 10.0.8.21", excerpt: "HTTP/1.1 401 Unauthorized\nContent-Length: 96", observation: "结果证据：服务端拒绝请求，不能据此否定异常尝试。" },
    ],
    packetOptions: ["Packet 1-3", "Packet 4-4", "Packet 5-7"],
    attackOptions: ["SQL 注入", "命令注入", "路径穿越"],
    purposeOptions: ["认证绕过", "脚本执行", "内部地址访问"],
    answer: { packet: "Packet 4-4", attack: "SQL 注入", purpose: "认证绕过" },
    explanation: "Packet 4-4 是最早出现可复核注入特征的请求；语法组合指向 SQL 注入候选，其最可能目的为认证绕过。该证据不证明攻击已经成功。",
  },
  {
    id: "http-command-02",
    title: "管理接口参数异常",
    scenario: "服务端管理接口出现参数拼接痕迹，需要判断异常起点与可能目的。",
    captureSummary: "HTTP/TCP · 18 个 Packet · 管理接口参数可见",
    clues: [
      { packet: "Packet 6-8", timestamp: "00:01.210-00:01.284", protocol: "HTTP", direction: "10.0.4.18 -> admin.demo.local", excerpt: "GET /admin/status?id=1034 HTTP/1.1", observation: "正常基线：参数为历史常见的数字标识。" },
      { packet: "Packet 12-14", timestamp: "00:01.611-00:01.705", protocol: "HTTP POST", direction: "10.0.4.18 -> admin.demo.local", excerpt: "POST /admin/diag HTTP/1.1\ntarget=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd", observation: "待研判：诊断参数包含编码后的命令分隔符和系统路径。" },
      { packet: "Packet 15-18", timestamp: "00:01.719-00:01.866", protocol: "HTTP/TCP", direction: "admin.demo.local -> 10.0.4.18", excerpt: "HTTP/1.1 500 Internal Server Error\nContent-Length: 1482", observation: "结果证据：响应体增大，但不能单独证明命令已执行。" },
    ],
    packetOptions: ["Packet 6-8", "Packet 12-14", "Packet 15-18"],
    attackOptions: ["SQL 注入", "命令注入", "路径穿越"],
    purposeOptions: ["认证绕过", "脚本执行", "内部地址访问"],
    answer: { packet: "Packet 12-14", attack: "命令注入", purpose: "脚本执行" },
    explanation: "Packet 12-14 首次形成连续的命令分隔符和执行参数证据，候选类型为命令注入，目的更接近脚本执行。",
  },
  {
    id: "http-path-03",
    title: "文件读取请求异常",
    scenario: "文件服务出现多级路径跳转特征，请从公开请求边界中定位异常。",
    captureSummary: "HTTP/DNS · 12 个 Packet · 文件服务路径可见",
    clues: [
      { packet: "Packet 2-3", timestamp: "00:02.004-00:02.041", protocol: "DNS", direction: "10.0.7.33 -> 10.0.0.53", excerpt: "A files.demo.local -> 10.0.6.12", observation: "正常基线：解析目标与历史记录一致。" },
      { packet: "Packet 7-8", timestamp: "00:02.228-00:02.297", protocol: "HTTP GET", direction: "10.0.7.33 -> files.demo.local", excerpt: "GET /download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1", observation: "待研判：文件参数出现连续编码路径片段。" },
      { packet: "Packet 9-12", timestamp: "00:02.310-00:02.482", protocol: "HTTP", direction: "files.demo.local -> 10.0.7.33", excerpt: "HTTP/1.1 403 Forbidden\nContent-Length: 74", observation: "结果证据：服务端已拒绝，仍需定位触发拒绝的请求。" },
    ],
    packetOptions: ["Packet 2-3", "Packet 7-8", "Packet 9-12"],
    attackOptions: ["SQL 注入", "命令注入", "路径穿越"],
    purposeOptions: ["认证绕过", "脚本执行", "内部地址访问"],
    answer: { packet: "Packet 7-8", attack: "路径穿越", purpose: "内部地址访问" },
    explanation: "Packet 7-8 出现连续目录回退与受限路径访问候选，攻击类型为路径穿越，目的候选为访问内部资源。",
  },
];
