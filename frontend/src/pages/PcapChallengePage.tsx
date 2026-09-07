import { CheckCircle2, Network, Play, RotateCcw, ShieldCheck } from "lucide-react";
import { useState } from "react";

import { PcapForensicRoles } from "../components/PcapForensicRoles";
import { ResultGuide } from "../components/ResultGuide";
import { PCAP_CHALLENGE_CASES } from "../pcap/challengeCases";

export function PcapChallengePage() {
  const [caseIndex, setCaseIndex] = useState(0);
  const [started, setStarted] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [packet, setPacket] = useState("");
  const [attack, setAttack] = useState("");
  const [purpose, setPurpose] = useState("");
  const current = PCAP_CHALLENGE_CASES[caseIndex];
  const activeStage: 1 | 2 | 3 = !packet ? 1 : !attack ? 2 : 3;
  const score = Number(packet === current.answer.packet) * 40
    + Number(attack === current.answer.attack) * 30
    + Number(purpose === current.answer.purpose) * 30;
  const resetRound = (nextIndex = caseIndex) => {
    setCaseIndex(nextIndex);
    setPacket(""); setAttack(""); setPurpose(""); setSubmitted(false);
  };
  return (
    <main className="page pcap-challenge-page" aria-label="PCAP 侦探挑战">
      <header className="page-header">
        <div>
          <h1>PCAP 侦探挑战</h1>
          <p>像 Token 侦探挑战一样，查看公开流量线索、标记异常 Packet 并提交你的研判。</p>
        </div>
        <span className="privacy-mark"><ShieldCheck size={15} /> 内置脱敏关卡</span>
      </header>

      <section className="pcap-challenge-brief" aria-label="挑战说明">
        <Network size={22} aria-hidden="true" />
        <div><strong>内置脱敏流量关卡</strong><p>挑战不上传你的文件，也不替代真实 PCAP 数据调查；得分只衡量你与预设答案的一致性。</p></div>
      </section>

      {!started ? <section className="pcap-challenge-start" aria-label="挑战准备">
        <div><strong>三关网络证据研判</strong><p>每关依次查看文件解析、流量特征和分诊结论，再选择异常 Packet、攻击类型与攻击目的。</p></div>
        <button type="button" onClick={() => setStarted(true)}><Play size={16} />开始挑战</button>
      </section> : <section className="pcap-challenge-stage" aria-label={`PCAP 挑战第 ${caseIndex + 1} 关`}>
        <header><div><span>关卡 {caseIndex + 1} / {PCAP_CHALLENGE_CASES.length}</span><h2>{current.title}</h2><p>{current.scenario}</p></div><button type="button" aria-label="重新开始本关" title="重新开始本关" onClick={() => resetRound()}><RotateCcw size={16} /></button></header>
        <PcapForensicRoles activeStage={activeStage} />
        <section className="pcap-challenge-evidence" aria-label="公开 Packet 证据">
          <header><div><strong>先看证据，再作判断</strong><span>{current.captureSummary}</span></div><small>内容已脱敏，答案将在提交后揭晓</small></header>
          <p className="pcap-challenge-method">研判顺序：先建立正常基线，再定位首次偏离，最后用响应判断结果；异常请求不等于攻击已经成功。</p>
          <div className="pcap-challenge-evidence-table" role="table" aria-label="Packet 证据对比">
            <div className="pcap-challenge-evidence-head" role="row"><span role="columnheader">Packet / 时间</span><span role="columnheader">协议与流向</span><span role="columnheader">脱敏包内容</span><span role="columnheader">观察提示</span></div>
            {current.clues.map((clue) => <div className="pcap-challenge-evidence-row" role="row" key={clue.packet}>
              <div role="cell"><strong>{clue.packet}</strong><time>{clue.timestamp}</time></div>
              <div role="cell"><strong>{clue.protocol}</strong><span>{clue.direction}</span></div>
              <code role="cell">{clue.excerpt}</code>
              <p role="cell">{clue.observation}</p>
            </div>)}
          </div>
        </section>
        <div className="pcap-challenge-answer">
          <fieldset><legend>1. 标记异常位置</legend><div>{current.packetOptions.map((option) => <button type="button" key={option} aria-pressed={packet === option} onClick={() => setPacket(option)}>{option}</button>)}</div></fieldset>
          <fieldset><legend>2. 判断攻击类型</legend>{current.attackOptions.map((option) => <label key={option}><input type="radio" name="pcap-attack" checked={attack === option} onChange={() => setAttack(option)} />{option}</label>)}</fieldset>
          <fieldset><legend>3. 判断攻击目的</legend>{current.purposeOptions.map((option) => <label key={option}><input type="radio" name="pcap-purpose" checked={purpose === option} onChange={() => setPurpose(option)} />{option}</label>)}</fieldset>
        </div>
        <button className="pcap-challenge-submit" type="button" disabled={!packet || !attack || !purpose || submitted} onClick={() => setSubmitted(true)}><CheckCircle2 size={16} />提交研判</button>
        {submitted ? <section className="pcap-challenge-score" aria-label="挑战评分"><strong>本关得分 {score}</strong><p>{current.explanation}</p><dl><div><dt>异常位置</dt><dd>{packet === current.answer.packet ? "正确" : `正确答案：${current.answer.packet}`}</dd></div><div><dt>攻击类型</dt><dd>{attack === current.answer.attack ? "正确" : `正确答案：${current.answer.attack}`}</dd></div><div><dt>攻击目的</dt><dd>{purpose === current.answer.purpose ? "正确" : `正确答案：${current.answer.purpose}`}</dd></div></dl>{caseIndex < PCAP_CHALLENGE_CASES.length - 1 ? <button type="button" onClick={() => resetRound(caseIndex + 1)}>进入下一关</button> : <button type="button" onClick={() => resetRound(0)}>重新挑战</button>}</section> : null}
      </section>}

      <ResultGuide
        title="如何完成 PCAP 侦探挑战"
        summary="先比较每个 Packet 区间的协议、方向和脱敏现象，再标记异常位置、攻击类型和目的，提交后查看评分与解析。"
        items={[
          { term: "规则侦探", explanation: "检查请求级特征是否命中 SQL 注入、命令注入、路径穿越或 Web 注入候选。" },
          { term: "序列侦探", explanation: "检查跨 Packet 的时序与行为证据；短请求可能不需要序列检测。" },
          { term: "Packet 定位", explanation: "异常区间是可复核证据位置，不代表攻击已经成功。" },
        ]}
      />
    </main>
  );
}
