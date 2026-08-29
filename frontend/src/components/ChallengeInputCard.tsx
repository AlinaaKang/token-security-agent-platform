import type { ChallengePublicInput } from "../challenge/definitions";

interface ChallengeInputCardProps {
  publicInput: ChallengePublicInput;
}

export function ChallengeInputCard({ publicInput }: ChallengeInputCardProps) {
  return (
    <section className="challenge-input-card" aria-label="本关待检输入">
      <header className="challenge-input-card__header">
        <strong>本关待检输入</strong>
        {publicInput.available ? (
          <span className={`challenge-input-card__badge ${publicInput.disclosure}`}>
            {publicInput.disclosure === "full" ? "公开安全样本" : "受保护样本"}
          </span>
        ) : null}
      </header>
      {!publicInput.available ? (
        <p className="challenge-input-card__unavailable">公开材料暂不可用</p>
      ) : (
        <div className="challenge-input-card__body">
          <span>任务意图</span>
          <p>{publicInput.intentSummary}</p>
          <span>输入材料</span>
          {publicInput.disclosure === "full" ? (
            <pre>{publicInput.content}</pre>
          ) : (
            <div>
              <p>{publicInput.content}</p>
              <p className="challenge-input-card__notice">[对抗攻击内容已隐藏]</p>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
