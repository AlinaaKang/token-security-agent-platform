import { CircleHelp } from "lucide-react";

export type ResultGuideItem = {
  term: string;
  explanation: string;
};

type ResultGuideProps = {
  title: string;
  summary: string;
  items: ResultGuideItem[];
};

export function ResultGuide({ title, summary, items }: ResultGuideProps) {
  return (
    <details className="result-guide" role="group" aria-label={title}>
      <summary>
        <CircleHelp size={18} aria-hidden="true" />
        <span>{title}</span>
      </summary>
      <div className="result-guide-content">
        <p>{summary}</p>
        <dl>
          {items.map((item) => (
            <div key={item.term}>
              <dt>{item.term}</dt>
              <dd>{item.explanation}</dd>
            </div>
          ))}
        </dl>
      </div>
    </details>
  );
}
