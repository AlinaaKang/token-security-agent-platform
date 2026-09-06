import { Database, FlaskConical, FunctionSquare } from "lucide-react";

import type { EvidenceAuthenticity } from "../agent/types";

const copy = {
  real: { label: "真实检测", Icon: Database },
  simulated: { label: "仿真", Icon: FlaskConical },
  derived: { label: "派生", Icon: FunctionSquare },
} as const;

export function AuthenticityBadge({ value }: { value: EvidenceAuthenticity }) {
  const { label, Icon } = copy[value];
  return <span className={`agent-authenticity is-${value}`}><Icon size={12} />{label}</span>;
}
