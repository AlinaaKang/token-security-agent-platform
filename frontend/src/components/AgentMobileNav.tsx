import { Menu, PanelRight } from "lucide-react";

export function AgentMobileNav({ onMenu, onInspector }: { onMenu: () => void; onInspector: () => void }) {
  return (
    <header className="agent-mobile-nav">
      <button type="button" onClick={onMenu} aria-label="打开主导航"><Menu size={20} /></button>
      <strong>Token Security</strong>
      <button type="button" onClick={onInspector} aria-label="打开检查器"><PanelRight size={20} /></button>
    </header>
  );
}
