import { describe, expect, it } from "vitest";

const nodeProcess = (globalThis as typeof globalThis & {
  process: {
    cwd(): string;
    getBuiltinModule(name: "fs"): {
      readFileSync(path: string, encoding: "utf8"): string;
    };
  };
}).process;
const styles = nodeProcess.getBuiltinModule("fs")
  .readFileSync(`${nodeProcess.cwd()}/src/styles.css`, "utf8");

describe("responsive motion styles", () => {
  it("overrides the mobile reasoning connector at equal specificity for reduced motion", () => {
    expect(styles).toMatch(
      /@media \(prefers-reduced-motion: reduce\) \{\s*\.superagent-spinner,\s*\.superagent-reasoning-node,\s*\.superagent-reasoning-overview > li:not\(:last-child\)::after \{ animation: none; \}\s*\}/,
    );
  });

  it("keeps reconnaissance profile single-column on narrow screens", () => {
    expect(styles).toMatch(/@media \(max-width: 760px\)[\s\S]*\.pcap-recon-profile \{ grid-template-columns: 1fr; \}[\s\S]*\.pcap-recon-bar \{ grid-template-columns:/);
  });

  it("bounds contextual guidance inside mobile and reduced-motion viewports", () => {
    expect(styles).toMatch(/@media \(max-width: 760px\)[\s\S]*\.guided-tour-panel \{[\s\S]*max-height: min\(70vh, 520px\);[\s\S]*overflow-y: auto;/);
    expect(styles).toMatch(/@media \(prefers-reduced-motion: reduce\)[\s\S]*\.result-guide/);
  });

  it("moves the guide launcher clear of the bottom composer on compact layouts", () => {
    expect(styles).toMatch(/@media \(max-width: 1100px\)[\s\S]*\.guided-tour-launcher \{ bottom: 148px; \}/);
    expect(styles).toMatch(/@media \(max-width: 760px\)[\s\S]*\.guided-tour-launcher \{[\s\S]*top: 68px;[\s\S]*bottom: auto;/);
  });

  it("limits touch gesture capture to the draggable guide launcher", () => {
    expect(styles).toMatch(/\.guided-tour-launcher \{[\s\S]*touch-action: none;/);
  });
});

describe("unified color roles", () => {
  it("uses one blue identity palette and a separate success role", () => {
    expect(styles).toMatch(/--trusted:\s*#347fbe;/);
    expect(styles).toMatch(/--trusted-soft:\s*#e7f2fb;/);
    expect(styles).toMatch(/--success:\s*#2e7d62;/);
    expect(styles).toMatch(/--success-soft:\s*#edf8f4;/);
  });

  it("removes the retired dark-green identity palette", () => {
    for (const retired of ["#147863", "#0e6757", "#0f6755", "#126a58", "#123f36", "#087e70"]) {
      expect(styles.toLowerCase()).not.toContain(retired);
    }
  });

  it("keeps safe and successful outcomes green instead of primary blue", () => {
    expect(styles).toMatch(/\.semantic-safe strong, \.status-text-allow strong \{ color: var\(--success\); \}/);
    expect(styles).toMatch(/\.status-allow \{ color: var\(--success\) !important; background: var\(--success-soft\); \}/);
    expect(styles).toMatch(/\.pcap-detection-counts \.is-success \{ color: var\(--success\); \}/);
  });
});

describe("agent workspace responsive bounds", () => {
  it("keeps the recent task delete control visibly discoverable without hover", () => {
    expect(styles).toMatch(/\.agent-delete-task \{[^}]*opacity: 1;/);
    expect(styles).not.toMatch(/\.agent-delete-task \{[^}]*opacity: 0;/);
  });

  it("gives the two conversation entry links primary text contrast", () => {
    expect(styles).toMatch(/\.sidebar\.agent-sidebar nav \.agent-conversation-link \{[^}]*color: var\(--agent-ink\);[^}]*font-weight: 700;/);
  });

  it("keeps three and four welcome shortcuts centered on one desktop row", () => {
    expect(styles).toMatch(/\.agent-welcome \{[^}]*grid-template-columns: minmax\(0, 1fr\);/);
    expect(styles).toMatch(/\.agent-welcome-actions\[data-count="3"\] \{[^}]*grid-template-columns: repeat\(3, minmax\(0, 1fr\)\);/);
    expect(styles).toMatch(/\.agent-welcome-actions\[data-count="4"\] \{[^}]*grid-template-columns: repeat\(4, minmax\(0, 1fr\)\);/);
    expect(styles).toMatch(/\.agent-welcome-actions \{[^}]*justify-self: stretch;/);
    expect(styles).toMatch(/@media \(max-width: 760px\)[\s\S]*\.agent-welcome-actions\[data-count\] \{ grid-template-columns: 1fr; \}/);
  });

  it("keeps an overflowing desktop sidebar inside its own painted scroll region", () => {
    expect(styles).toMatch(
      /\.sidebar\.agent-sidebar \{[^}]*height: 100vh;[^}]*overflow-y: auto;[^}]*overscroll-behavior: contain;/,
    );
  });

  it("prevents the welcome content from using an intrinsic width wider than the viewport", () => {
    expect(styles).toMatch(/\.agent-welcome \{[^}]*width: 100%;[^}]*min-width: 0;/);
  });

  it("keeps the resource workspace inside the mobile viewport", () => {
    expect(styles).toMatch(/\.agent-resource-page,\s*\.agent-resource-page \* \{ box-sizing: border-box; \}/);
  });
});

describe("PCAP forensic challenge roles", () => {
  it("uses a stable three-column desktop rail and one-column mobile stack", () => {
    expect(styles).toMatch(/\.pcap-forensic-roles \{[^}]*grid-template-columns: repeat\(3, minmax\(0, 1fr\)\);/);
    expect(styles).toMatch(/@media \(max-width: 760px\)[\s\S]*\.pcap-forensic-roles \{ grid-template-columns: 1fr; \}/);
  });

  it("does not animate the icon-only forensic roles", () => {
    expect(styles).not.toMatch(/\.pcap-forensic-role[^}]*animation:/);
  });
});
