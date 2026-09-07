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
