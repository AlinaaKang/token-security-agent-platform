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
