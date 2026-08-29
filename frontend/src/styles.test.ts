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
});
