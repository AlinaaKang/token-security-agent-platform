import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { MascotTeam } from "./MascotTeam";

afterEach(cleanup);

describe("MascotTeam", () => {
  it("keeps all roles mounted and activates CPD for the entropy stage", () => {
    const { container } = render(
      <MascotTeam
        phase="investigating"
        replayStageId="entropy_cpd"
        evidenceConflict={false}
      />,
    );

    expect(screen.getByRole("img", { name: "Guard 语义侦探" }))
      .toHaveAttribute("src", "/mascots/guard-detective.webp");
    expect(screen.getByRole("img", { name: "CPD 曲线侦探" }).closest("figure"))
      .toHaveClass("active");
    expect(screen.getByRole("img", { name: "Agent 小队队长" }).closest("figure"))
      .not.toHaveClass("active");
    expect(container.querySelectorAll("figure")).toHaveLength(3);
  });

  it.each([
    ["semantic_guard", "Guard 语义侦探"],
    ["token_observation", "CPD 曲线侦探"],
    ["fixed_fusion", "Agent 小队队长"],
    ["knowledge_retrieval", "Agent 小队队长"],
  ] as const)("activates the matching role for %s", (replayStageId, roleName) => {
    render(
      <MascotTeam
        phase="investigating"
        replayStageId={replayStageId}
        evidenceConflict={false}
      />,
    );
    expect(screen.getByRole("img", { name: roleName }).closest("figure")).toHaveClass("active");
  });

  it("shows a fixed evidence disagreement label", () => {
    render(
      <MascotTeam
        phase="revealed"
        replayStageId="fixed_fusion"
        evidenceConflict
      />,
    );
    expect(screen.getByText("证据分歧")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "Agent 小队队长" }).closest("figure"))
      .toHaveClass("conflict");
  });

  it("marks status icons as decorative", () => {
    const { container } = render(
      <MascotTeam phase="complete" replayStageId={null} evidenceConflict={false} />,
    );
    const icons = container.querySelectorAll("[data-mascot-status-icon]");
    expect(icons).toHaveLength(3);
    icons.forEach((icon) => expect(icon).toHaveAttribute("aria-hidden", "true"));
  });
});
