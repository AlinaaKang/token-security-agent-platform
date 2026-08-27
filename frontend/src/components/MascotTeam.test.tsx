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

  it.each([
    ["semantic_guard", "Guard 语义侦探", "approach"],
    ["token_observation", "CPD 曲线侦探", "approach"],
    ["entropy_cpd", "CPD 曲线侦探", "inspect"],
    ["fixed_fusion", "Agent 小队队长", "approach"],
    ["knowledge_retrieval", "Agent 小队队长", "conclude"],
  ] as const)("maps %s to %s motion", (stageId, roleName, motion) => {
    render(<MascotTeam phase="investigating" replayStageId={stageId} evidenceConflict={false} />);
    expect(screen.getByRole("img", { name: roleName }).closest("figure"))
      .toHaveAttribute("data-motion", motion);
    expect(screen.getAllByRole("figure").filter((figure) => figure.dataset.motion !== "idle"))
      .toHaveLength(1);
  });

  it("returns every mascot to quiet idle while the player answers", () => {
    render(<MascotTeam phase="guessing" replayStageId="entropy_cpd" evidenceConflict={false} />);
    screen.getAllByRole("figure").forEach((figure) => {
      expect(figure).toHaveAttribute("data-motion", "idle");
      expect(figure).not.toHaveClass("active");
    });
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

  it.each(["investigating", "guessing"] as const)(
    "keeps evidence conflict hidden during %s",
    (phase) => {
      render(
        <MascotTeam
          phase={phase}
          replayStageId="fixed_fusion"
          evidenceConflict
        />,
      );

      expect(screen.queryByText("证据分歧")).not.toBeInTheDocument();
      expect(screen.getByRole("img", { name: "Agent 小队队长" }).closest("figure"))
        .not.toHaveClass("conflict");
      screen.getAllByRole("figure").forEach((figure) => {
        expect(figure).not.toHaveAttribute("data-motion", "conflict");
      });
    },
  );

  it("uses conflict only for the captain and renders a decorative evidence desk", () => {
    const { container } = render(
      <MascotTeam phase="revealed" replayStageId="fixed_fusion" evidenceConflict />,
    );
    expect(screen.getByRole("img", { name: "Agent 小队队长" }).closest("figure"))
      .toHaveAttribute("data-motion", "conflict");
    expect(container.querySelector("[data-evidence-desk]"))
      .toHaveAttribute("aria-hidden", "true");
  });

  it("marks all three mascots for a one-shot completion celebration", () => {
    render(<MascotTeam phase="complete" replayStageId={null} evidenceConflict={false} />);
    expect(screen.getAllByRole("figure")).toHaveLength(3);
    screen.getAllByRole("figure").forEach((figure) => {
      expect(figure).toHaveAttribute("data-motion", "celebrate");
    });
  });

  it("keeps the same three figures mounted across replay and guessing states", () => {
    const { rerender } = render(
      <MascotTeam phase="investigating" replayStageId="semantic_guard" evidenceConflict={false} />,
    );
    const figures = screen.getAllByRole("figure");

    rerender(<MascotTeam phase="guessing" replayStageId={null} evidenceConflict={false} />);

    expect(screen.getAllByRole("figure")).toHaveLength(3);
    expect(screen.getAllByRole("figure")).toEqual(figures);
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
