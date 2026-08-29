import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  completeRolePresentation,
  createInvestigationState,
  inspectRole,
} from "../challenge/investigation";
import { MascotTeam } from "./MascotTeam";

afterEach(cleanup);

function interactiveTeam(state = createInvestigationState(), onSelect = vi.fn()) {
  return render(
    <MascotTeam
      phase="guessing"
      replayStageId={null}
      evidenceConflict={false}
      interaction={{ state, onSelect }}
    />,
  );
}

describe("MascotTeam", () => {
  it("renders visible status text that describes each interactive role button", () => {
    interactiveTeam();
    const guard = screen.getByRole("button", { name: "Guard 语义侦探" });
    const cpd = screen.getByRole("button", { name: "CPD 曲线侦探" });
    const agent = screen.getByRole("button", { name: "Agent 小队队长" });

    expect(guard).toBeEnabled();
    expect(cpd).toBeDisabled();
    expect(agent).toBeDisabled();
    expect(screen.getByText("等待点击")).toBeVisible();
    expect(screen.getByText("下一步：点击语义侦探")).toBeVisible();
    expect(screen.getByText("等待语义侦探汇报")).toBeVisible();
    expect(screen.getByText("等待曲线侦探汇报")).toBeVisible();
    expect(guard).toHaveAttribute("aria-describedby", "mascot-role-status-guard");
    expect(cpd).toHaveAttribute("aria-describedby", "mascot-role-status-cpd");
    expect(agent).toHaveAttribute("aria-describedby", "mascot-role-status-agent");
  });

  it("uses a focusable native button with the ready role state", () => {
    interactiveTeam();
    const guard = screen.getByRole("button", { name: "Guard 语义侦探" });
    expect(guard).toBeInstanceOf(HTMLButtonElement);
    expect(guard).toHaveAttribute("type", "button");
    expect(guard).toHaveAttribute("aria-pressed", "false");
    guard.focus();
    expect(guard).toHaveFocus();
  });

  it("emits the selected role from click activation", () => {
    const onSelect = vi.fn();
    interactiveTeam(createInvestigationState(), onSelect);
    fireEvent.click(screen.getByRole("button", { name: /Guard 语义侦探/ }));
    expect(onSelect).toHaveBeenCalledWith("guard");
  });

  it("does not select locked detectives", () => {
    const onSelect = vi.fn();
    interactiveTeam(createInvestigationState(), onSelect);
    fireEvent.click(screen.getByRole("button", { name: "CPD 曲线侦探" }));
    fireEvent.click(screen.getByRole("button", { name: "Agent 小队队长" }));
    expect(onSelect).not.toHaveBeenCalled();
  });

  it("locks every role while the selected detective presents", () => {
    const state = inspectRole(createInvestigationState(), "guard");
    interactiveTeam(state);
    const figure = screen.getByRole("button", { name: /Guard 语义侦探/ }).closest("figure");
    expect(figure).toHaveAttribute("data-role-state", "presenting");
    expect(figure).toHaveAttribute("data-motion", "idle");
    screen.getAllByRole("button").forEach((button) => expect(button).toBeDisabled());
    expect(screen.queryByText(/下一步：点击/)).not.toBeInTheDocument();
  });

  it("keeps a reviewed role selected while the next role hops in place", () => {
    const first = inspectRole(createInvestigationState(), "guard");
    const guardDone = completeRolePresentation(first, "guard");
    const reviewed = inspectRole(guardDone, "guard");
    interactiveTeam(reviewed);
    const figure = screen.getByRole("button", { name: /Guard 语义侦探/ }).closest("figure");
    expect(figure).toHaveAttribute("data-role-state", "visited");
    expect(figure).toHaveAttribute("data-motion", "idle");
    expect(screen.getByRole("button", { name: "Guard 语义侦探" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("正在回看")).toHaveAttribute("id", "mascot-role-status-guard");
    expect(screen.getByRole("button", { name: "CPD 曲线侦探" }).closest("figure"))
      .toHaveAttribute("data-motion", "hop");
    expect(screen.getByText("下一步：点击曲线侦探")).toBeVisible();
  });

  it("preserves the existing automatic replay mapping without interaction props", () => {
    render(<MascotTeam phase="investigating" replayStageId="entropy_cpd" evidenceConflict={false} />);
    expect(screen.getByRole("button", { name: "CPD 曲线侦探" }).closest("figure"))
      .toHaveAttribute("data-motion", "hop");
  });

  it("keeps all roles mounted and activates CPD for the entropy stage", () => {
    const { container } = render(
      <MascotTeam
        phase="investigating"
        replayStageId="entropy_cpd"
        evidenceConflict={false}
      />,
    );

    expect(screen.getByRole("button", { name: "Guard 语义侦探" }).querySelector("img"))
      .toHaveAttribute("src", "/mascots/guard-detective.webp");
    expect(screen.getByRole("button", { name: "CPD 曲线侦探" }).closest("figure"))
      .toHaveClass("active");
    expect(screen.getByRole("button", { name: "Agent 小队队长" }).closest("figure"))
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
    expect(screen.getByRole("button", { name: roleName }).closest("figure")).toHaveClass("active");
  });

  it.each([
    ["semantic_guard", "Guard 语义侦探"],
    ["token_observation", "CPD 曲线侦探"],
    ["entropy_cpd", "CPD 曲线侦探"],
    ["fixed_fusion", "Agent 小队队长"],
    ["knowledge_retrieval", "Agent 小队队长"],
  ] as const)("maps %s to an in-place hop for %s", (stageId, roleName) => {
    render(<MascotTeam phase="investigating" replayStageId={stageId} evidenceConflict={false} />);
    expect(screen.getByRole("button", { name: roleName }).closest("figure"))
      .toHaveAttribute("data-motion", "hop");
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
    expect(screen.getByRole("button", { name: "Agent 小队队长" }).closest("figure"))
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
      expect(screen.getByRole("button", { name: "Agent 小队队长" }).closest("figure"))
        .not.toHaveClass("conflict");
      screen.getAllByRole("figure").forEach((figure) => {
        expect(figure).not.toHaveAttribute("data-motion", "conflict");
      });
    },
  );

  it("uses conflict only for the captain without a misleading central decoration", () => {
    const { container } = render(
      <MascotTeam phase="revealed" replayStageId="fixed_fusion" evidenceConflict />,
    );
    expect(screen.getByRole("button", { name: "Agent 小队队长" }).closest("figure"))
      .toHaveAttribute("data-motion", "conflict");
    expect(container.querySelector("[data-evidence-desk]")).not.toBeInTheDocument();
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
