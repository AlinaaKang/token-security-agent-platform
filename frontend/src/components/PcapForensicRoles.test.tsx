import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { PcapForensicRoles } from "./PcapForensicRoles";

describe("PcapForensicRoles", () => {
  afterEach(cleanup);

  it("presents three icon-only forensic roles distinct from Token mascots", () => {
    render(<PcapForensicRoles activeStage={1} />);

    const rail = screen.getByRole("region", { name: "PCAP 三角色取证流程" });
    expect(within(rail).getByText("包解析员")).toBeVisible();
    expect(within(rail).getByText("流量关联员")).toBeVisible();
    expect(within(rail).getByText("攻击研判员")).toBeVisible();
    expect(rail.querySelectorAll("svg")).toHaveLength(3);
    expect(rail.querySelector("img")).not.toBeInTheDocument();
    expect(rail).not.toHaveTextContent("语义侦探");
    expect(rail).not.toHaveTextContent("曲线侦探");
    expect(rail).not.toHaveTextContent("小队队长");
  });

  it("marks exactly one role as the current investigation step", () => {
    render(<PcapForensicRoles activeStage={2} />);

    expect(screen.getByText("流量关联员").closest("li")).toHaveAttribute("aria-current", "step");
    expect(screen.getAllByRole("listitem").filter((item) => item.hasAttribute("aria-current"))).toHaveLength(1);
  });
});
