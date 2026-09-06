import { cleanup, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";

import { AgentSidebar } from "./AgentSidebar";

afterEach(cleanup);

describe("AgentSidebar", () => {
  it("groups cases, professional workspaces, and agent resources", () => {
    render(<MemoryRouter initialEntries={["/super-agent"]}><AgentSidebar /></MemoryRouter>);

    const navigation = screen.getByRole("navigation", { name: "主导航" });
    const groups = within(navigation).getAllByRole("group");
    expect(groups.map((group) => group.getAttribute("aria-label"))).toEqual([
      "安全案件", "专业工作区", "智能体资源",
    ]);
    expect(screen.getByRole("link", { name: "Token 侦探挑战" })).toHaveAttribute("href", "/challenge");
    expect(screen.getByRole("link", { name: "安全智能体" })).toHaveAttribute("aria-current", "page");
  });

  it("uses semantic headings above navigation items", () => {
    render(<MemoryRouter><AgentSidebar /></MemoryRouter>);

    expect(screen.getAllByRole("heading", { level: 2 }).map((item) => item.textContent)).toEqual([
      "安全案件", "专业工作区", "智能体资源",
    ]);
  });
});
