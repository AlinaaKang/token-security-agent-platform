import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

const health = {
  status: "ok",
  model: { ready: true, model_id: "qwen-model" },
  detector: { ready: true, calibration_version: "cal-v2" },
  lab: { enabled: true, ready: true, reason: "ready" },
};

const scenarios = [
  { scenario_id: "synthetic_safe", label: "普通无害", scenario_kind: "synthetic", attack_family: null, ready: true },
  { scenario_id: "synthetic_shift", label: "无害格式突变", scenario_kind: "synthetic", attack_family: null, ready: true },
  { scenario_id: "gcg_01", label: "GCG", scenario_kind: "protected", attack_family: "gcg", ready: true },
  { scenario_id: "autodan_01", label: "AutoDAN", scenario_kind: "protected", attack_family: "autodan", ready: true },
  { scenario_id: "adv_01", label: "AdvPrompter", scenario_kind: "protected", attack_family: "advprompter", ready: true },
];

function response(payload: unknown, ok = true) {
  return Promise.resolve({ ok, status: ok ? 200 : 503, json: async () => payload });
}

function installFetch(options: { health?: unknown; scenarios?: unknown } = {}) {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    requests.push({ url, init });
    if (url === "/health") return response(options.health ?? health);
    if (url === "/api/v1/lab/scenarios") return response(options.scenarios ?? scenarios);
    throw new Error(`Unexpected request: ${url}`);
  }));
  return requests;
}

describe("token detective challenge setup", () => {
  beforeEach(() => {
    window.history.pushState({}, "", "/challenge");
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("adds an isolated challenge route with speed and full setup choices", async () => {
    const requests = installFetch();
    render(<App />);

    expect(await screen.findByRole("main", { name: "Token 侦探挑战" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "侦探挑战" })).toHaveClass("active");
    expect(screen.getByRole("link", { name: "专业调查" })).toHaveAttribute("href", "/lab");
    expect(screen.getByRole("button", { name: "三关速战" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "五关完整挑战" })).toBeEnabled();
    expect(screen.getByRole("img", { name: "Guard 语义侦探" })).toBeInTheDocument();
    expect(requests.map((item) => item.url).sort()).toEqual([
      "/api/v1/lab/scenarios",
      "/health",
    ]);
    expect(requests.every((item) => item.init?.method === undefined)).toBe(true);
  });

  it("disables setup when the lab is unavailable", async () => {
    installFetch({
      health: { ...health, lab: { enabled: false, ready: false, reason: "disabled" } },
    });
    render(<App />);

    expect(await screen.findByText("挑战模式不可用")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "三关速战" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "五关完整挑战" })).toBeDisabled();
  });

  it("keeps speed mode available and labels a missing full-mode family", async () => {
    installFetch({
      scenarios: scenarios.filter((scenario) => scenario.attack_family !== "gcg"),
    });
    render(<App />);

    expect(await screen.findByText("完整挑战缺少：GCG")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "三关速战" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "五关完整挑战" })).toBeDisabled();
  });

  it("treats a legacy health response without lab state as unavailable", async () => {
    const { lab: _, ...legacyHealth } = health;
    installFetch({ health: legacyHealth });
    render(<App />);

    expect(await screen.findByText("挑战模式不可用")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "三关速战" })).toBeDisabled();
  });
});
