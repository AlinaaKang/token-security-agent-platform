import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { PcapChallengePage } from "./pages/PcapChallengePage";

describe("PcapChallengePage", () => {
  afterEach(cleanup);

  it("uses built-in evidence cases instead of repeating the upload detector", () => {
    render(<PcapChallengePage />);

    expect(screen.getByRole("main", { name: "PCAP 侦探挑战" })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "PCAP 异常检测工作区" })).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/pcap 文件/i)).not.toBeInTheDocument();
    expect(screen.getByText(/内置脱敏流量关卡/)).toBeVisible();
  });

  it("lets the player inspect the team, mark packets, and receive a scored reveal", () => {
    render(<PcapChallengePage />);
    fireEvent.click(screen.getByRole("button", { name: "开始挑战" }));

    expect(screen.getByRole("region", { name: "PCAP 三角色取证流程" })).toBeVisible();
    const evidence = screen.getByRole("region", { name: "公开 Packet 证据" });
    expect(evidence).toBeVisible();
    expect(within(evidence).getByText("Packet 1-3")).toBeVisible();
    expect(within(evidence).getByText("Packet 4-4")).toBeVisible();
    expect(within(evidence).getByText("Packet 5-7")).toBeVisible();
    expect(within(evidence).getByText(/布尔条件组合/)).toBeVisible();
    expect(within(evidence).getByText(/POST \/login HTTP\/1.1/)).toBeVisible();
    expect(within(evidence).getByText(/admin%27\+OR/)).toBeVisible();
    expect(within(evidence).getByText("00:00.084")).toBeVisible();
    expect(screen.getByText(/先建立正常基线，再定位首次偏离/)).toBeVisible();
    expect(screen.queryByRole("button", { name: "回放捕获 1" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Packet 4-4" }));
    fireEvent.click(screen.getByRole("radio", { name: "SQL 注入" }));
    fireEvent.click(screen.getByRole("radio", { name: "认证绕过" }));
    fireEvent.click(screen.getByRole("button", { name: "提交研判" }));

    expect(screen.getByRole("region", { name: "挑战评分" })).toBeVisible();
    expect(screen.getByText("本关得分 100")).toBeVisible();
    expect(screen.getByText(/Packet 4-4 是最早出现可复核注入特征的请求/)).toBeVisible();
  });

  it("provides three distinct evidence-based rounds", () => {
    render(<PcapChallengePage />);
    fireEvent.click(screen.getByRole("button", { name: "开始挑战" }));

    expect(screen.getByRole("heading", { name: "登录接口异常请求" })).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Packet 4-4" }));
    fireEvent.click(screen.getByRole("radio", { name: "SQL 注入" }));
    fireEvent.click(screen.getByRole("radio", { name: "认证绕过" }));
    fireEvent.click(screen.getByRole("button", { name: "提交研判" }));
    fireEvent.click(screen.getByRole("button", { name: "进入下一关" }));

    expect(screen.getByRole("heading", { name: "管理接口参数异常" })).toBeVisible();
    expect(screen.getByText(/命令分隔符/)).toBeVisible();
  });
});
