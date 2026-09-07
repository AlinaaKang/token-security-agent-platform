import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "../api";
import { PcapProfilePage } from "./PcapProfilePage";

describe("PcapProfilePage", () => {
  afterEach(() => { cleanup(); vi.restoreAllMocks(); });

  it("presents the aggregate reconnaissance workflow without duplicating upload detection", async () => {
    vi.spyOn(api, "pcapReconOverview").mockResolvedValue({
      enabled: true,
      eligible_file_count: 2318,
      sample_limit: 100,
      sampling_method: "size_quartile_v1",
    });

    render(<PcapProfilePage />);

    expect(screen.getByRole("heading", { name: "PCAP 流量画像" })).toBeVisible();
    expect(await screen.findByText("按文件大小分层抽取 100 个代表样本")).toBeVisible();
    expect(screen.getByRole("button", { name: "准备生成画像" })).toBeVisible();
    expect(screen.queryByLabelText(/PCAP 文件/i)).not.toBeInTheDocument();
    expect(screen.getByText(/不执行攻击检测/)).toBeVisible();
    const sampleInput = screen.getByRole("spinbutton", { name: "画像样本数" });
    expect(sampleInput).toHaveValue(100);
    fireEvent.change(sampleInput, { target: { value: "240" } });
    expect(sampleInput).toHaveValue(240);
    fireEvent.click(screen.getByRole("button", { name: "全部 2318 个" }));
    expect(sampleInput).toHaveValue(2318);
  });

  it("names the 10000-file safety cap honestly when the dataset is larger", async () => {
    vi.spyOn(api, "pcapReconOverview").mockResolvedValue({
      enabled: true,
      eligible_file_count: 12000,
      sample_limit: 100,
      sampling_method: "size_quartile_v1",
    });

    render(<PcapProfilePage />);

    expect(await screen.findByRole("button", { name: "上限 10000 个" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "全部 12000 个" })).not.toBeInTheDocument();
  });
});
