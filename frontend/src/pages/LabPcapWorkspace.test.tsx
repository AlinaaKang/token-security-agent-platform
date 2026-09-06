import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../api";
import type { PcapDetectionMissionResult } from "../types";
import { LabPcapWorkspace } from "./LabPcapWorkspace";

function result(status: PcapDetectionMissionResult["status"] = "completed"): PcapDetectionMissionResult {
  return {
    detection_id: "detection_0123456789abcdef0123456789abcdef",
    objective: "detect_pcap_anomalies",
    status,
    events: [],
    summary: status === "completed" ? { schema_version: 1, analyzed_count: 1, succeeded_count: 1, failed_count: 0, evidence: [], processed_samples: [{ sample_index: 1, status: "succeeded", evidence_count: 0, failure_code: null }] } : null,
    report: { confirmed_evidence_ids: [], candidate_evidence_ids: [], unknowns: status === "completed" ? ["no_localized_attack_evidence"] : [], recommended_actions: status === "completed" ? ["allow_no_rule_evidence"] : [] },
    failure_code: null,
    created_at: "2026-09-06T00:00:00Z",
  };
}

describe("LabPcapWorkspace", () => {
  beforeEach(() => {
    vi.spyOn(api, "pcapUploadCapability").mockResolvedValue({ enabled: true, max_bytes: 536870912, accepted_formats: ["pcap", "pcapng"] });
    vi.spyOn(api, "authorizePcapUpload").mockResolvedValue({ authorization_id: "pcap_auth_0123456789abcdef0123456789abcdef", max_files: 1 });
    vi.spyOn(api, "uploadPcapForDetection").mockResolvedValue(result());
    vi.spyOn(api, "getPcapMission").mockResolvedValue(result());
    vi.spyOn(api, "cancelPcapDetectionMission").mockResolvedValue(result("cancelled"));
  });
  afterEach(() => { cleanup(); vi.restoreAllMocks(); });

  it("does not send file bytes before the final confirmation", async () => {
    render(<LabPcapWorkspace />);
    expect(await screen.findByText("本地 PCAP 后端已就绪")).toBeInTheDocument();
    const file = new File([new Uint8Array(24)], "sample.pcap");
    fireEvent.change(screen.getByLabelText("选择 PCAP 文件"), { target: { files: [file] } });
    expect(screen.getByText("sample.pcap")).toBeInTheDocument();
    expect(api.authorizePcapUpload).not.toHaveBeenCalled();
    expect(api.uploadPcapForDetection).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "准备检测" }));
    expect(screen.getByText(/无网络 Docker/)).toBeInTheDocument();
    expect(api.authorizePcapUpload).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "确认上传并检测" }));

    await waitFor(() => expect(api.uploadPcapForDetection).toHaveBeenCalledWith(file, expect.stringContaining("pcap_auth_"), expect.any(Function)));
    expect(api.authorizePcapUpload).toHaveBeenCalledWith(24);
    expect(await screen.findByText("未发现可定位异常")).toBeInTheDocument();
  });

  it("keeps a recoverable selection but clears an unsupported file", async () => {
    const error = Object.assign(new Error("unsupported"), { status: 415, code: "pcap_format_unsupported" });
    vi.mocked(api.uploadPcapForDetection).mockRejectedValueOnce(error);
    render(<LabPcapWorkspace />);
    await screen.findByText("本地 PCAP 后端已就绪");
    fireEvent.change(screen.getByLabelText("选择 PCAP 文件"), { target: { files: [new File([new Uint8Array(24)], "fake.pcap") ] } });
    fireEvent.click(screen.getByRole("button", { name: "准备检测" }));
    fireEvent.click(screen.getByRole("button", { name: "确认上传并检测" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("不是有效的 PCAP 或 PCAPNG");
    expect(screen.queryByText("fake.pcap")).not.toBeInTheDocument();
  });

  it("polls a queued upload mission and can cancel a running mission", async () => {
    vi.mocked(api.uploadPcapForDetection).mockResolvedValueOnce(result("running"));
    vi.mocked(api.getPcapMission).mockResolvedValueOnce(result("running"));
    render(<LabPcapWorkspace />);
    await screen.findByText("本地 PCAP 后端已就绪");
    fireEvent.change(screen.getByLabelText("选择 PCAP 文件"), { target: { files: [new File([new Uint8Array(24)], "sample.pcap") ] } });
    fireEvent.click(screen.getByRole("button", { name: "准备检测" }));
    fireEvent.click(screen.getByRole("button", { name: "确认上传并检测" }));
    fireEvent.click(await screen.findByRole("button", { name: "取消" }));

    await waitFor(() => expect(api.cancelPcapDetectionMission).toHaveBeenCalled());
  });
});
