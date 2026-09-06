import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "./api";

function ok(payload: object = {}) {
  return Promise.resolve(new Response(JSON.stringify(payload), { status: 200 }));
}

describe("API backend routing", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("keeps model requests on the main API namespace", async () => {
    const fetchMock = vi.fn((_url: string) => ok());
    vi.stubGlobal("fetch", fetchMock);

    await api.health();
    await api.superAgentCapabilities();

    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "/health",
      "/api/v1/superagent/capabilities",
    ]);
  });

  it("routes every PCAP mission operation through the local namespace", async () => {
    const fetchMock = vi.fn((_url: string) => ok());
    vi.stubGlobal("fetch", fetchMock);
    const missionId = "detection_0123456789abcdef0123456789abcdef";

    await api.pcapDetectionOverview();
    await api.createPcapDetectionMission({
      objective: "detect_pcap_anomalies",
      authorization_id: "pcap_auth_0123456789abcdef0123456789abcdef",
      start_index: 0,
    });
    await api.getPcapMission(missionId);
    await api.cancelPcapDetectionMission(missionId);

    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "/pcap-api/v1/superagent/pcap/detection/overview",
      "/pcap-api/v1/superagent/missions",
      `/pcap-api/v1/superagent/missions/${missionId}`,
      `/pcap-api/v1/superagent/missions/${missionId}/cancel`,
    ]);
  });

  it("uploads the exact browser file through the local namespace without a filename header", async () => {
    class FakeXhr {
      static latest: FakeXhr;
      method = "";
      url = "";
      status = 201;
      responseText = JSON.stringify({ detection_id: "detection_0123456789abcdef0123456789abcdef" });
      headers = new Map<string, string>();
      body: Document | XMLHttpRequestBodyInit | null = null;
      upload = {} as XMLHttpRequestUpload;
      onload: (() => void) | null = null;
      onerror: (() => void) | null = null;
      onabort: (() => void) | null = null;
      constructor() { FakeXhr.latest = this; }
      open(method: string, url: string) { this.method = method; this.url = url; }
      setRequestHeader(name: string, value: string) { this.headers.set(name, value); }
      send(body: Document | XMLHttpRequestBodyInit | null) { this.body = body; }
    }
    vi.stubGlobal("XMLHttpRequest", FakeXhr);
    const file = new File([bytes(24)], "PRIVATE-NAME.pcap", { type: "application/vnd.tcpdump.pcap" });
    const progress = vi.fn();

    const pending = api.uploadPcapForDetection(
      file,
      "pcap_auth_0123456789abcdef0123456789abcdef",
      progress,
    );
    const xhr = FakeXhr.latest!;
    (xhr.upload.onprogress as (event: ProgressEvent) => void)({ lengthComputable: true, loaded: 12, total: 24 } as ProgressEvent);
    xhr.onload?.();
    await pending;

    expect(xhr.method).toBe("POST");
    expect(xhr.url).toBe("/pcap-api/v1/superagent/pcap/detection/uploads");
    expect(xhr.body).toBe(file);
    expect(xhr.headers.get("Content-Type")).toBe("application/octet-stream");
    expect(xhr.headers.get("X-PCAP-Authorization")).toContain("pcap_auth_");
    expect([...xhr.headers.keys()].join(" ").toLowerCase()).not.toContain("filename");
    expect(progress).toHaveBeenCalledWith(50);
  });
});

function bytes(length: number) {
  return new Uint8Array(length);
}
