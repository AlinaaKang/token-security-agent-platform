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
});
