import { describe, expect, it } from "vitest";

import { formatPcapFileSize, validatePcapSelection } from "./pcapUpload";

describe("PCAP upload selection", () => {
  it("rejects unsupported, empty, and oversized files before authorization", () => {
    expect(validatePcapSelection(new File(["x"], "sample.txt"))).toBe("请选择 .pcap 或 .pcapng 文件。");
    expect(validatePcapSelection(new File([], "empty.pcap"))).toBe("文件为空，请重新选择。");
    expect(validatePcapSelection(new File(["1234"], "large.pcapng"), 3)).toBe("文件超过当前允许的上传大小。");
  });

  it("accepts PCAP formats case-insensitively and formats the local summary", () => {
    expect(validatePcapSelection(new File(["1234"], "sample.PCAP"), 4)).toBeNull();
    expect(validatePcapSelection(new File(["1234"], "sample.pcapng"))).toBeNull();
    expect(formatPcapFileSize(401)).toBe("401 B");
    expect(formatPcapFileSize(1536)).toBe("1.5 KiB");
  });
});
