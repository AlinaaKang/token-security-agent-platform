export function validatePcapSelection(file: File, maxBytes = 0): string | null {
  const extension = file.name.split(".").pop()?.toLowerCase();
  if (extension !== "pcap" && extension !== "pcapng") return "请选择 .pcap 或 .pcapng 文件。";
  if (file.size < 1) return "文件为空，请重新选择。";
  if (maxBytes > 0 && file.size > maxBytes) return "文件超过当前允许的上传大小。";
  return null;
}

export function formatPcapFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}
