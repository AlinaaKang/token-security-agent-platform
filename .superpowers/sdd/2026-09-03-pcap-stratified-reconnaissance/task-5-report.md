# Task 5 Report: PCAP-only Stratified Reconnaissance Workspace

## RED evidence

Added `frontend/src/PcapReconWorkspace.test.tsx` with synthetic API fixtures covering:

- Prompt mode performs no PCAP requests and PCAP opens on `批量分诊`.
- `数据勘察` requests only the reconnaissance overview before authorization.
- Authorization requires the range click followed by a separate confirmation click.
- The exact consent copy, aggregate profile fields, phase gate, and privacy exclusions.

Initial focused run failed because the segmented control and recon workspace were missing (`Unable to find role="button" and name "批量分诊"`).

## GREEN evidence

- `npm.cmd test -- --run PcapReconWorkspace.test.tsx`: 3 passed.
- `npm.cmd test -- --run PcapReconWorkspace.test.tsx PcapSuperAgentWorkspace.test.tsx SuperAgentPage.test.tsx`: 21 passed.
- `npm.cmd test -- --run ChallengePage.test.tsx components/MascotTeam.test.tsx`: 51 passed.
- `npm.cmd test`: 233 passed across 24 files.
- `npm.cmd run build`: TypeScript and Vite production build passed.

## Implementation notes

- Added typed recon overview, authorization, mission request/result, summary, histogram, and trace contracts.
- Added `pcapReconOverview`, `authorizePcapRecon`, and `createPcapReconMission` API methods.
- Isolated recon storage under `token-security-superagent-pcap-recon-mission-id`.
- Kept Prompt and batch-triage defaults/consumers unchanged; reconnaissance is excluded from `LabToolId` and Prompt labels.
- Recon UI renders aggregate quartile, packet, duration, protocol, plaintext/encrypted, and sequence-candidate metrics only. `PcapMascotTeam` remains triage-only.

## Review fixes (RED/GREEN)

### RED

Added regressions for triage polling after mode switch, stale reconnaissance mission restoration, unknown trace-summary privacy, and narrow profile layout. The stale restore test initially left `准备开始勘察` disabled after a 404, and the unknown-summary test initially exposed `PRIVATE_UNKNOWN_TRACE`; the responsive style test initially failed because no mobile override existed.

### GREEN

- `npm.cmd test -- --run PcapReconWorkspace.test.tsx styles.test.ts`: 7 passed.
- `npm.cmd test -- --run PcapSuperAgentWorkspace.test.tsx`: 14 passed.
- `npm.cmd test`: 237 passed across 24 files.
- `npm.cmd run build`: TypeScript and Vite production build passed.

Fixes gate triage polling on the active PCAP view, load overview independently from restore, clear 404/410 and terminal recon keys, apply fixed narrative/protocol allowlists, and add a single-column mobile profile override. The shared authorization receipt now requires `max_files` and does not advertise a returned `sample_limit`.

## Protocol allowlist follow-up

The frontend protocol allowlist now matches `scripts/pcap_preflight.py` exactly: `arp`, `dns`, `eth`, `http`, `http2`, `icmp`, `icmpv6`, `ip`, `ipv6`, `quic`, `sll`, `sll2`, `tcp`, `tls`, `udp`, and `websocket`. A synthetic `arp` profile fixture verifies omitted valid protocols remain visible. Quartile keys are also exact-match allowlisted. Recon restore is gated until the stored-mission request settles, preventing a delayed stale response from affecting a newly started mission.

Verification after this fix:

- `npm.cmd test -- --run PcapReconWorkspace.test.tsx PcapSuperAgentWorkspace.test.tsx styles.test.ts`: 21 passed.
- `npm.cmd test`: 237 passed across 24 files.
- `npm.cmd run build`: TypeScript and Vite production build passed.
