# Dual Backend Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route model-backed requests to AutoDL and PCAP requests to the local Docker backend from one Web session.

**Architecture:** Give PCAP API calls a browser-only `/pcap-api` namespace and let Vite rewrite it to the backend's existing `/api` namespace. Keep all non-PCAP calls on the normal `/api` namespace.

**Tech Stack:** React 19, TypeScript, Vite 7, Vitest.

## Global Constraints

- Keep backend APIs and all detection behavior unchanged.
- Keep Prompt and challenge requests on the remote backend.
- Keep every PCAP operation on the local backend.
- Preserve existing privacy and authorization boundaries.

---

### Task 1: Lock the client routing contract

**Files:**
- Create: `frontend/src/api.test.ts`
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/pages/PcapSuperAgentWorkspace.tsx`
- Modify: `frontend/src/pages/PcapReconWorkspace.tsx`
- Modify: `frontend/src/pages/PcapDetectionWorkspace.tsx`

**Interfaces:**
- Consumes: existing `api` client methods.
- Produces: `api.getPcapMission()` and `/pcap-api/v1/superagent/*` requests for every PCAP operation.

- [x] Write API URL tests proving model and PCAP requests use different prefixes.
- [x] Run the test and verify it fails against the single-backend client.
- [x] Move all PCAP create/read/cancel calls to the PCAP namespace.
- [x] Run API and PCAP page tests and verify they pass.

### Task 2: Configure and verify both proxies

**Files:**
- Modify: `frontend/vite.config.ts`
- Modify: `README.md`
- Modify: `docs/competition-delivery-guide.md`

**Interfaces:**
- Consumes: `/api`, `/health`, and `/pcap-api` browser requests.
- Produces: configurable remote and local reverse-proxy targets.

- [x] Add the main and PCAP proxy targets with the `/pcap-api` rewrite.
- [x] Document the two local ports and environment overrides.
- [x] Run the full frontend suite and production build.
- [x] Restart Vite and verify remote health plus local PCAP overview through port 5173.
- [x] Commit the verified implementation.
