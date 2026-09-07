# Prompt And PCAP Professional Workspace Separation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Separate Prompt and PCAP professional tools, merge Prompt analysis with its event view, add a truthful PCAP detective challenge, and center the PCAP welcome shortcuts.

**Architecture:** Keep all existing backend contracts and detection components. Reorganize only frontend routing, navigation, view composition, and layout; compatibility routes remain valid.

**Tech Stack:** React, React Router, TypeScript, Vitest, Testing Library, CSS.

## Global Constraints

- Do not change Prompt or PCAP detection algorithms, thresholds, event storage, authorization, or Docker isolation.
- Do not change Token detective challenge rules or scoring.
- PCAP challenge results must come from the existing detector and must not claim fabricated accuracy or scores.

### Task 1: Navigation and welcome layout

**Files:** `frontend/src/components/AgentSidebar.tsx`, `frontend/src/components/AgentSidebar.test.tsx`, `frontend/src/App.test.tsx`, `frontend/src/styles.css`, `frontend/src/styles.test.ts`

- [ ] Write failing tests for the four navigation groups, exact Prompt/PCAP links, and three-column PCAP welcome layout.
- [ ] Run the focused tests and confirm the old grouping and fixed four-column layout fail.
- [ ] Move the links and use an auto-fitting equal-column grid.
- [ ] Run focused tests and confirm they pass.

### Task 2: Prompt analysis and event views

**Files:** `frontend/src/pages/AnalyzePage.tsx`, `frontend/src/pages/EventsPage.tsx`, `frontend/src/App.tsx`, `frontend/src/App.test.tsx`

- [ ] Write failing integration tests for analysis/event tabs and `/events` compatibility.
- [ ] Run the tests and confirm the combined workspace is absent.
- [ ] Add shared view navigation, keep each existing data surface intact, and mark Prompt analysis active for both views.
- [ ] Run focused tests and confirm they pass.

### Task 3: Fixed lab surfaces

**Files:** `frontend/src/pages/LabPage.tsx`, `frontend/src/LabPage.test.tsx`, `frontend/src/tourConfig.ts`

- [ ] Write failing tests proving each surface URL renders only its matching input type.
- [ ] Run the tests and confirm the old in-page switch violates isolation.
- [ ] Resolve the surface from the URL and remove the in-page type switch.
- [ ] Run focused tests and confirm both routes pass.

### Task 4: PCAP detective challenge

**Files:** `frontend/src/pages/PcapChallengePage.tsx`, `frontend/src/PcapChallengePage.test.tsx`, `frontend/src/App.tsx`, `frontend/src/tourConfig.ts`

- [ ] Write a failing route test for the independent challenge heading, explanation, and real PCAP detection workspace.
- [ ] Run the test and confirm the route is missing.
- [ ] Add the page by composing `PcapDetectionWorkspace` under explicit challenge boundaries.
- [ ] Run focused tests and confirm the real authorization flow remains present.

### Task 5: Verification

- [ ] Run `npm.cmd test` in `frontend` and require zero failures.
- [ ] Run `npm.cmd run build` and require exit code 0.
- [ ] Run `git diff --check` and the Impeccable detector on changed UI files.
- [ ] Capture desktop and mobile screenshots of Prompt analysis, Prompt event view, Prompt lab, PCAP lab, PCAP challenge, and PCAP welcome.
