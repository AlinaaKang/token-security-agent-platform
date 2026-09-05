# Dual Backend Routing Design

## Goal

Allow one local Web session to use the AutoDL Prompt/Token agent and the local Docker PCAP agent without moving either service or changing the existing pages.

## Routing

- Browser `/health` and `/api/*` requests go to the main AutoDL tunnel, defaulting to `http://127.0.0.1:18001`.
- PCAP client methods use an internal `/pcap-api/*` prefix. Vite rewrites that prefix to `/api/*` and proxies it to the local PCAP backend, defaulting to `http://127.0.0.1:18000`.
- `TOKEN_SECURITY_REMOTE_API_TARGET` and `TOKEN_SECURITY_PCAP_API_TARGET` may override the two development targets.
- Prompt SuperAgent mission reads remain on `/api`; PCAP mission create, read, and cancel operations all use `/pcap-api`.

## Constraints

- Do not change backend routes, Prompt analysis behavior, challenge scoring, PCAP authorization, or privacy boundaries.
- Do not expose either backend address in the rendered UI.
- Production deployments must reproduce the same two-prefix reverse-proxy contract.

## Verification

Add API URL contract tests, run affected page tests and the full frontend suite, build the production bundle, then verify remote `/health` and local PCAP overview through the running Web proxy.
