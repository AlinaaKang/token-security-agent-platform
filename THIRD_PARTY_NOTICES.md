# Third-Party Notices

## CPDonline

Source: <https://github.com/cpdonline/cpdonline>

This project uses CPDonline as an attributed reference for robust baseline estimation, positive Page-CUSUM behavior, dataset schemas, and synthetic parity fixtures. The Token onset backtracking, calibration identity enforcement, detector fusion, counterfactual verification, policy workflow, and minimal intervention logic are project-created extensions and are not claimed as part of CPDonline.

```text
MIT License

Copyright (c) 2026 cpdonline

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Qwen3Guard-Gen-0.6B

Model: `Qwen/Qwen3Guard-Gen-0.6B`

Source: <https://modelscope.cn/models/Qwen/Qwen3Guard-Gen-0.6B>

License: Apache License 2.0. The downloaded snapshot includes the complete `LICENSE` file. This project uses Qwen3Guard as a third-party semantic safety classifier and does not claim its weights, training data, categories, or base classification capability as project-created work.

Deployment identity recorded on 2026-08-26:

- ModelScope resolved revision: `master` (the API did not expose an immutable commit ID)
- `model.safetensors` bytes: `1503300328`
- Snapshot total bytes: `1519209737`
- `model.safetensors` SHA-256: `4f3ce47ebd968cddb67de08d8764f8ede7c410a7d1fb9e08145a4c7a2f2e5c0f`

The runtime version therefore combines the resolved branch and the immutable weight hash instead of representing `master` as an immutable commit.

## Offline Security Knowledge Snapshot

The `official-v1` snapshot contains project-authored Chinese summaries and links to official OWASP GenAI Security Project, MITRE ATLAS, and NIST AI Risk Management Framework materials. It does not copy complete pages or include source attack examples. The original organizations retain all rights in their respective materials; the links and source versions recorded on each card are the authoritative references.

Deployment identity recorded on 2026-08-26:

- Snapshot: `official-v1`
- Cards: 12
- Cards SHA-256: `05230ee8581ff8dd486c0d1d39cc54ce34b0e0e2b757fea19543ec1594e7e32c`
- MITRE ATLAS data version: `2026.07`
- NIST source: AI Risk Management Framework 1.0
- OWASP source: GenAI Security Project 2025 risk pages

The snapshot is an offline, immutable competition artifact. Updating external material is a separate controlled process and is not performed during request handling.

## Agent Ablation Source Candidates

The frozen agent ablation benchmark records candidate upstream repositories before any sample enters headline metrics. A repository revision alone is not treated as a verified dataset. The exact protected data file, its SHA-256, repository license, and attribution must also pass the source audit.

Candidate revisions recorded on 2026-08-26:

- AutoDAN-HGA: <https://github.com/SheltonLiu-N/AutoDAN>, `34062e964185693e81a6775b4f0d00bfd7507612`
- AdvPrompter: <https://github.com/facebookresearch/advprompter>, `802a500c91f1dcd7c8b76869d3e39bf8e40ed7d7`
- GCG reference implementation: <https://github.com/llm-attacks/llm-attacks>, `098262edf85f807224e70ecd87b9d83716bf6b73`
- HarmBench candidate semantic-risk source: <https://github.com/centerforaisafety/HarmBench>, `8e1604d1171fe8a48d8febecd22f600e462bdcdd`
- XSTest candidate hard-negative source: <https://github.com/paul-rottger/exaggerated-safety>, `d7bb5bd738c1fcbc36edd83d5e7d1b71a3e2d84d`

These candidates remain `unverified` until the file and license audit is complete. BEAST remains `source_unavailable` because an official repository or immutable released artifact has not been verified. The project does not redistribute attack Prompt text from these sources.
