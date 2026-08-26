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

## Agent Ablation Sources

The frozen agent ablation benchmark treats a source as verified only when its repository revision, license, attribution, and exact protected file SHA-256 all match the committed registry. The audit performed on 2026-08-26 verified these files:

- CPDonline `full_prompt_dataset.csv`, `cd1833a77577e3d814c61b25181df7ddb5fcc22419fb89bc3f0890ef4c12b588`.
- CPDonline `llama2_7B_foo_opt_624.csv`, `9193519b6e16696a53df488f90740c1711f6bd9f1ee979ba80baa3ddf288f082`.
- CPDonline `gcg_llamaguard_bypass.csv`, `6dbdcd82ea8bec98caa8c0c8c33c90a4c5468ee512de9bfcfa4d392791b669be`.
- HarmBench `harmbench_behaviors_text_test.csv`, commit `8e1604d1171fe8a48d8febecd22f600e462bdcdd`, MIT, `75d257b3e7428c52eb7b0154318f455af3e01b09a3794b5e2f3d36054f3c0e29`.
- XSTest `xstest_prompts.csv`, commit `d7bb5bd738c1fcbc36edd83d5e7d1b71a3e2d84d`, CC-BY-4.0, `11783fb294ed017473ee53c207d71f2161c7672c8d0b037501e78387f801cb5a`.

CPDonline remains MIT licensed and attributed to Copyright (c) 2026 cpdonline. HarmBench is attributed to Copyright (c) 2024 centerforaisafety. XSTest is attributed to Paul Roettger, Hannah Rose Kirk, Bertie Vidgen, Giuseppe Attanasio, Federico Bianchi, and Dirk Hovy.

The AutoDAN-HGA repository was fixed to the revision in `configs/ablation_sources.json`, but no generated suffix artifact from that repository was selected for this benchmark. The current AutoDAN, AdvPrompter, and GCG family samples are the separately audited CPDonline artifacts above, not outputs regenerated from the three reference implementations. BEAST remains `source_unavailable`. The project does not redistribute Prompt text from any source.
