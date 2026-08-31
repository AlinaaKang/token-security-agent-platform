from __future__ import annotations

import json
import sys
from pathlib import Path


_INSPECTOR_DIRECTORY = str(Path(__file__).resolve().parent)
sys.path[:] = [entry for entry in sys.path if entry != _INSPECTOR_DIRECTORY]
import inspect

sys.path.insert(0, _INSPECTOR_DIRECTORY)

from pcap_preflight import PreflightError, inspect_capture


def main() -> int:
    try:
        report = inspect_capture(Path("/input/capture"))
    except PreflightError as exc:
        print(f"pcap_preflight_error={exc.code}", file=sys.stderr)
        return 2
    except Exception:
        print("pcap_preflight_error=unexpected_failure", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
