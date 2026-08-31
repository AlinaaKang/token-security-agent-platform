from __future__ import annotations

import json
import sys
from pathlib import Path


def _emit_error(code: str) -> None:
    print(f"pcap_preflight_error={code}", file=sys.stderr)


def main() -> int:
    try:
        inspector_directory = str(Path(__file__).resolve().parent)
        sys.path[:] = [entry for entry in sys.path if entry != inspector_directory]
        import inspect as _standard_library_inspect

        del _standard_library_inspect
        sys.path.insert(0, inspector_directory)
        from pcap_preflight import PreflightError, inspect_capture

        try:
            report = inspect_capture(Path("/input/capture"))
        except PreflightError as exc:
            _emit_error(exc.code)
            return 2
        print(json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception:
        _emit_error("unexpected_failure")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
