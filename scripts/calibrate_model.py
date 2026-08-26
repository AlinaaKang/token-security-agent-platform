from __future__ import annotations


DEPRECATION_MESSAGE = (
    "Unlabeled benign-only calibration is disabled because it does not reproduce "
    "the paper method. Use scripts/benchmark_cpdonline.py with frozen labeled "
    "calibration, development, and test splits."
)


def main() -> None:
    raise SystemExit(DEPRECATION_MESSAGE)


if __name__ == "__main__":
    main()
