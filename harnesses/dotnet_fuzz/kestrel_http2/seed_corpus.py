#!/usr/bin/env python3
"""Create bounded decision-byte seeds for the structured HTTP/2 generator."""

from pathlib import Path
import sys


SCENARIOS = (
    "valid-single",
    "valid-continuation",
    "valid-empty-continuation",
    "valid-padded-headers",
    "valid-priority-headers",
    "valid-padded-priority-headers",
    "invalid-headers-padding",
    "headers-padding-priority-negative-fragment",
    "continuation-without-headers",
    "continuation-wrong-stream",
    "data-interleaved-with-headers",
    "data-frame-boundaries",
    "data-padding-zero",
    "data-padding-max",
    "invalid-data-padding",
    "trailers-single",
    "trailers-continuation",
    "trailers-without-end-stream",
    "data-after-end-stream",
    "data-after-reset",
    "even-stream-id",
    "connection-window-update-zero",
    "stream-window-update-zero",
    "multi-stream-pipeline",
    "padded-data-flow-burst",
    "settings-initial-window-boundary",
    "stream-id-reuse",
    "lower-stream-after-higher",
    "cross-stream-padding-and-data",
)


VARIANTS = {
    "data-empty": bytes((11, 0)),
    "data-2047": bytes((11, 15)),
    "data-2048": bytes((11, 16)),
    "data-2049": bytes((11, 17)),
    "data-16383": bytes((11, 25)),
    "data-16384": bytes((11, 26)),
    "data-16385": bytes((11, 27)),
    "headers-padding-max-local": bytes((3, 15)),
    "padding-burst-one-zero": bytes((24, 0, 0)),
    "padding-burst-255x255": bytes((24, 3, 3)),
    "padding-burst-1536x255": bytes((24, 5, 3)),
    "padding-burst-1537x255": bytes((24, 6, 3)),
    "settings-window-zero": bytes((25, 0)),
    "settings-window-one": bytes((25, 1)),
    "settings-window-default": bytes((25, 2)),
    "settings-window-max": bytes((25, 3)),
    "settings-window-overflow": bytes((25, 4)),
    "cross-stream-padding-max": bytes((28, 31, 3, 255, 255)),
}


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} OUTPUT_DIR", file=sys.stderr)
        return 2

    output = Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=True)
    for scenario_id, name in enumerate(SCENARIOS):
        (output / f"scenario-{scenario_id:02d}-{name}").write_bytes(bytes((scenario_id,)))
    for name, decisions in VARIANTS.items():
        (output / f"variant-{name}").write_bytes(decisions)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
