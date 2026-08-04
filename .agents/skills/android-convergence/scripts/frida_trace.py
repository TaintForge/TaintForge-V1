#!/usr/bin/env python3
"""Record Android sink telemetry from an authorized emulator with Frida."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

PACKAGE = re.compile(r"^[A-Za-z][A-Za-z0-9_.]*$")


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


def attest_emulator(serial: str) -> None:
    if not re.fullmatch(r"emulator-\d+", serial):
        fail("hardware devices are forbidden; serial must be emulator-<port>")
    result = subprocess.run(
        ["adb", "-s", serial, "shell", "getprop", "ro.kernel.qemu"],
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    if result.returncode != 0 or result.stdout.strip() != "1":
        fail("selected serial did not attest as an Android emulator")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--spawn", action="store_true")
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    if not PACKAGE.fullmatch(args.package):
        fail(f"invalid package: {args.package!r}")
    if not 1 <= args.seconds <= 3600:
        fail("--seconds must be between 1 and 3600")
    attest_emulator(args.serial)

    try:
        import frida
    except ImportError:
        fail("Frida Python bindings are not installed (pip install frida frida-tools)")

    output = args.out or Path("workspace/android/telemetry") / f"{args.package}.jsonl"
    output.parent.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).with_name("frida_trace.js").read_text(encoding="utf-8")

    try:
        device = frida.get_device(args.serial, timeout=5)
    except Exception as error:
        fail(f"Frida device {args.serial!r} unavailable: {error}")

    spawned_pid = None
    try:
        if args.spawn:
            spawned_pid = device.spawn([args.package])
            session = device.attach(spawned_pid)
        else:
            session = device.attach(args.package)
        script = session.create_script(source)
        stream = output.open("a", encoding="utf-8")

        def on_message(message, data):
            record = {
                "frida_message": message,
                "binary_data_length": len(data) if data else 0,
                "host_ts": time.time(),
            }
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
            stream.flush()

        script.on("message", on_message)
        script.load()
        if spawned_pid is not None:
            device.resume(spawned_pid)
        print(f"[frida-trace] package={args.package} serial={args.serial} -> {output}")
        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline:
            time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    except Exception as error:
        fail(f"Frida trace failed: {error}")
    finally:
        if "stream" in locals():
            stream.close()
        if "session" in locals():
            session.detach()


if __name__ == "__main__":
    main()
