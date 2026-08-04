#!/usr/bin/env python3
"""Emulator-only wrapper for reproducible Android component probes."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

TOKEN = re.compile(r"^[A-Za-z0-9_.$:/@+-]+$")
PACKAGE = re.compile(r"^[A-Za-z][A-Za-z0-9_.]*$")
COMPONENT = re.compile(r"^[A-Za-z0-9_.$]+$")
ACTION = re.compile(r"^[A-Za-z0-9_.$-]+$")


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


def validate_package(value: str) -> str:
    if not PACKAGE.fullmatch(value):
        fail(f"invalid package: {value!r}")
    return value


def normalize_component(package: str, value: str) -> str:
    if value.startswith("."):
        value = package + value
    elif "." not in value:
        value = package + "." + value
    if not COMPONENT.fullmatch(value):
        fail(f"invalid component: {value!r}")
    return value


def validate_uri(value: str, allowed_authority: str | None = None) -> str:
    if any(ch in value for ch in ("\x00", "\n", "\r")):
        fail("URI contains control characters")
    parsed = urlparse(value)
    if not parsed.scheme:
        fail("URI must include a scheme")
    if parsed.scheme == "content" and allowed_authority and parsed.netloc != allowed_authority:
        fail("content URI authority does not match the reviewed authority")
    return value


def resolve_serial(requested: str | None, dry_run: bool) -> str:
    if requested:
        serial = requested
    elif dry_run:
        serial = "emulator-5554"
    else:
        result = subprocess.run(["adb", "devices"], text=True, capture_output=True, check=True)
        serials = [
            line.split()[0] for line in result.stdout.splitlines()[1:]
            if line.strip().endswith("\tdevice") and line.split()[0].startswith("emulator-")
        ]
        if len(serials) != 1:
            fail("specify --serial; exactly one online emulator was not found")
        serial = serials[0]
    if not re.fullmatch(r"emulator-\d+", serial):
        fail("hardware devices are forbidden; serial must be emulator-<port>")
    if not dry_run:
        result = subprocess.run(
            ["adb", "-s", serial, "shell", "getprop", "ro.kernel.qemu"],
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )
        if result.returncode != 0 or result.stdout.strip() != "1":
            fail("selected serial did not attest as an Android emulator")
    return serial


def validate_apk(apk: str) -> str:
    repo = Path(__file__).resolve().parents[4]
    target_root = (repo / "targets").resolve()
    path = Path(apk).resolve()
    if path.suffix.lower() != ".apk" or not path.is_file():
        fail("install target must be an existing .apk")
    try:
        path.relative_to(target_root)
    except ValueError:
        fail("install target must reside under targets/")
    return str(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--confirm-state-change", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    install = sub.add_parser("install")
    install.add_argument("--apk", required=True)

    activity = sub.add_parser("activity")
    activity.add_argument("--package", required=True)
    activity.add_argument("--component", required=True)

    uri = sub.add_parser("uri")
    uri.add_argument("--package", required=True)
    uri.add_argument("--uri", required=True)

    broadcast = sub.add_parser("broadcast")
    broadcast.add_argument("--package", required=True)
    broadcast.add_argument("--action", required=True)
    broadcast.add_argument("--component")

    service = sub.add_parser("service")
    service.add_argument("--package", required=True)
    service.add_argument("--component", required=True)

    query = sub.add_parser("provider-query")
    query.add_argument("--authority", required=True)
    query.add_argument("--uri", required=True)

    logcat = sub.add_parser("logcat")
    logcat.add_argument("--package", required=True)
    logcat.add_argument("--lines", type=int, default=250)

    args = parser.parse_args()
    serial = resolve_serial(args.serial, args.dry_run)
    prefix = ["adb", "-s", serial]

    if args.command == "install":
        command = prefix + ["install", "-r", validate_apk(args.apk)]
    elif args.command == "activity":
        package = validate_package(args.package)
        component = normalize_component(package, args.component)
        command = prefix + [
            "shell", "am", "start", "-W", "-n", f"{package}/{component}",
            "--es", "tf_probe", "component-marker",
        ]
    elif args.command == "uri":
        package = validate_package(args.package)
        value = validate_uri(args.uri)
        command = prefix + [
            "shell", "am", "start", "-W", "-a", "android.intent.action.VIEW",
            "-c", "android.intent.category.BROWSABLE", "-d", value, package,
        ]
    elif args.command == "broadcast":
        package = validate_package(args.package)
        if not ACTION.fullmatch(args.action):
            fail(f"invalid action: {args.action!r}")
        command = prefix + ["shell", "am", "broadcast", "-a", args.action, "-p", package]
        if args.component:
            component = normalize_component(package, args.component)
            command += ["-n", f"{package}/{component}"]
        command += ["--es", "tf_probe", "broadcast-marker"]
    elif args.command == "service":
        if not args.confirm_state_change:
            fail("service probes require --confirm-state-change")
        package = validate_package(args.package)
        component = normalize_component(package, args.component)
        command = prefix + [
            "shell", "am", "startservice", "-n", f"{package}/{component}",
            "--es", "tf_probe", "service-marker",
        ]
    elif args.command == "provider-query":
        if not args.confirm_state_change:
            fail("provider probes require --confirm-state-change after path review")
        if not TOKEN.fullmatch(args.authority):
            fail(f"invalid authority: {args.authority!r}")
        value = validate_uri(args.uri, args.authority)
        command = prefix + ["shell", "content", "query", "--uri", value]
    else:
        package = validate_package(args.package)
        if not 1 <= args.lines <= 5000:
            fail("--lines must be between 1 and 5000")
        command = prefix + [
            "shell", "logcat", "-d", "-t", str(args.lines),
            f"--pid=$(pidof {package})",
        ]
        # logcat is the sole command that would require shell substitution. Keep it
        # in adb shell as separate words and reject it in dry-run execution.
        if not args.dry_run:
            pid = subprocess.run(
                prefix + ["shell", "pidof", package],
                text=True, capture_output=True, check=False, timeout=10,
            ).stdout.strip().split()
            command = prefix + ["shell", "logcat", "-d", "-t", str(args.lines)]
            if pid:
                command += [f"--pid={pid[0]}"]

    record = {"serial": serial, "command": command, "dry_run": args.dry_run}
    print(json.dumps(record, ensure_ascii=False))
    if args.dry_run:
        return
    result = subprocess.run(command, text=True, capture_output=True, timeout=60, check=False)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
