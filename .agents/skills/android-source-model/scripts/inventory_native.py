#!/usr/bin/env python3
"""Inventory native executables embedded in an APK without executing them."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

MAX_MEMBER = 256 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_TOOL_OUTPUT = 4 * 1024 * 1024
MAX_ENTRIES = 200_000
CODE_SUFFIXES = {".dex", ".jar", ".apk", ".wasm", ".odex", ".oat", ".vdex", ".art", ".bc"}
PARSER_MARKERS = {
    "image": re.compile(r"(?i)\b(jpe?g|png|webp|heif|heic|qmage|dng|gif|bmp|tiff)\b"),
    "media": re.compile(r"(?i)\b(mp4|mkv|avi|mpeg|aac|flac|opus|vorbis|codec|extractor)\b"),
    "document": re.compile(r"(?i)\b(pdf|office|docx|xlsx|pptx|rtf)\b"),
    "archive": re.compile(r"(?i)\b(zip|gzip|tar|7z|rar|archive)\b"),
    "structured-data": re.compile(r"(?i)\b(json|xml|protobuf|flatbuffer|msgpack|cbor)\b"),
    "network-message": re.compile(r"(?i)\b(mms|sms|wap|push|notification|websocket)\b"),
}
RISKY_SYMBOLS = re.compile(
    r"(?i)\b(strcpy|strcat|sprintf|vsprintf|gets|scanf|sscanf|memcpy|dlopen|system|execve|popen)\b"
)


def run_text(argv: list[str]) -> str:
    with tempfile.TemporaryFile() as output:
        try:
            process = subprocess.Popen(argv, stdout=output, stderr=subprocess.STDOUT)
            process.wait(timeout=30)
        except OSError:
            return ""
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        output.seek(0)
        return output.read(MAX_TOOL_OUTPUT).decode("utf-8", errors="replace")


def safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts and "\x00" not in name


def hash_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> tuple[str, bytes]:
    hasher = hashlib.sha256()
    prefix = b""
    with archive.open(info) as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            if not prefix:
                prefix = chunk[:16]
            hasher.update(chunk)
    return hasher.hexdigest(), prefix


def magic_type(prefix: bytes) -> str:
    if prefix.startswith(b"dex\n"):
        return "dex"
    if prefix.startswith(b"\x7fELF"):
        return "elf"
    if prefix.startswith(b"\x00asm"):
        return "wasm"
    if prefix.startswith(b"PK\x03\x04"):
        return "zip-container"
    return "unknown"


def extract_and_analyze(apk: Path, extract_dir: Path) -> dict:
    extract_dir.mkdir(parents=True, exist_ok=True)
    libraries = []
    total = 0
    embedded_code = []
    with zipfile.ZipFile(apk) as archive:
        all_infos = archive.infolist()
        if len(all_infos) > MAX_ENTRIES:
            raise SystemExit("APK entry count exceeds safety limit")
        for item in all_infos:
            if not safe_member(item.filename):
                raise SystemExit(f"unsafe APK member: {item.filename}")
        infos = [
            item for item in all_infos
            if item.filename.startswith("lib/") and item.filename.endswith(".so")
        ]
        for info in infos:
            if not safe_member(info.filename):
                raise SystemExit(f"unsafe APK member: {info.filename}")
            if info.file_size > MAX_MEMBER:
                raise SystemExit(f"native member exceeds limit: {info.filename}")
            total += info.file_size
            if total > MAX_TOTAL:
                raise SystemExit("native library total exceeds 1 GiB safety limit")
            raw = archive.read(info)
            destination = extract_dir.joinpath(*PurePosixPath(info.filename).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)

            strings = run_text(["strings", "-a", "-n", "4", str(destination)]) if shutil.which("strings") else ""
            readelf = run_text(["readelf", "-h", "-d", "-sW", str(destination)]) if shutil.which("readelf") else ""
            markers = {
                category: sorted({match.group(0).lower() for match in pattern.finditer(strings)})[:30]
                for category, pattern in PARSER_MARKERS.items()
            }
            markers = {k: v for k, v in markers.items() if v}
            risky = sorted({match.group(0) for match in RISKY_SYMBOLS.finditer(readelf + "\n" + strings)})
            jni_exports = sorted(
                set(re.findall(r"\b(?:JNI_OnLoad|Java_[A-Za-z0-9_]+)\b", readelf))
            )[:200]
            dependencies = sorted(
                set(re.findall(r"\(NEEDED\).*Shared library: \[([^\]]+)\]", readelf))
            )
            soname = re.search(r"\(SONAME\).*Library soname: \[([^\]]+)\]", readelf)
            machine = re.search(r"Machine:\s*(.+)", readelf)
            elf_class = re.search(r"Class:\s*(\S+)", readelf)
            libraries.append(
                {
                    "archive_path": info.filename,
                    "extracted_path": str(destination),
                    "abi": PurePosixPath(info.filename).parts[1] if len(PurePosixPath(info.filename).parts) > 2 else "",
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "elf_class": elf_class.group(1) if elf_class else None,
                    "machine": machine.group(1).strip() if machine else None,
                    "soname": soname.group(1) if soname else None,
                    "dependencies": dependencies,
                    "jni_exports": jni_exports,
                    "risky_native_symbols": risky,
                    "parser_markers": markers,
                    "zero_click_candidate": bool(markers),
                    "candidate_basis": (
                        "parser/input-format strings only; prove an automatic delivery path and "
                        "memory-unsafe operation before calling this zero-click"
                    ),
                }
            )
        for info in all_infos:
            suffix = PurePosixPath(info.filename).suffix.lower()
            if suffix not in CODE_SUFFIXES or info.filename.endswith(".so"):
                continue
            if info.file_size > MAX_MEMBER:
                embedded_code.append(
                    {
                        "archive_path": info.filename,
                        "size": info.file_size,
                        "skipped": "member exceeds 256 MiB analysis limit",
                    }
                )
                continue
            digest, prefix = hash_member(archive, info)
            embedded_code.append(
                {
                    "archive_path": info.filename,
                    "size": info.file_size,
                    "sha256": digest,
                    "magic": magic_type(prefix),
                }
            )
    return {
        "apk": str(apk),
        "extraction_dir": str(extract_dir),
        "tools": {
            "readelf": shutil.which("readelf"),
            "strings": shutil.which("strings"),
        },
        "libraries": libraries,
        "embedded_code": embedded_code,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--extract-dir", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    if not args.apk.is_file():
        parser.error(f"APK not found: {args.apk}")
    try:
        result = extract_and_analyze(args.apk, args.extract_dir)
    except zipfile.BadZipFile:
        parser.error("input is not a valid APK/ZIP")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    candidates = sum(1 for item in result["libraries"] if item["zero_click_candidate"])
    print(
        f"[native-inventory] libraries={len(result['libraries'])} "
        f"embedded-code={len(result['embedded_code'])} "
        f"parser-string-candidates={candidates} -> {args.out}"
    )


if __name__ == "__main__":
    main()
