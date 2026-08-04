#!/usr/bin/env python3
"""Build a deterministic Android APK attack-surface model.

The input manifest must be decoded text XML. APK metadata and decompiled source
roots are optional so the model remains useful when only part of the toolchain is
installed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import zipfile
from pathlib import Path
import xml.etree.ElementTree as ET

ANDROID_NS = "http://schemas.android.com/apk/res/android"
A = f"{{{ANDROID_NS}}}"

SOURCE_PATTERNS = {
    "intent-object": re.compile(r"\b(getIntent|getParcelableExtra|getSerializableExtra)\s*\("),
    "intent-extra": re.compile(r"\bget(?:String|Boolean|Byte|Char|Double|Float|Int|Long|Short|Bundle|CharSequence)Extra\s*\("),
    "uri-data": re.compile(r"\b(getData|getDataString|getQueryParameter|getPathSegments)\s*\("),
    "ipc-input": re.compile(r"\bon(?:Receive|StartCommand|Bind|Transact|ActivityResult|NewIntent)\s*\("),
    "provider-input": re.compile(r"\b(query|insert|update|delete|openFile|call)\s*\([^)]*(?:Uri|uri)"),
    "webview-navigation": re.compile(r"\bshouldOverrideUrlLoading\s*\("),
}

SINK_PATTERNS = {
    "component-launch": re.compile(r"\b(startActivity|startActivities|startService|startForegroundService|bindService)\s*\("),
    "broadcast-send": re.compile(r"\b(sendBroadcast|sendOrderedBroadcast)\s*\("),
    "intent-parse": re.compile(r"\bIntent\.parseUri\s*\("),
    "webview-load": re.compile(r"\b(loadUrl|loadData|loadDataWithBaseURL|evaluateJavascript)\s*\("),
    "webview-bridge": re.compile(r"\baddJavascriptInterface\s*\("),
    "webview-dangerous-setting": re.compile(r"\b(setJavaScriptEnabled|setAllowFileAccess|setAllowUniversalAccessFromFileURLs)\s*\(\s*true"),
    "content-access": re.compile(r"\b(openInputStream|openOutputStream|openFileDescriptor|acquireContentProviderClient)\s*\("),
    "native-load": re.compile(r"\bSystem\.(?:load|loadLibrary)\s*\("),
    "dex-load": re.compile(r"\b(?:DexClassLoader|PathClassLoader|InMemoryDexClassLoader)\s*\("),
    "command-exec": re.compile(r"\b(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\("),
    "java-deserialization": re.compile(r"\bObjectInputStream\s*\("),
    "parcelable-deserialization": re.compile(r"\b(?:readParcelable|getParcelableExtra|getSerializableExtra)\s*\("),
    "archive-extract": re.compile(r"\b(?:ZipInputStream|ZipFile|TarArchiveInputStream)\s*\("),
}

TEXT_SUFFIXES = {".java", ".kt", ".kts", ".smali", ".xml"}
MAX_SCAN_BYTES = 2 * 1024 * 1024


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def attr(node: ET.Element, name: str, default: str | None = None) -> str | None:
    return node.get(A + name, default)


def bool_attr(node: ET.Element, name: str) -> bool | None:
    value = attr(node, name)
    if value is None:
        return None
    return value.lower() == "true"


def qualify(package: str, name: str | None) -> str:
    if not name:
        return ""
    if name.startswith("."):
        return package + name
    if "." not in name:
        return package + "." + name
    return name


def parse_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def parse_manifest(path: Path) -> dict:
    root = ET.parse(path).getroot()
    package = root.get("package", "")
    uses_sdk = root.find("uses-sdk")
    target_sdk = parse_int(attr(uses_sdk, "targetSdkVersion")) if uses_sdk is not None else None
    app = root.find("application")

    permission_nodes = [
        (node, False) for node in root.findall("uses-permission")
    ] + [
        (node, True) for node in root.findall("uses-permission-sdk-23")
    ]
    model = {
        "path": str(path),
        "package": package,
        "version_name": attr(root, "versionName"),
        "version_code": attr(root, "versionCode"),
        "min_sdk": parse_int(attr(uses_sdk, "minSdkVersion")) if uses_sdk is not None else None,
        "target_sdk": target_sdk,
        "uses_permissions": sorted({attr(n, "name", "") for n, _ in permission_nodes if attr(n, "name")}),
        "uses_permission_details": [
            {
                "name": attr(node, "name"),
                "max_sdk": parse_int(attr(node, "maxSdkVersion")),
                "sdk23_only": sdk23_only,
            }
            for node, sdk23_only in permission_nodes
        ],
        "declared_permissions": [
            {
                "name": attr(n, "name"),
                "protection_level": attr(n, "protectionLevel"),
                "permission_group": attr(n, "permissionGroup"),
            }
            for n in root.findall("permission")
        ],
        "uses_features": [
            {
                "name": attr(n, "name"),
                "required": bool_attr(n, "required"),
                "gl_es_version": attr(n, "glEsVersion"),
            }
            for n in root.findall("uses-feature")
        ],
        "application": {},
        "components": [],
        "deep_links": [],
    }
    if app is None:
        return model

    model["application"] = {
        "name": qualify(package, attr(app, "name")),
        "debuggable": bool_attr(app, "debuggable"),
        "allow_backup": bool_attr(app, "allowBackup"),
        "uses_cleartext_traffic": bool_attr(app, "usesCleartextTraffic"),
        "network_security_config": attr(app, "networkSecurityConfig"),
        "permission": attr(app, "permission"),
        "shared_user_id": attr(root, "sharedUserId"),
        "shared_user_max_sdk": parse_int(attr(root, "sharedUserMaxSdkVersion")),
    }

    tags = ("activity", "activity-alias", "service", "receiver", "provider")
    for tag in tags:
        for node in app.findall(tag):
            filters = []
            for idx, intent_filter in enumerate(node.findall("intent-filter")):
                actions = [attr(x, "name") for x in intent_filter.findall("action") if attr(x, "name")]
                categories = [attr(x, "name") for x in intent_filter.findall("category") if attr(x, "name")]
                data = []
                for item in intent_filter.findall("data"):
                    datum = {
                        key: attr(item, key)
                        for key in (
                            "scheme", "host", "port", "path", "pathPrefix",
                            "pathPattern", "pathAdvancedPattern", "mimeType"
                        )
                        if attr(item, key) is not None
                    }
                    if datum:
                        data.append(datum)
                filters.append(
                    {
                        "index": idx,
                        "priority": parse_int(attr(intent_filter, "priority")) or 0,
                        "auto_verify": bool_attr(intent_filter, "autoVerify"),
                        "actions": actions,
                        "categories": categories,
                        "data": data,
                    }
                )

            explicit_exported = bool_attr(node, "exported")
            legacy_implicit = explicit_exported is None and bool(filters)
            effective_exported = explicit_exported is True or legacy_implicit
            component = {
                "type": tag,
                "name": qualify(package, attr(node, "name")),
                "target_activity": qualify(package, attr(node, "targetActivity")),
                "declared_exported": explicit_exported,
                "effective_exported": effective_exported,
                "legacy_implicit_export": legacy_implicit,
                "exported_declaration_required": bool(
                    target_sdk is not None and target_sdk >= 31 and filters and explicit_exported is None
                ),
                "enabled": bool_attr(node, "enabled"),
                "process": attr(node, "process"),
                "direct_boot_aware": bool_attr(node, "directBootAware"),
                "isolated_process": bool_attr(node, "isolatedProcess"),
                "foreground_service_type": attr(node, "foregroundServiceType"),
                "permission": attr(node, "permission") or attr(app, "permission"),
                "read_permission": attr(node, "readPermission"),
                "write_permission": attr(node, "writePermission"),
                "grant_uri_permissions": bool_attr(node, "grantUriPermissions"),
                "authorities": (attr(node, "authorities") or "").split(";") if tag == "provider" else [],
                "intent_filters": filters,
            }
            model["components"].append(component)

            for intent_filter in filters:
                browsable = "android.intent.category.BROWSABLE" in intent_filter["categories"]
                for datum in intent_filter["data"]:
                    if datum.get("scheme") or datum.get("host"):
                        link = {
                            "component": component["name"],
                            "browsable": browsable,
                            "auto_verify": intent_filter["auto_verify"],
                            **datum,
                        }
                        model["deep_links"].append(link)

    model["components"].sort(key=lambda c: (c["type"], c["name"]))
    model["deep_links"].sort(
        key=lambda x: (x.get("component", ""), x.get("scheme", ""), x.get("host", ""), x.get("path", ""))
    )
    return model


def scan_sources(roots: list[Path]) -> dict:
    hits: list[dict] = []
    files_scanned = 0
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            try:
                if path.stat().st_size > MAX_SCAN_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            files_scanned += 1
            for lineno, line in enumerate(text.splitlines(), 1):
                for category, pattern in SOURCE_PATTERNS.items():
                    if pattern.search(line):
                        hits.append(
                            {
                                "kind": "source",
                                "category": category,
                                "file": str(path),
                                "line": lineno,
                                "snippet": line.strip()[:300],
                            }
                        )
                for category, pattern in SINK_PATTERNS.items():
                    if pattern.search(line):
                        hits.append(
                            {
                                "kind": "sink",
                                "category": category,
                                "file": str(path),
                                "line": lineno,
                                "snippet": line.strip()[:300],
                            }
                        )
    return {"files_scanned": files_scanned, "hits": hits}


def apk_inventory(path: Path | None) -> dict:
    if path is None:
        return {}
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    digest = hasher.hexdigest()
    result = {
        "path": str(path),
        "sha256": digest,
        "size": path.stat().st_size,
        "zip_valid": False,
        "dex_files": [],
        "native_libraries": [],
        "embedded_archives": [],
    }
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            # Reading the central directory is sufficient here. Do not decompress the
            # whole APK with testzip(); hostile inputs may have extreme expansion ratios.
            result["zip_valid"] = True
            result["dex_files"] = sorted(x for x in names if re.fullmatch(r"classes\d*\.dex", Path(x).name))
            result["native_libraries"] = sorted(
                x for x in names if x.startswith("lib/") and x.endswith(".so")
            )
            result["embedded_archives"] = sorted(
                x for x in names if Path(x).suffix.lower() in {".apk", ".dex", ".jar", ".zip"}
            )
    except zipfile.BadZipFile:
        pass
    return result


def derive_surfaces(manifest: dict, scan: dict) -> dict:
    exported = [c for c in manifest.get("components", []) if c.get("effective_exported")]
    passive_actions = {
        "android.intent.action.BOOT_COMPLETED",
        "android.intent.action.LOCKED_BOOT_COMPLETED",
        "android.provider.Telephony.SMS_RECEIVED",
        "android.provider.Telephony.WAP_PUSH_RECEIVED",
        "android.intent.action.PACKAGE_ADDED",
        "com.google.android.c2dm.intent.RECEIVE",
    }
    passive = []
    for component in manifest.get("components", []):
        actions = {
            action
            for item in component.get("intent_filters", [])
            for action in item.get("actions", [])
        }
        matched = sorted(actions & passive_actions)
        if component.get("type") in {"receiver", "service", "provider"} and (
            component.get("effective_exported") or matched
        ):
            passive.append({"component": component["name"], "type": component["type"], "actions": matched})

    categories: dict[str, int] = {}
    for hit in scan.get("hits", []):
        categories[hit["category"]] = categories.get(hit["category"], 0) + 1
    return {
        "exported_components": len(exported),
        "exported_without_permission": [
            {"type": c["type"], "name": c["name"]}
            for c in exported
            if not c.get("permission") and not c.get("read_permission") and not c.get("write_permission")
        ],
        "deep_link_count": len(manifest.get("deep_links", [])),
        "passive_entry_candidates": passive,
        "source_sink_hit_counts": categories,
    }


def component_code_index(manifest: dict, scan: dict) -> list[dict]:
    index = []
    hits = scan.get("hits", [])
    for component in manifest.get("components", []):
        class_name = (component.get("name") or "").rsplit(".", 1)[-1]
        if not class_name:
            continue
        related = []
        for hit in hits:
            stem = Path(hit.get("file", "")).stem
            if stem == class_name or stem.startswith(class_name + "$"):
                related.append(hit)
        index.append(
            {
                "component": component.get("name"),
                "type": component.get("type"),
                "files": sorted({hit["file"] for hit in related}),
                "sources": [hit for hit in related if hit.get("kind") == "source"],
                "sinks": [hit for hit in related if hit.get("kind") == "sink"],
                "status": "indexed" if related else "implementation-not-located",
            }
        )
    return index


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--apk", type=Path)
    parser.add_argument("--source-root", type=Path, action="append", default=[])
    parser.add_argument("--native-inventory", type=Path)
    parser.add_argument("--out", type=Path, default=Path("workspace/android/ANDROID_MODEL.json"))
    args = parser.parse_args()

    if not args.manifest and not args.apk and not args.source_root:
        parser.error("provide at least one of --manifest, --apk, or --source-root")
    if args.manifest and not args.manifest.is_file():
        parser.error(f"manifest not found: {args.manifest}")
    if args.apk and not args.apk.is_file():
        parser.error(f"APK not found: {args.apk}")

    manifest = parse_manifest(args.manifest) if args.manifest else {
        "path": None,
        "package": "",
        "components": [],
        "deep_links": [],
        "warning": "decoded manifest unavailable",
    }
    scan = scan_sources(args.source_root)
    model = {
        "schema_version": 1,
        "generated_at": now(),
        "apk": apk_inventory(args.apk),
        "manifest": manifest,
        "source_roots": [str(p) for p in args.source_root],
        "code_scan": scan,
        "native": (
            json.loads(args.native_inventory.read_text(encoding="utf-8"))
            if args.native_inventory and args.native_inventory.is_file()
            else {"libraries": [], "warning": "native inventory unavailable"}
        ),
    }
    model["attack_surface"] = derive_surfaces(manifest, scan)
    model["component_code_index"] = component_code_index(manifest, scan)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(model, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(
        f"[android-model] package={manifest.get('package') or '?'} "
        f"components={len(manifest.get('components', []))} "
        f"deep_links={len(manifest.get('deep_links', []))} "
        f"code_hits={len(scan.get('hits', []))} -> {args.out}"
    )


if __name__ == "__main__":
    main()
