#!/usr/bin/env python3
import argparse
import json
import os
import plistlib
import shutil
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath

MAX_ENTRIES = 150_000
MAX_UNCOMPRESSED = 3 * 1024 * 1024 * 1024
MAX_SINGLE_FILE = 1024 * 1024 * 1024


def fail(message):
    print(json.dumps({"error": message}), file=sys.stderr)
    raise SystemExit(2)


def safe_extract(ipa_path: Path, destination: Path):
    if not zipfile.is_zipfile(ipa_path):
        fail("The uploaded IPA is not a valid ZIP archive.")
    destination.mkdir(parents=True, exist_ok=False)
    total_size = 0
    count = 0
    seen = set()
    try:
        with zipfile.ZipFile(ipa_path, "r") as archive:
            members = archive.infolist()
            if len(members) > MAX_ENTRIES:
                fail("The IPA contains too many archive entries.")
            for info in members:
                count += 1
                name = info.filename
                if not name or "\\" in name:
                    fail("The IPA contains an invalid archive path.")
                relative = PurePosixPath(name)
                if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
                    fail("The IPA contains an unsafe archive path.")
                if relative.parts[0] not in ("Payload", "SwiftSupport", "Symbols", "iTunesMetadata.plist", "iTunesArtwork"):
                    fail("The IPA contains files outside expected iOS archive folders.")
                normalized = str(relative)
                if normalized in seen:
                    fail("The IPA contains duplicate archive paths.")
                seen.add(normalized)
                if info.flag_bits & 0x1:
                    fail("Encrypted ZIP entries are not supported.")
                if info.file_size > MAX_SINGLE_FILE:
                    fail("An IPA archive entry exceeds the allowed size.")
                total_size += info.file_size
                if total_size > MAX_UNCOMPRESSED:
                    fail("The extracted IPA exceeds the allowed uncompressed size.")
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(unix_mode):
                    fail("Symbolic links are not allowed inside IPA archives.")
                output = destination.joinpath(*relative.parts)
                resolved = output.resolve()
                if destination.resolve() not in resolved.parents and resolved != destination.resolve():
                    fail("The IPA contains an unsafe archive path.")
                if info.is_dir():
                    output.mkdir(parents=True, exist_ok=True)
                    continue
                output.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info, "r") as source, output.open("xb") as target:
                    shutil.copyfileobj(source, target, length=1024 * 1024)
                mode = unix_mode & 0o777
                if mode:
                    output.chmod(mode & 0o755)
                else:
                    output.chmod(0o644)
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        fail("The IPA archive could not be safely extracted: " + str(exc)[:160])


def find_main_app(root: Path) -> Path:
    payload = root / "Payload"
    if not payload.is_dir():
        fail("The IPA does not contain a Payload folder.")
    candidates = []
    for app in payload.glob("*.app"):
        info = app / "Info.plist"
        if info.is_file() and app.is_dir():
            candidates.append(app)
    if len(candidates) != 1:
        fail("The IPA must contain exactly one main application bundle in Payload.")
    return candidates[0]


def read_info(app: Path):
    info_path = app / "Info.plist"
    try:
        with info_path.open("rb") as handle:
            value = plistlib.load(handle)
    except Exception:
        fail("The application's Info.plist could not be read.")
    if not isinstance(value, dict):
        fail("The application's Info.plist is invalid.")
    return info_path, value


def metadata(info):
    return {
        "appName": str(info.get("CFBundleDisplayName") or info.get("CFBundleName") or ""),
        "bundleId": str(info.get("CFBundleIdentifier") or ""),
        "appVersion": str(info.get("CFBundleShortVersionString") or ""),
        "buildNumber": str(info.get("CFBundleVersion") or ""),
        "minimumIOS": str(info.get("MinimumOSVersion") or ""),
    }


def patch_app(app: Path, options: dict):
    info_path, info = read_info(app)
    if options.get("appName"):
        info["CFBundleDisplayName"] = options["appName"]
        info["CFBundleName"] = options["appName"]
    if options.get("bundleId"):
        info["CFBundleIdentifier"] = options["bundleId"]
    if options.get("appVersion"):
        info["CFBundleShortVersionString"] = options["appVersion"]
    if options.get("buildNumber"):
        info["CFBundleVersion"] = options["buildNumber"]
    if options.get("proMotion"):
        info["CADisableMinimumFrameDurationOnPhone"] = True
    if options.get("gameMode"):
        info["LSSupportsGameMode"] = True
    if options.get("minimumIOS"):
        info["MinimumOSVersion"] = options["minimumIOS"]
    try:
        with info_path.open("wb") as handle:
            plistlib.dump(info, handle, fmt=plistlib.FMT_BINARY, sort_keys=False)
    except Exception:
        fail("The application's Info.plist could not be updated.")
    return metadata(info)


def validate_output(ipa_path: Path):
    if not ipa_path.is_file() or ipa_path.stat().st_size == 0:
        fail("The signing tool did not produce an output IPA.")
    try:
        with zipfile.ZipFile(ipa_path, "r") as archive:
            bad = archive.testzip()
            if bad:
                fail("The signed IPA failed ZIP integrity verification.")
            app_infos = [
                item for item in archive.namelist()
                if item.startswith("Payload/") and item.endswith(".app/Info.plist")
                and ".appex/" not in item and ".app/Watch/" not in item
            ]
            if not app_infos:
                fail("The signed IPA does not contain a valid application bundle.")
            embedded = [item for item in archive.namelist() if item.startswith("Payload/") and item.endswith(".app/embedded.mobileprovision")]
            if not embedded:
                fail("The signed IPA is missing its embedded provisioning profile.")
    except (zipfile.BadZipFile, OSError) as exc:
        fail("The signed IPA could not be verified: " + str(exc)[:160])
    return {"valid": True, "size": ipa_path.stat().st_size}


def main():
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers(dest="command", required=True)

    extract_parser = subs.add_parser("extract")
    extract_parser.add_argument("--ipa", required=True)
    extract_parser.add_argument("--dest", required=True)

    inspect_parser = subs.add_parser("inspect")
    inspect_parser.add_argument("--app", required=True)

    patch_parser = subs.add_parser("patch")
    patch_parser.add_argument("--app", required=True)
    patch_parser.add_argument("--options", required=True)

    validate_parser = subs.add_parser("validate")
    validate_parser.add_argument("--ipa", required=True)

    args = parser.parse_args()
    if args.command == "extract":
        destination = Path(args.dest)
        safe_extract(Path(args.ipa), destination)
        app = find_main_app(destination)
        _, info = read_info(app)
        print(json.dumps({"appPath": str(app), "metadata": metadata(info)}))
    elif args.command == "inspect":
        _, info = read_info(Path(args.app))
        print(json.dumps(metadata(info)))
    elif args.command == "patch":
        try:
            options = json.loads(args.options)
        except json.JSONDecodeError:
            fail("Invalid app signing options.")
        result = patch_app(Path(args.app), options)
        print(json.dumps(result))
    elif args.command == "validate":
        print(json.dumps(validate_output(Path(args.ipa))))


if __name__ == "__main__":
    main()
