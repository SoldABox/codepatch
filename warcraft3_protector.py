#!/usr/bin/env python3
"""Conservative Warcraft III source protection and verification tool.

The Warcraft III client must read distributed scripts and assets, so this tool
raises reverse-engineering cost and detects tampering without claiming perfect
client-side encryption.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCRIPT_NAMES = {"war3map.lua", "war3map.j"}
ASSET_SUFFIXES = {".mdx", ".mdl", ".blp", ".tga", ".dds", ".wav", ".mp3"}
MANIFEST_NAME = "protection-manifest.json"
PRIVATE_REPORT_NAME = "protection-private-report.json"


@dataclass(frozen=True)
class ProtectionOptions:
    randomize_assets: bool = True
    strip_comments: bool = True
    reduce_whitespace: bool = True
    include_private_report: bool = False


@dataclass(frozen=True)
class BuildResult:
    output_dir: Path
    manifest_path: Path
    private_report_path: Path | None
    renamed_assets: int
    protected_scripts: int


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    missing: tuple[str, ...]
    changed: tuple[str, ...]
    unexpected: tuple[str, ...]
    signature_valid: bool | None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _manifest_signature(manifest_without_signature: dict[str, Any], key: str) -> str:
    return hmac.new(key.encode("utf-8"), _canonical_json(manifest_without_signature), hashlib.sha256).hexdigest()


def _strip_lua_comments(text: str) -> str:
    out: list[str] = []
    i = 0
    quote: str | None = None
    while i < len(text):
        char = text[i]
        if quote:
            out.append(char)
            if char == "\\" and i + 1 < len(text):
                i += 1
                out.append(text[i])
            elif char == quote:
                quote = None
            i += 1
            continue
        if char in {"'", '"'}:
            quote = char
            out.append(char)
            i += 1
            continue
        if text.startswith("--[[", i):
            end = text.find("]]", i + 4)
            i = len(text) if end == -1 else end + 2
            continue
        if text.startswith("--", i):
            end = text.find("\n", i + 2)
            i = len(text) if end == -1 else end
            continue
        out.append(char)
        i += 1
    return "".join(out)


def protect_lua(text: str, *, strip_comments: bool = True, reduce_whitespace: bool = True) -> str:
    if strip_comments:
        text = _strip_lua_comments(text)
    if reduce_whitespace:
        text = "\n".join(line.strip() for line in text.splitlines() if line.strip())
    return text.rstrip() + "\n"


def protect_jass(text: str, *, strip_comments: bool = True, reduce_whitespace: bool = True) -> str:
    lines: list[str] = []
    for line in text.splitlines():
        current = line.strip() if reduce_whitespace else line.rstrip()
        if strip_comments:
            if not current or current.lstrip().startswith("//"):
                continue
            current = re.sub(r"\s+//.*$", "", current).rstrip()
        if current:
            lines.append(current)
    return "\n".join(lines).rstrip() + "\n"


def _asset_token(path: Path, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{path.as_posix()}".encode("utf-8")).hexdigest()[:24]


def _replace_asset_references(text: str, mappings: dict[str, str]) -> str:
    updated = text
    for old, new in sorted(mappings.items(), key=lambda item: len(item[0]), reverse=True):
        old_backslash = old.replace("/", "\\")
        new_backslash = new.replace("/", "\\")
        variants = (
            (old, new),
            (old_backslash, new_backslash),
            (old_backslash.replace("\\", "\\\\"), new_backslash.replace("\\", "\\\\")),
        )
        for candidate, replacement in variants:
            updated = updated.replace(candidate, replacement)
    return updated


def _inventory(root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.name not in {MANIFEST_NAME, PRIVATE_REPORT_NAME}):
        entries.append({
            "path": path.relative_to(root).as_posix(),
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
        })
    return entries


def protect_project(
    source_dir: Path,
    output_dir: Path,
    build_id: str | None = None,
    *,
    options: ProtectionOptions | None = None,
    signing_key: str | None = None,
) -> BuildResult:
    options = options or ProtectionOptions()
    source_dir = source_dir.resolve()
    output_dir = output_dir.resolve()
    if not source_dir.is_dir():
        raise ValueError(f"Source directory does not exist: {source_dir}")
    if source_dir == output_dir or source_dir in output_dir.parents:
        raise ValueError("Output directory must be outside the source directory")

    if output_dir.exists():
        shutil.rmtree(output_dir)
    shutil.copytree(source_dir, output_dir)

    build_id = build_id or secrets.token_hex(12)
    mappings: dict[str, str] = {}
    if options.randomize_assets:
        assets = [p for p in output_dir.rglob("*") if p.is_file() and p.suffix.lower() in ASSET_SUFFIXES]
        for asset in assets:
            rel = asset.relative_to(output_dir)
            token = _asset_token(rel, build_id)
            mappings[rel.as_posix()] = (Path("war3mapImported") / token[:2] / (token + asset.suffix.lower())).as_posix()

    protected_scripts = 0
    for script in [p for p in output_dir.rglob("*") if p.is_file() and p.name.lower() in SCRIPT_NAMES]:
        text = _replace_asset_references(script.read_text(encoding="utf-8"), mappings)
        if script.name.lower().endswith(".lua"):
            text = protect_lua(text, strip_comments=options.strip_comments, reduce_whitespace=options.reduce_whitespace)
        else:
            text = protect_jass(text, strip_comments=options.strip_comments, reduce_whitespace=options.reduce_whitespace)
        script.write_text(text, encoding="utf-8", newline="\n")
        protected_scripts += 1

    for old, new in mappings.items():
        old_path = output_dir / Path(old)
        new_path = output_dir / Path(new)
        new_path.parent.mkdir(parents=True, exist_ok=True)
        old_path.replace(new_path)

    manifest: dict[str, Any] = {
        "schema": 2,
        "build_id": build_id,
        "protection": {
            "script_comment_removal": options.strip_comments,
            "script_whitespace_reduction": options.reduce_whitespace,
            "asset_path_randomization": options.randomize_assets,
            "cryptographic_secrecy": False,
        },
        "summary": {
            "renamed_assets": len(mappings),
            "protected_scripts": protected_scripts,
        },
        "files": _inventory(output_dir),
    }
    if signing_key:
        manifest["hmac_sha256"] = _manifest_signature(manifest, signing_key)

    manifest_path = output_dir / MANIFEST_NAME
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    private_report_path: Path | None = None
    if options.include_private_report:
        private_report_path = output_dir.parent / f"{output_dir.name}-{PRIVATE_REPORT_NAME}"
        private_report_path.write_text(json.dumps({
            "build_id": build_id,
            "source": str(source_dir),
            "output": str(output_dir),
            "asset_mappings": mappings,
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return BuildResult(output_dir, manifest_path, private_report_path, len(mappings), protected_scripts)


def verify_project(output_dir: Path, *, signing_key: str | None = None) -> VerificationResult:
    output_dir = output_dir.resolve()
    manifest_path = output_dir / MANIFEST_NAME
    if not manifest_path.is_file():
        raise ValueError(f"Manifest not found: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = {entry["path"]: entry for entry in manifest.get("files", [])}
    actual = {entry["path"]: entry for entry in _inventory(output_dir)}
    missing = tuple(sorted(set(expected) - set(actual)))
    unexpected = tuple(sorted(set(actual) - set(expected)))
    changed = tuple(sorted(
        path for path in set(expected) & set(actual)
        if expected[path]["sha256"] != actual[path]["sha256"] or expected[path]["size"] != actual[path]["size"]
    ))

    signature_valid: bool | None = None
    if "hmac_sha256" in manifest:
        if signing_key is None:
            signature_valid = False
        else:
            supplied = manifest.pop("hmac_sha256")
            signature_valid = hmac.compare_digest(supplied, _manifest_signature(manifest, signing_key))

    valid = not missing and not changed and not unexpected and signature_valid is not False
    return VerificationResult(valid, missing, changed, unexpected, signature_valid)


def main() -> int:
    parser = argparse.ArgumentParser(description="Protect or verify Warcraft III map source releases")
    subparsers = parser.add_subparsers(dest="command", required=True)

    protect_parser = subparsers.add_parser("protect", help="Create a protected release directory")
    protect_parser.add_argument("source", type=Path)
    protect_parser.add_argument("output", type=Path)
    protect_parser.add_argument("--build-id")
    protect_parser.add_argument("--signing-key-env", default="WC3_PROTECTION_KEY")
    protect_parser.add_argument("--private-report", action="store_true")
    protect_parser.add_argument("--no-asset-randomization", action="store_true")
    protect_parser.add_argument("--keep-comments", action="store_true")
    protect_parser.add_argument("--keep-whitespace", action="store_true")

    verify_parser = subparsers.add_parser("verify", help="Verify a protected release directory")
    verify_parser.add_argument("output", type=Path)
    verify_parser.add_argument("--signing-key-env", default="WC3_PROTECTION_KEY")

    args = parser.parse_args()
    import os
    signing_key = os.environ.get(args.signing_key_env)

    if args.command == "protect":
        result = protect_project(
            args.source,
            args.output,
            args.build_id,
            options=ProtectionOptions(
                randomize_assets=not args.no_asset_randomization,
                strip_comments=not args.keep_comments,
                reduce_whitespace=not args.keep_whitespace,
                include_private_report=args.private_report,
            ),
            signing_key=signing_key,
        )
        print(json.dumps({
            "output": str(result.output_dir),
            "manifest": str(result.manifest_path),
            "private_report": str(result.private_report_path) if result.private_report_path else None,
            "renamed_assets": result.renamed_assets,
            "protected_scripts": result.protected_scripts,
        }, indent=2))
        return 0

    result = verify_project(args.output, signing_key=signing_key)
    print(json.dumps({
        "valid": result.valid,
        "missing": result.missing,
        "changed": result.changed,
        "unexpected": result.unexpected,
        "signature_valid": result.signature_valid,
    }, indent=2))
    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
