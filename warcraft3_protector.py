#!/usr/bin/env python3
"""Conservative Warcraft III source protection build tool.

This tool prepares distributable source folders. It does not promise irreversible
client-side encryption: Warcraft III must be able to read scripts and assets.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path

SCRIPT_NAMES = {"war3map.lua", "war3map.j"}
ASSET_SUFFIXES = {".mdx", ".mdl", ".blp", ".tga", ".dds", ".wav", ".mp3"}


@dataclass(frozen=True)
class BuildResult:
    output_dir: Path
    manifest_path: Path
    renamed_assets: int
    protected_scripts: int


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _strip_lua_comments(text: str) -> str:
    """Remove ordinary Lua comments while preserving quoted strings."""
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


def protect_lua(text: str) -> str:
    text = _strip_lua_comments(text)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return "\n".join(lines) + "\n"


def protect_jass(text: str) -> str:
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        stripped = re.sub(r"\s+//.*$", "", stripped).rstrip()
        if stripped:
            lines.append(stripped)
    return "\n".join(lines) + "\n"


def _asset_token(path: Path, salt: str) -> str:
    raw = f"{salt}:{path.as_posix()}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:20]


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


def protect_project(source_dir: Path, output_dir: Path, build_id: str | None = None) -> BuildResult:
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
    assets = [p for p in output_dir.rglob("*") if p.is_file() and p.suffix.lower() in ASSET_SUFFIXES]
    for asset in assets:
        rel = asset.relative_to(output_dir)
        token = _asset_token(rel, build_id)
        new_rel = Path("war3mapImported") / token[:2] / (token + asset.suffix.lower())
        mappings[rel.as_posix()] = new_rel.as_posix()

    protected_scripts = 0
    for script in [p for p in output_dir.rglob("*") if p.is_file() and p.name.lower() in SCRIPT_NAMES]:
        text = script.read_text(encoding="utf-8")
        text = _replace_asset_references(text, mappings)
        text = protect_lua(text) if script.name.lower().endswith(".lua") else protect_jass(text)
        script.write_text(text, encoding="utf-8", newline="\n")
        protected_scripts += 1

    for old, new in mappings.items():
        old_path = output_dir / Path(old)
        new_path = output_dir / Path(new)
        new_path.parent.mkdir(parents=True, exist_ok=True)
        old_path.replace(new_path)

    files = []
    for path in sorted(p for p in output_dir.rglob("*") if p.is_file()):
        files.append({
            "path": path.relative_to(output_dir).as_posix(),
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
        })
    manifest = {
        "schema": 1,
        "build_id": build_id,
        "protection": {
            "script_comment_removal": True,
            "script_whitespace_reduction": True,
            "asset_path_randomization": True,
            "cryptographic_secrecy": False,
        },
        "asset_mappings": mappings,
        "files": files,
    }
    manifest_path = output_dir / "protection-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return BuildResult(output_dir, manifest_path, len(mappings), protected_scripts)


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare a protected Warcraft III map source directory")
    parser.add_argument("source", type=Path, help="Extracted private map source directory")
    parser.add_argument("output", type=Path, help="Protected release directory")
    parser.add_argument("--build-id", help="Stable release identifier; random when omitted")
    args = parser.parse_args()
    result = protect_project(args.source, args.output, args.build_id)
    print(json.dumps({
        "output": str(result.output_dir),
        "manifest": str(result.manifest_path),
        "renamed_assets": result.renamed_assets,
        "protected_scripts": result.protected_scripts,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
