#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import statistics
import tempfile
import time
from pathlib import Path

from file_vault import decrypt_vault, protect_files, verify_vault

PASSWORD = "benchmark password with sufficient length"


def make_fixture(root: Path, total_bytes: int, files: int) -> Path:
    source = root / "fixture"
    source.mkdir()
    chunk = max(1, total_bytes // files)
    for index in range(files):
        size = chunk if index < files - 1 else total_bytes - chunk * (files - 1)
        (source / f"file-{index:04d}.bin").write_bytes(os.urandom(max(0, size)))
    return source


def run_once(total_bytes: int, files: int) -> dict[str, float | int | bool]:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        source = make_fixture(root, total_bytes, files)
        vault = root / "benchmark.cpvault"
        start = time.perf_counter()
        result = protect_files([source], vault, PASSWORD, manifest_key="benchmark-manifest-key")
        protect_seconds = time.perf_counter() - start

        start = time.perf_counter()
        verification = verify_vault(vault, manifest_key="benchmark-manifest-key")
        verify_seconds = time.perf_counter() - start

        start = time.perf_counter()
        restored = root / "restored"
        restored_files = decrypt_vault(vault, restored, PASSWORD)
        decrypt_seconds = time.perf_counter() - start

        mib = total_bytes / (1024 * 1024) if total_bytes else 0.0
        return {
            "bytes": total_bytes,
            "files": files,
            "vault_bytes": vault.stat().st_size,
            "protect_seconds": protect_seconds,
            "verify_seconds": verify_seconds,
            "decrypt_seconds": decrypt_seconds,
            "protect_mib_s": mib / protect_seconds if protect_seconds else 0.0,
            "decrypt_mib_s": mib / decrypt_seconds if decrypt_seconds else 0.0,
            "verification_valid": verification.valid,
            "restored_files": restored_files,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--size-mib", type=int, default=8)
    parser.add_argument("--files", type=int, default=32)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--max-protect-seconds", type=float, default=30.0)
    parser.add_argument("--max-decrypt-seconds", type=float, default=30.0)
    args = parser.parse_args()

    if args.size_mib < 1 or args.files < 1 or args.runs < 1:
        raise SystemExit("size, files and runs must be positive")

    results = [run_once(args.size_mib * 1024 * 1024, args.files) for _ in range(args.runs)]
    summary = {
        "schema": 1,
        "configuration": {
            "size_mib": args.size_mib,
            "files": args.files,
            "runs": args.runs,
        },
        "median": {
            "protect_seconds": statistics.median(float(r["protect_seconds"]) for r in results),
            "verify_seconds": statistics.median(float(r["verify_seconds"]) for r in results),
            "decrypt_seconds": statistics.median(float(r["decrypt_seconds"]) for r in results),
            "protect_mib_s": statistics.median(float(r["protect_mib_s"]) for r in results),
            "decrypt_mib_s": statistics.median(float(r["decrypt_mib_s"]) for r in results),
        },
        "runs": results,
    }
    text = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")

    valid = all(bool(r["verification_valid"]) and int(r["restored_files"]) == args.files for r in results)
    within_threshold = (
        summary["median"]["protect_seconds"] <= args.max_protect_seconds
        and summary["median"]["decrypt_seconds"] <= args.max_decrypt_seconds
    )
    return 0 if valid and within_threshold else 1


if __name__ == "__main__":
    raise SystemExit(main())
