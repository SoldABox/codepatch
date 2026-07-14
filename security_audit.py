#!/usr/bin/env python3
"""Deterministic repository security audit for CodePatch.

The audit is intentionally local and dependency-light so it can run in CI,
pre-commit hooks, or offline environments. It never prints secret values.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, List

FORBIDDEN_SUFFIXES = {".cpvault", ".p12", ".pfx", ".kdbx", ".pem", ".key"}
FORBIDDEN_NAMES = {".env", "credentials.json", "secrets.json", "wallet.dat", "seed.txt"}
GENERIC_SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"](?P<value>[^'\"\n]{12,})['\"]"
)
SECRET_PATTERNS = {
    "private_key_header": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "openai_key": re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
}
TEXT_SUFFIXES = {
    ".py", ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini",
    ".cfg", ".js", ".ts", ".tsx", ".jsx", ".sh", ".ps1", ".bat",
}
MAX_SCAN_BYTES = 2 * 1024 * 1024
PLACEHOLDER_MARKERS = {
    "placeholder", "example", "sample", "benchmark", "correct horse",
    "use-a-", "use_a_", "your-", "your_", "change-me", "changeme",
    "the-original", "sufficient length", "long-random", "test-secret",
}


@dataclass(frozen=True)
class Finding:
    severity: str
    rule: str
    path: str
    line: int | None
    message: str


@dataclass(frozen=True)
class AuditResult:
    score: int
    passed: bool
    files_scanned: int
    findings: List[Finding]


def _tracked_files(root: Path) -> list[Path]:
    try:
        output = subprocess.check_output(
            ["git", "ls-files", "-z"], cwd=root, stderr=subprocess.DEVNULL
        )
        names = [name for name in output.decode("utf-8").split("\0") if name]
        return [root / name for name in names]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return [path for path in root.rglob("*") if path.is_file() and ".git" not in path.parts]


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.lower().strip()
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return True
    if value.upper() == value and re.fullmatch(r"[A-Z0-9_\-]+", value):
        return True
    return False


def _scan_text(path: Path, relative: str) -> Iterable[Finding]:
    try:
        if path.stat().st_size > MAX_SCAN_BYTES:
            return []
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if "security-audit: allow" in line:
            continue

        generic_match = GENERIC_SECRET_PATTERN.search(line)
        if generic_match and not _looks_like_placeholder(generic_match.group("value")):
            findings.append(Finding(
                severity="CRITICAL",
                rule="generic_api_key",
                path=relative,
                line=line_number,
                message="Possible secret material in tracked text",
            ))

        for rule, pattern in SECRET_PATTERNS.items():
            if pattern.search(line):
                findings.append(Finding(
                    severity="CRITICAL",
                    rule=rule,
                    path=relative,
                    line=line_number,
                    message="Possible secret material in tracked text",
                ))
    return findings


def audit_repository(root: Path) -> AuditResult:
    root = root.resolve()
    findings: list[Finding] = []
    files = _tracked_files(root)
    for path in files:
        relative = path.relative_to(root).as_posix()
        lower_name = path.name.lower()
        if lower_name in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            findings.append(Finding(
                severity="CRITICAL",
                rule="forbidden_sensitive_file",
                path=relative,
                line=None,
                message="Sensitive or generated file must not be tracked",
            ))
        if path.suffix.lower() in TEXT_SUFFIXES or lower_name in {"dockerfile", "makefile"}:
            findings.extend(_scan_text(path, relative))

    deductions = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 1}
    score = max(0, 100 - sum(deductions.get(item.severity, 1) for item in findings))
    return AuditResult(
        score=score,
        passed=not any(f.severity in {"CRITICAL", "HIGH"} for f in findings),
        files_scanned=len(files),
        findings=findings,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit tracked repository files for security regressions")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    parser.add_argument("--minimum-score", type=int, default=100)
    args = parser.parse_args()
    result = audit_repository(args.root)
    payload = {
        "schema": 1,
        "score": result.score,
        "passed": result.passed and result.score >= args.minimum_score,
        "minimum_score": args.minimum_score,
        "files_scanned": result.files_scanned,
        "findings": [asdict(item) for item in result.findings],
    }
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
