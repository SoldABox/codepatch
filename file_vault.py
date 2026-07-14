#!/usr/bin/env python3
"""Authenticated encrypted vaults for confidential files and source bundles."""
from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import os
import secrets
import struct
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

MAGIC = b"CPVAULT2"
FORMAT_VERSION = 2
DEFAULT_PASSWORD_ENV = "CODEPATCH_VAULT_PASSWORD"
DEFAULT_MANIFEST_KEY_ENV = "CODEPATCH_MANIFEST_KEY"
PRIVATE_MANIFEST_PATH = ".codepatch/private-manifest.json"
SENSITIVE_SUFFIXES = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".md", ".txt", ".json", ".yaml", ".yml", ".csv", ".sql",
    ".py", ".js", ".ts", ".tsx", ".jsx", ".lua", ".j", ".w3x", ".w3m",
}
SECRET_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".kdbx", ".env"}
HIGH_RISK_NAMES = {
    ".env", "id_rsa", "id_ed25519", "credentials.json", "secrets.json",
    "wallet.dat", "seed.txt", "private.key",
}


@dataclass(frozen=True)
class VaultResult:
    vault_path: Path
    manifest_path: Path
    files: int
    plaintext_bytes: int
    elapsed_seconds: float


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    ciphertext_hash_valid: bool
    manifest_signature_valid: bool | None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _manifest_signature(manifest: dict[str, Any], key: str) -> str:
    unsigned = {k: v for k, v in manifest.items() if k != "hmac_sha256"}
    return hmac.new(key.encode("utf-8"), _canonical_json(unsigned), hashlib.sha256).hexdigest()


def _load_crypto():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except ImportError as exc:
        raise RuntimeError("Install security requirements: python -m pip install -r requirements-security.txt") from exc
    return AESGCM, Scrypt


def _derive_key(password: str, salt: bytes) -> bytes:
    if len(password) < 14:
        raise ValueError("Use a password of at least 14 characters")
    _, Scrypt = _load_crypto()
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))


def _password(env_name: str, *, confirm: bool = False) -> str:
    value = os.environ.get(env_name)
    if value:
        if len(value) < 14:
            raise ValueError(f"{env_name} must contain at least 14 characters")
        return value
    first = getpass.getpass("Vault password: ")
    if confirm:
        second = getpass.getpass("Confirm vault password: ")
        if not hmac.compare_digest(first, second):
            raise ValueError("Passwords do not match")
    if len(first) < 14:
        raise ValueError("Use a password of at least 14 characters")
    return first


def _iter_files(inputs: Iterable[Path]) -> list[tuple[Path, str]]:
    files: list[tuple[Path, str]] = []
    seen: set[Path] = set()
    for raw in inputs:
        path = raw.resolve()
        if not path.exists():
            raise ValueError(f"Input does not exist: {path}")
        candidates = [(path, path.name)] if path.is_file() else [
            (child, f"{path.name}/{child.relative_to(path).as_posix()}")
            for child in sorted(path.rglob("*")) if child.is_file()
        ]
        for child, archive_name in candidates:
            if child not in seen:
                seen.add(child)
                files.append((child, archive_name))
    if not files:
        raise ValueError("No files found")
    return files


def classify_path(path: Path) -> str:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if name in HIGH_RISK_NAMES or suffix in SECRET_SUFFIXES:
        return "RESTRICTED_SECRET"
    if suffix in SENSITIVE_SUFFIXES:
        return "CONFIDENTIAL_IP"
    return "INTERNAL"


def inventory(inputs: Iterable[Path]) -> dict[str, Any]:
    entries = []
    for path, archive_name in _iter_files(inputs):
        entries.append({
            "path": archive_name,
            "classification": classify_path(path),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        })
    summary: dict[str, int] = {}
    for entry in entries:
        summary[entry["classification"]] = summary.get(entry["classification"], 0) + 1
    return {"schema": 2, "summary": summary, "files": entries}


def _build_zip(files: list[tuple[Path, str]], destination: Path) -> tuple[list[dict[str, Any]], int]:
    entries = []
    total_size = 0
    for path, archive_name in files:
        size = path.stat().st_size
        total_size += size
        entries.append({
            "path": archive_name,
            "classification": classify_path(path),
            "size": size,
            "sha256": sha256_file(path),
        })
    private_manifest = {"schema": 1, "files": entries}
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path, archive_name in files:
            archive.write(path, archive_name)
        archive.writestr(PRIVATE_MANIFEST_PATH, json.dumps(private_manifest, indent=2, sort_keys=True) + "\n")
    return entries, total_size


def protect_files(
    inputs: Iterable[Path],
    vault_path: Path,
    password: str,
    *,
    manifest_key: str | None = None,
    authority: str = "Jānis Grīnvalds",
    disclose_inventory: bool = False,
) -> VaultResult:
    started = time.perf_counter()
    AESGCM, _ = _load_crypto()
    files = _iter_files(inputs)
    vault_path = vault_path.resolve()
    vault_path.parent.mkdir(parents=True, exist_ok=True)
    if vault_path.exists():
        raise FileExistsError(f"Refusing to overwrite existing vault: {vault_path}")

    with tempfile.TemporaryDirectory() as temp:
        zip_path = Path(temp) / "payload.zip"
        entries, source_bytes = _build_zip(files, zip_path)
        plaintext = zip_path.read_bytes()

    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    header = {
        "format": "CodePatch Vault",
        "version": FORMAT_VERSION,
        "cipher": "AES-256-GCM",
        "kdf": "scrypt-n32768-r8-p1",
        "salt": salt.hex(),
        "nonce": nonce.hex(),
    }
    header_bytes = _canonical_json(header)
    ciphertext = AESGCM(_derive_key(password, salt)).encrypt(nonce, plaintext, header_bytes)
    vault_path.write_bytes(MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes + ciphertext)

    classifications: dict[str, int] = {}
    for entry in entries:
        classifications[entry["classification"]] = classifications.get(entry["classification"], 0) + 1
    manifest: dict[str, Any] = {
        "schema": 2,
        "authority": authority,
        "role": "Project Authority",
        "vault_file": vault_path.name,
        "vault_sha256": sha256_file(vault_path),
        "encrypted_bytes": vault_path.stat().st_size,
        "source_bytes": source_bytes,
        "file_count": len(entries),
        "classification_summary": classifications,
        "inventory_disclosed": disclose_inventory,
        "security": {
            "authenticated_encryption": "AES-256-GCM",
            "password_kdf": "scrypt-n32768-r8-p1",
            "password_stored": False,
            "detailed_inventory_encrypted": True,
            "recoverable_without_password": False,
        },
    }
    if disclose_inventory:
        manifest["files"] = entries
    if manifest_key:
        manifest["hmac_sha256"] = _manifest_signature(manifest, manifest_key)
    manifest_path = vault_path.with_suffix(vault_path.suffix + ".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return VaultResult(vault_path, manifest_path, len(entries), len(plaintext), time.perf_counter() - started)


def verify_vault(vault_path: Path, manifest_path: Path | None = None, *, manifest_key: str | None = None) -> VerificationResult:
    vault_path = vault_path.resolve()
    manifest_path = (manifest_path or vault_path.with_suffix(vault_path.suffix + ".manifest.json")).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    ciphertext_hash_valid = hmac.compare_digest(manifest["vault_sha256"], sha256_file(vault_path))
    signature_valid: bool | None = None
    if "hmac_sha256" in manifest:
        signature_valid = bool(manifest_key) and hmac.compare_digest(
            manifest["hmac_sha256"], _manifest_signature(manifest, manifest_key or "")
        )
    return VerificationResult(ciphertext_hash_valid and signature_valid is not False, ciphertext_hash_valid, signature_valid)


def _safe_extract(archive: zipfile.ZipFile, destination: Path) -> None:
    root = destination.resolve()
    for info in archive.infolist():
        relative = PurePosixPath(info.filename)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"Unsafe archive path: {info.filename}")
        target = (root / Path(*relative.parts)).resolve()
        if root != target and root not in target.parents:
            raise ValueError(f"Archive path escapes destination: {info.filename}")
    archive.extractall(root)


def decrypt_vault(vault_path: Path, output_dir: Path, password: str) -> int:
    AESGCM, _ = _load_crypto()
    data = vault_path.read_bytes()
    if not data.startswith(MAGIC):
        raise ValueError("Not a CodePatch vault")
    offset = len(MAGIC)
    if len(data) < offset + 4:
        raise ValueError("Truncated vault")
    header_length = struct.unpack(">I", data[offset:offset + 4])[0]
    offset += 4
    if header_length <= 0 or header_length > 64 * 1024 or len(data) < offset + header_length + 16:
        raise ValueError("Invalid or truncated vault header")
    header_bytes = data[offset:offset + header_length]
    offset += header_length
    header = json.loads(header_bytes.decode("utf-8"))
    if header.get("version") != FORMAT_VERSION or header.get("cipher") != "AES-256-GCM":
        raise ValueError("Unsupported vault format")
    salt = bytes.fromhex(header["salt"])
    nonce = bytes.fromhex(header["nonce"])
    plaintext = AESGCM(_derive_key(password, salt)).decrypt(nonce, data[offset:], header_bytes)

    output_dir = output_dir.resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError(f"Output directory must be empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as handle:
        temp_zip = Path(handle.name)
        handle.write(plaintext)
    try:
        with zipfile.ZipFile(temp_zip, "r") as archive:
            _safe_extract(archive, output_dir)
            return len([item for item in archive.infolist() if not item.is_dir() and item.filename != PRIVATE_MANIFEST_PATH])
    finally:
        temp_zip.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Protect sensitive files with encryption and tamper evidence")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("inputs", nargs="+", type=Path)
    scan.add_argument("--output", type=Path)
    protect = sub.add_parser("protect")
    protect.add_argument("inputs", nargs="+", type=Path)
    protect.add_argument("--output", required=True, type=Path)
    protect.add_argument("--password-env", default=DEFAULT_PASSWORD_ENV)
    protect.add_argument("--manifest-key-env", default=DEFAULT_MANIFEST_KEY_ENV)
    protect.add_argument("--authority", default="Jānis Grīnvalds")
    protect.add_argument("--disclose-inventory", action="store_true")
    verify = sub.add_parser("verify")
    verify.add_argument("vault", type=Path)
    verify.add_argument("--manifest", type=Path)
    verify.add_argument("--manifest-key-env", default=DEFAULT_MANIFEST_KEY_ENV)
    decrypt = sub.add_parser("decrypt")
    decrypt.add_argument("vault", type=Path)
    decrypt.add_argument("output", type=Path)
    decrypt.add_argument("--password-env", default=DEFAULT_PASSWORD_ENV)
    args = parser.parse_args()

    if args.command == "scan":
        output = json.dumps(inventory(args.inputs), indent=2, sort_keys=True) + "\n"
        args.output.write_text(output, encoding="utf-8") if args.output else print(output, end="")
        return 0
    if args.command == "protect":
        result = protect_files(
            args.inputs,
            args.output,
            _password(args.password_env, confirm=True),
            manifest_key=os.environ.get(args.manifest_key_env),
            authority=args.authority,
            disclose_inventory=args.disclose_inventory,
        )
        print(json.dumps({
            "vault": str(result.vault_path),
            "manifest": str(result.manifest_path),
            "files": result.files,
            "plaintext_bytes": result.plaintext_bytes,
            "elapsed_seconds": round(result.elapsed_seconds, 4),
        }, indent=2))
        return 0
    if args.command == "verify":
        result = verify_vault(args.vault, args.manifest, manifest_key=os.environ.get(args.manifest_key_env))
        print(json.dumps(result.__dict__, indent=2))
        return 0 if result.valid else 1
    count = decrypt_vault(args.vault, args.output, _password(args.password_env))
    print(json.dumps({"output": str(args.output.resolve()), "files": count}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
