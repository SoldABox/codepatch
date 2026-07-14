#!/usr/bin/env python3
"""Protect sensitive documents and source bundles with authenticated encryption.

Security properties:
- AES-256-GCM authenticated encryption
- scrypt password-based key derivation with a random salt
- SHA-256 plaintext and ciphertext hashes
- optional HMAC-SHA256 manifest authentication
- no passwords accepted as command-line arguments

Install the optional cryptography dependency before using encrypt/decrypt:
    python -m pip install -r requirements-security.txt
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import os
import secrets
import shutil
import struct
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

MAGIC = b"CPVAULT1"
FORMAT_VERSION = 1
DEFAULT_PASSWORD_ENV = "CODEPATCH_VAULT_PASSWORD"
DEFAULT_MANIFEST_KEY_ENV = "CODEPATCH_MANIFEST_KEY"
SENSITIVE_SUFFIXES = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".md", ".txt", ".json", ".yaml", ".yml", ".csv", ".sql",
    ".py", ".js", ".ts", ".tsx", ".jsx", ".lua", ".j", ".w3x", ".w3m",
    ".pem", ".key", ".p12", ".pfx", ".kdbx", ".env",
}
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
        raise RuntimeError(
            "Missing dependency: install with 'python -m pip install -r requirements-security.txt'"
        ) from exc
    return AESGCM, Scrypt


def _derive_key(password: str, salt: bytes) -> bytes:
    _, Scrypt = _load_crypto()
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def _password(env_name: str, *, confirm: bool = False) -> str:
    value = os.environ.get(env_name)
    if value:
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
        if path.is_file():
            candidates = [(path, path.name)]
        else:
            candidates = [
                (child, f"{path.name}/{child.relative_to(path).as_posix()}")
                for child in sorted(path.rglob("*")) if child.is_file()
            ]
        for child, archive_name in candidates:
            if child in seen:
                continue
            seen.add(child)
            files.append((child, archive_name))
    if not files:
        raise ValueError("No files found")
    return files


def classify_path(path: Path) -> str:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if name in HIGH_RISK_NAMES or suffix in {".pem", ".key", ".p12", ".pfx", ".kdbx", ".env"}:
        return "RESTRICTED_SECRET"
    if suffix in SENSITIVE_SUFFIXES:
        return "CONFIDENTIAL_IP"
    return "INTERNAL"


def inventory(inputs: Iterable[Path]) -> dict[str, Any]:
    files = _iter_files(inputs)
    entries = []
    for path, archive_name in files:
        entries.append({
            "path": archive_name,
            "classification": classify_path(path),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        })
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry["classification"]] = counts.get(entry["classification"], 0) + 1
    return {"schema": 1, "summary": counts, "files": entries}


def _build_zip(files: list[tuple[Path, str]], destination: Path) -> list[dict[str, Any]]:
    entries = []
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path, archive_name in files:
            archive.write(path, archive_name)
            entries.append({
                "path": archive_name,
                "classification": classify_path(path),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            })
    return entries


def protect_files(
    inputs: Iterable[Path],
    vault_path: Path,
    password: str,
    *,
    manifest_key: str | None = None,
    authority: str = "Jānis Grīnvalds",
) -> VaultResult:
    AESGCM, _ = _load_crypto()
    files = _iter_files(inputs)
    vault_path = vault_path.resolve()
    vault_path.parent.mkdir(parents=True, exist_ok=True)
    if vault_path.exists():
        raise FileExistsError(f"Refusing to overwrite existing vault: {vault_path}")

    with tempfile.TemporaryDirectory() as temp:
        zip_path = Path(temp) / "payload.zip"
        entries = _build_zip(files, zip_path)
        plaintext = zip_path.read_bytes()

    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = _derive_key(password, salt)
    header = {
        "format": "CodePatch Vault",
        "version": FORMAT_VERSION,
        "cipher": "AES-256-GCM",
        "kdf": "scrypt-n32768-r8-p1",
        "salt": salt.hex(),
        "nonce": nonce.hex(),
    }
    associated_data = _canonical_json(header)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    header_bytes = _canonical_json(header)
    vault_path.write_bytes(MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes + ciphertext)

    classifications: dict[str, int] = {}
    for entry in entries:
        classifications[entry["classification"]] = classifications.get(entry["classification"], 0) + 1
    manifest: dict[str, Any] = {
        "schema": 1,
        "authority": authority,
        "role": "Project Authority",
        "vault_file": vault_path.name,
        "vault_sha256": sha256_file(vault_path),
        "plaintext_archive_sha256": hashlib.sha256(plaintext).hexdigest(),
        "plaintext_bytes": len(plaintext),
        "file_count": len(entries),
        "classification_summary": classifications,
        "files": entries,
        "security": {
            "authenticated_encryption": "AES-256-GCM",
            "password_kdf": "scrypt",
            "password_stored": False,
            "recoverable_without_password": False,
        },
    }
    if manifest_key:
        manifest["hmac_sha256"] = _manifest_signature(manifest, manifest_key)
    manifest_path = vault_path.with_suffix(vault_path.suffix + ".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return VaultResult(vault_path, manifest_path, len(entries), len(plaintext))


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
    return VerificationResult(
        valid=ciphertext_hash_valid and signature_valid is not False,
        ciphertext_hash_valid=ciphertext_hash_valid,
        manifest_signature_valid=signature_valid,
    )


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
    header_length = struct.unpack(">I", data[offset:offset + 4])[0]
    offset += 4
    header_bytes = data[offset:offset + header_length]
    offset += header_length
    header = json.loads(header_bytes.decode("utf-8"))
    salt = bytes.fromhex(header["salt"])
    nonce = bytes.fromhex(header["nonce"])
    key = _derive_key(password, salt)
    plaintext = AESGCM(key).decrypt(nonce, data[offset:], header_bytes)

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
            count = len([item for item in archive.infolist() if not item.is_dir()])
    finally:
        temp_zip.unlink(missing_ok=True)
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description="Protect sensitive files with encryption and tamper evidence")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Classify and hash files without changing them")
    scan.add_argument("inputs", nargs="+", type=Path)
    scan.add_argument("--output", type=Path)

    protect = sub.add_parser("protect", help="Create an encrypted .cpvault file")
    protect.add_argument("inputs", nargs="+", type=Path)
    protect.add_argument("--output", required=True, type=Path)
    protect.add_argument("--password-env", default=DEFAULT_PASSWORD_ENV)
    protect.add_argument("--manifest-key-env", default=DEFAULT_MANIFEST_KEY_ENV)
    protect.add_argument("--authority", default="Jānis Grīnvalds")

    verify = sub.add_parser("verify", help="Verify vault and manifest integrity")
    verify.add_argument("vault", type=Path)
    verify.add_argument("--manifest", type=Path)
    verify.add_argument("--manifest-key-env", default=DEFAULT_MANIFEST_KEY_ENV)

    decrypt = sub.add_parser("decrypt", help="Decrypt a vault into an empty directory")
    decrypt.add_argument("vault", type=Path)
    decrypt.add_argument("output", type=Path)
    decrypt.add_argument("--password-env", default=DEFAULT_PASSWORD_ENV)

    args = parser.parse_args()
    if args.command == "scan":
        report = inventory(args.inputs)
        output = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        return 0
    if args.command == "protect":
        result = protect_files(
            args.inputs,
            args.output,
            _password(args.password_env, confirm=True),
            manifest_key=os.environ.get(args.manifest_key_env),
            authority=args.authority,
        )
        print(json.dumps({
            "vault": str(result.vault_path),
            "manifest": str(result.manifest_path),
            "files": result.files,
            "plaintext_bytes": result.plaintext_bytes,
        }, indent=2))
        return 0
    if args.command == "verify":
        result = verify_vault(
            args.vault,
            args.manifest,
            manifest_key=os.environ.get(args.manifest_key_env),
        )
        print(json.dumps(result.__dict__, indent=2))
        return 0 if result.valid else 1
    count = decrypt_vault(args.vault, args.output, _password(args.password_env))
    print(json.dumps({"output": str(args.output.resolve()), "files": count}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
