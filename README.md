# CodePatch

**Universal Secure Python Code Auto-Healing and File Protection Engine**

---

## Overview

**CodePatch** repairs unsafe Python patterns, prepares Warcraft III custom-map source for controlled release, and protects confidential documents or source bundles using authenticated encryption and tamper-evident manifests.

The project does not claim that distributed client-side game code or decrypted documents are impossible to copy. It focuses on practical protection: private-master separation, AES-256-GCM encrypted vaults, strong password derivation, asset-path randomization, integrity verification and accurate provenance records.

---

## Features

- Detects Python syntax errors and unsafe patterns
- Protects extracted Warcraft III Lua/JASS release sources
- Randomizes Warcraft III imported asset paths and rewrites references
- Generates SHA-256 release manifests
- Classifies sensitive files before storage or sharing
- Creates authenticated AES-256-GCM `.cpvault` containers
- Uses scrypt with a random salt for password-derived keys
- Supports optional HMAC-SHA256 manifest authentication
- Detects encrypted-vault tampering before decryption
- Safely blocks archive path traversal during recovery
- Avoids passwords in command-line arguments or manifests

---

## Protect confidential files

Install the security dependency:

```bash
python -m pip install -r requirements-security.txt
```

Scan and classify files:

```bash
python file_vault.py scan "CORE PHILOSOPHY 2.pdf" \
  --output core-philosophy.inventory.json
```

Create and verify an encrypted vault:

```bash
python file_vault.py protect "CORE PHILOSOPHY 2.pdf" \
  --output CORE-PHILOSOPHY-2.cpvault

python file_vault.py verify CORE-PHILOSOPHY-2.cpvault
```

Recover into an empty directory:

```bash
python file_vault.py decrypt CORE-PHILOSOPHY-2.cpvault restored-files
```

The password is read from `CODEPATCH_VAULT_PASSWORD` or a hidden interactive prompt. It is never accepted as a command-line value.

See [`docs/MASTER_FILE_PROTECTION_PLAN.md`](docs/MASTER_FILE_PROTECTION_PLAN.md) for classification, backups, controlled sharing, repository controls and incident response.

---

## Warcraft III protection

```bash
python warcraft3_protector.py private-map-source release/MyMap-1.0 \
  --build-id JG-WC3-20260714-001
```

The source and output directories must be separate. Keep the editable map source private and distribute only a reviewed, repacked release build.

Detailed instructions and limitations are in [`docs/WARCRAFT3_PROTECTION.md`](docs/WARCRAFT3_PROTECTION.md).

---

## Tests

```bash
python -m unittest discover -s tests -v
```

---

## Getting Started

### Requirements

- Python 3.9 or higher
- `cryptography` for encrypted file vaults

### Installation

```bash
git clone https://github.com/soldabox/CodePatch.git
cd CodePatch
python -m pip install -r requirements-security.txt
```
