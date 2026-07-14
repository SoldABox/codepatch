# Master File Protection Plan

Authority: Jānis Grīnvalds  
Role: Project Authority  
Scope: proprietary documents, source code, game logic, models, animations, research, trading systems, evidence, credentials and release artifacts.

## Reference risk profile

A document such as `CORE PHILOSOPHY 2.pdf` contains proprietary operational knowledge: market-state definitions, bot classifications, entry filters, risk allocation rules and repeatable strategy parameters. A plain PDF is readable, copyable and modifiable. A PDF open-password alone is not a sufficient protection system.

## Protection objectives

1. Confidentiality - unauthorized people cannot read the protected contents.
2. Integrity - unauthorized changes are detectable.
3. Provenance - releases can be tied to a named authority, version and hash.
4. Least privilege - only the minimum necessary files are shared.
5. Recovery - protected originals remain recoverable after device loss or corruption.
6. Leak prevention - private source and secrets do not enter Git or public release bundles.
7. Revocation readiness - access keys and sharing links can be rotated or withdrawn.
8. Honest limits - no client-distributed file is described as impossible to copy.

## Four protection classes

### PUBLIC

Approved marketing material and public release documentation.

Controls:
- SHA-256 manifest
- version and release date
- accurate authorship/role statement
- immutable release record

### INTERNAL

Ordinary project files not approved for public release.

Controls:
- private repository or encrypted local storage
- authenticated accounts and MFA
- backups
- access logging where available

### CONFIDENTIAL_IP

Strategies, research, source code, designs, PDFs, models, animation logic and unpublished specifications.

Controls:
- AES-256-GCM encrypted vault
- strong unique vault password
- separate HMAC manifest key where practical
- no public repository storage
- recipient-specific shared copies
- provenance manifest and backup rotation

### RESTRICTED_SECRET

Private keys, recovery phrases, API secrets, signing keys, production credentials and password databases.

Controls:
- dedicated password manager, HSM or operating-system secret store
- never commit to Git
- never include in ordinary document vaults when avoidable
- access limited to named operators
- rotation and incident-response procedure

## Storage architecture

```text
PRIVATE MASTER
  original editable documents and source
        |
        +--> ENCRYPTED PRIMARY VAULT
        |      local encrypted disk or approved private storage
        |
        +--> OFFLINE RECOVERY COPY
        |      separate device/location, periodically tested
        |
        +--> CONTROLLED RELEASE PIPELINE
               sanitized recipient-specific copy
               hash + manifest + version
               encrypted transport
```

Never use a public release artifact as the only editable master.

## Implemented CodePatch controls

`file_vault.py` provides:

- file classification and SHA-256 inventory;
- encrypted `.cpvault` containers using AES-256-GCM;
- scrypt password derivation with random salt;
- authenticated ciphertext, so incorrect passwords or tampering fail decryption;
- public sidecar manifests with plaintext file hashes and classifications;
- optional HMAC-SHA256 manifest authentication;
- password input through an environment variable or hidden prompt, never a CLI argument;
- safe extraction that rejects absolute paths and `..` traversal;
- refusal to overwrite an existing vault;
- round-trip and tamper-detection tests.

## Installation

```bash
python -m pip install -r requirements-security.txt
```

## Scan before protection

```bash
python file_vault.py scan "CORE PHILOSOPHY 2.pdf" --output core-philosophy.inventory.json
```

Review the report. Move `RESTRICTED_SECRET` files into a dedicated secret manager instead of casually sharing them.

## Create an encrypted vault on Windows PowerShell

```powershell
$env:CODEPATCH_VAULT_PASSWORD = "use-a-long-unique-password"
$env:CODEPATCH_MANIFEST_KEY = "use-a-different-random-secret"

python file_vault.py protect "CORE PHILOSOPHY 2.pdf" `
  --output "CORE-PHILOSOPHY-2.cpvault" `
  --authority "Jānis Grīnvalds"

Remove-Item Env:CODEPATCH_VAULT_PASSWORD
Remove-Item Env:CODEPATCH_MANIFEST_KEY
```

Using the hidden interactive password prompt is preferred on shared machines because environment variables may be visible to sufficiently privileged local processes.

## Verify before storage or sharing

```powershell
$env:CODEPATCH_MANIFEST_KEY = "the-original-manifest-secret"
python file_vault.py verify "CORE-PHILOSOPHY-2.cpvault"
Remove-Item Env:CODEPATCH_MANIFEST_KEY
```

Verification confirms the vault hash and, when configured, the manifest HMAC. It does not decrypt the contents.

## Recover files

```powershell
$env:CODEPATCH_VAULT_PASSWORD = "the-original-vault-password"
python file_vault.py decrypt "CORE-PHILOSOPHY-2.cpvault" "restored-core-philosophy"
Remove-Item Env:CODEPATCH_VAULT_PASSWORD
```

Decrypt only into a trusted device and an empty destination directory.

## Repository controls

Recommended `.gitignore` entries:

```gitignore
*.cpvault
*.cpvault.manifest.json
*.inventory.json
private/
masters/
recovery/
.env
.env.*
*.pem
*.key
*.p12
*.pfx
*.kdbx
```

A private repository reduces exposure but is not encryption. Repository administrators, compromised credentials, malicious dependencies and copied clones remain risks.

## Controlled-sharing procedure

1. Keep the master encrypted and private.
2. Create a recipient-specific copy containing only required pages/files.
3. Assign a unique release ID and record the recipient/purpose privately.
4. Encrypt the copy with a unique password.
5. Send the vault and password through different channels.
6. Verify the vault hash after upload/download.
7. Set an expiry or delete the shared copy after its purpose ends.
8. Record revocation or supersession without deleting historical evidence.

Visible watermarks may deter casual redistribution, but they are not encryption and can sometimes be removed. Use them only as an additional attribution layer.

## Backup rule: 3-2-1

- 3 copies of critical masters;
- 2 different storage types;
- 1 copy offline or in a separate trusted location.

At least quarterly, restore a test vault and confirm that passwords, tools and backup media still work.

## Incident response

When a protected file may have leaked:

1. Preserve logs, hashes, affected versions and timestamps.
2. Revoke sharing links and access tokens.
3. Rotate any secrets contained in or stored beside the file.
4. Identify the exact exposed version and recipients.
5. Publish a superseding version only when appropriate.
6. Do not destroy original evidence.
7. Assess contractual, privacy and notification obligations with qualified counsel where necessary.

## Limits

- Encryption cannot protect a file after an authorized recipient decrypts and copies it.
- HMAC uses a shared secret and is not a public digital signature.
- Losing the vault password means losing the encrypted contents; CodePatch has no backdoor.
- Malware running under the user account may capture plaintext or passwords.
- Strong operational discipline is as important as the encryption algorithm.
