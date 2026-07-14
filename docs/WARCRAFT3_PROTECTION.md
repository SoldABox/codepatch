# Warcraft III Game Logic Protection

This module prepares an extracted Warcraft III map source directory for release.
It raises reverse-engineering cost and detects release tampering; it does **not**
claim irreversible encryption because the Warcraft III client must read scripts
and assets during gameplay.

## Protection layers

- Copies private source into a separate generated release directory.
- Conservatively strips Lua or JASS comments and unnecessary whitespace.
- Randomizes imported model, texture and audio paths.
- Rewrites matching references in `war3map.lua` or `war3map.j`, including escaped Lua paths.
- Generates a public SHA-256 inventory without exposing original asset names.
- Optionally signs the manifest with HMAC-SHA256 from an environment secret.
- Verifies missing, changed and unexpected release files.
- Keeps optional source-to-release mappings outside the release directory.
- Refuses to write output inside the private source directory.

## Recommended layout

```text
project/
  private-map-source/       # never publish
  private-build-records/    # manifests/mappings; never publish
  release/                  # generated output only
  warcraft3_protector.py
```

Recommended `.gitignore` rules:

```gitignore
private-map-source/
private-build-records/
release/
*.w3x
*.w3m
*-protection-private-report.json
```

## Protect a release

Without manifest signing:

```bash
python warcraft3_protector.py protect private-map-source release/MyMap-1.0 \
  --build-id JG-WC3-20260714-001
```

With HMAC manifest signing in PowerShell:

```powershell
$env:WC3_PROTECTION_KEY = "use-a-long-random-secret"
python warcraft3_protector.py protect private-map-source release/MyMap-1.0 `
  --build-id JG-WC3-20260714-001
```

Generate an optional private asset-mapping report outside the release folder:

```bash
python warcraft3_protector.py protect private-map-source release/MyMap-1.0 \
  --build-id JG-WC3-20260714-001 --private-report
```

Never publish that private report. It contains original source paths.

## Verify a release

```bash
python warcraft3_protector.py verify release/MyMap-1.0
```

For a signed manifest, set the same `WC3_PROTECTION_KEY` before verification.
The command exits with status `0` for a valid release and `1` when files or the
signature do not match.

## Optional controls

```text
--no-asset-randomization  Keep original asset paths
--keep-comments           Preserve script comments
--keep-whitespace         Preserve script spacing
--signing-key-env NAME    Read the HMAC key from another environment variable
```

## Tests

```bash
python -m unittest discover -s tests -v
python -m py_compile warcraft3_protector.py
```

GitHub Actions tests Python 3.9, 3.11 and 3.13.

## Important limits

- Never store signing keys, passwords or proprietary formulas in the map or repository.
- HMAC proves knowledge of a shared secret; it is not a public digital signature.
- Do not use malformed archives, client crashes or destructive anti-tamper behavior.
- Asset randomization cannot make client-loaded models or animations unrecoverable.
- Repack the protected directory into `.w3x`/`.w3m` with a trusted map tool after
  this step; binary archive packing remains outside this module.
