# Warcraft III Game Logic Protection

This module prepares an extracted Warcraft III map source directory for release.
It protects distribution hygiene; it does **not** claim irreversible encryption.
The Warcraft III client must still be able to read map scripts and assets.

## What it does

- Copies the private source into a separate release directory.
- Conservatively strips Lua or JASS comments and unnecessary whitespace.
- Randomizes imported model, texture and audio paths.
- Rewrites matching asset references in `war3map.lua` or `war3map.j`.
- Creates a deterministic SHA-256 file manifest for release evidence.
- Refuses to write the protected build inside the private source directory.

## Recommended repository layout

```text
project/
  private-map-source/       # never publish
  release/                  # generated output only
  warcraft3_protector.py
```

Add these patterns to the game repository `.gitignore`:

```gitignore
private-map-source/
*.w3x
*.w3m
release/
```

Only remove the `*.w3x`/`*.w3m` rules when intentionally publishing compiled maps.

## Usage

```bash
python warcraft3_protector.py private-map-source release/MyMap-1.0 \
  --build-id JG-WC3-20260714-001
```

The output includes `protection-manifest.json`. Store a copy of the manifest and
the final packed map hash in a private evidence vault or signed release record.

## Verification

```bash
python -m unittest discover -s tests -v
```

## Important limits

- Do not store signing keys, passwords or secret algorithms in the public map.
- Do not use intentionally malformed archives, client crashes or destructive
  anti-tamper behavior.
- Asset randomization increases extraction cost but cannot make client-loaded
  models or animations unrecoverable.
- Repack the protected directory into `.w3x`/`.w3m` with a trusted map tool after
  this step; binary archive packing is intentionally outside this module.
