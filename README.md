# CodePatch

**Universal Secure Python Code Auto-Healing Engine**

---

## Overview

**CodePatch** is a lightweight, safe, and automated tool for repairing and protecting source code. It helps developers, learners, and educators detect common programming issues, produce safer Python code, and prepare Warcraft III custom-map source for controlled releases.

The project does not claim that distributed client-side game code can be made impossible to extract. Protection features focus on safe build separation, conservative source transformation, asset-path randomization, and verifiable release manifests.

---

## Features

- Detects Python syntax errors before running code
- Flags undefined variables to prevent runtime errors
- Identifies unsafe `eval` usage and replaces it safely
- Automatically produces a fixed, clean version of Python code
- Provides a command-line interface
- Protects extracted Warcraft III Lua/JASS release sources
- Randomizes Warcraft III imported asset paths and rewrites script references
- Generates SHA-256 release manifests for provenance and tamper comparison

---

## Warcraft III protection

```bash
python warcraft3_protector.py private-map-source release/MyMap-1.0 \
  --build-id JG-WC3-20260714-001
```

The source and output directories must be separate. Keep the editable map source private and distribute only a reviewed, repacked release build.

Detailed instructions and limitations are in [`docs/WARCRAFT3_PROTECTION.md`](docs/WARCRAFT3_PROTECTION.md).

Run the regression tests with:

```bash
python -m unittest discover -s tests -v
```

---

## Getting Started

### Requirements

- Python 3.9 or higher

### Installation

Clone the repository:

```bash
git clone https://github.com/soldabox/CodePatch.git
cd CodePatch
```
