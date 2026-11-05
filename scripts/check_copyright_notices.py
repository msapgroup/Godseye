#!/usr/bin/env python3
"""Check project attribution without asserting ownership of third-party content.

Run: python scripts/check_copyright_notices.py
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
CHECKS = {
    "COPYRIGHT.md": ["MSAP Group LLC", "GNU General Public License", "https://github.com/msapgroup/Godseye"],
    "LICENSE": ["GNU GENERAL PUBLIC LICENSE", "Version 3, 29 June 2007"],
    "docs/LEGAL_NOTICES.md": ["COPYRIGHT.md", "LICENSE"],
    "app/access_control.py": ["SPDX-License-Identifier: GPL-3.0-only", "SPDX-FileCopyrightText: 2026 MSAP Group LLC"],
    "app/assets/about-legal.js": ["SPDX-License-Identifier: GPL-3.0-only", "SPDX-FileCopyrightText: 2026 MSAP Group LLC"],
}

def main() -> int:
    errors = []
    for name, markers in CHECKS.items():
        path = ROOT / name
        if not path.is_file():
            errors.append(f"{name}: missing")
            continue
        content = path.read_text(encoding="utf-8")
        for marker in markers:
            if marker not in content:
                errors.append(f"{name}: missing {marker!r}")
    if errors:
        for error in errors:
            print("ERROR:", error, file=sys.stderr)
        return 1
    print(f"Copyright/provenance notices verified in {len(CHECKS)} tracked files.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
