"""Audit saved HTTP response headers against a small hardening baseline."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

BASELINE = {
    "content-security-policy": "Reduces script and content injection impact",
    "strict-transport-security": "Enforces HTTPS for future requests",
    "x-content-type-options": "Prevents MIME type sniffing",
    "referrer-policy": "Limits referrer information leakage",
    "permissions-policy": "Restricts browser capabilities",
}


def parse_headers(text: str) -> dict[str, str]:
    headers = {}
    for line in text.splitlines():
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    return headers


def audit(text: str) -> dict:
    headers = parse_headers(text)
    missing = [{"header": name, "purpose": purpose} for name, purpose in BASELINE.items() if name not in headers]
    return {"present": sorted(name for name in BASELINE if name in headers), "missing": missing, "observed_server": headers.get("server")}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("headers", type=Path, help="Text file containing saved HTTP response headers")
    args = parser.parse_args()
    print(json.dumps(audit(args.headers.read_text(encoding="utf-8")), indent=2))


if __name__ == "__main__":
    main()
