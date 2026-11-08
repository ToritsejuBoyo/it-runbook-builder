#!/usr/bin/env python3
"""
sanitize_session_history.py - Sanitizes terminal command history for SOP/Runbook generation.
Strips common internal IPs, domain names, and passwords.
Zero third-party dependencies.
"""

import argparse
import json
import re

IP_PATTERN = r'(?:\d{1,3}\.){3}\d{1,3}'
EMAIL_PATTERN = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
SECRET_PATTERN = r'(?i)(password|secret|apikey|token)\s*[:=]\s*[^\s]+'

def sanitize_line(line: str) -> str:
    line = re.sub(IP_PATTERN, '10.x.x.x', line)
    line = re.sub(EMAIL_PATTERN, 'user@corp.example.com', line)
    line = re.sub(SECRET_PATTERN, r': [REDACTED_SECRET]', line)
    return line

def process_history(filepath: str) -> list:
    cleaned = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for idx, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            cleaned.append({
                "step": idx,
                "sanitized_command": sanitize_line(line)
            })
    return cleaned

def main():
    parser = argparse.ArgumentParser(description="Sanitize terminal history for runbook creation.")
    parser.add_argument("--input", "-i", required=True, help="Path to raw command history file")
    parser.add_argument("--output", "-o", default=None, help="Output JSON path")
    args = parser.parse_args()

    items = process_history(args.input)
    out_json = json.dumps({"total_commands": len(items), "commands": items}, indent=2)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(out_json)
        print(f"Sanitized history saved to {args.output}")
    else:
        print(out_json)

if __name__ == "__main__":
    main()
