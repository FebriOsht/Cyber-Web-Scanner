"""Cyber Web Scanner from the command line.

Examples:
  python cli.py example.com
  python cli.py https://example.com --json
  python cli.py example.com --out report.json
"""
import argparse
import json
import sys

from scanner import run_full_scan

LEVEL_ORDER = {"Kritis": 0, "Tinggi": 1, "Menengah": 2, "Rendah": 3}


def pick(d, *keys):
    for k in keys:
        if d.get(k):
            return d[k]
    return ""


def main():
    parser = argparse.ArgumentParser(description="Check your own website for common security misconfigurations (Vulpfest Lab).")
    parser.add_argument("url", help="website to scan, e.g. example.com or https://example.com")
    parser.add_argument("--json", action="store_true", help="print the full result as JSON")
    parser.add_argument("--out", metavar="FILE", help="also save the full result as JSON to FILE")
    args = parser.parse_args()

    print("Reminder: scan only websites you own or are authorized to test.", file=sys.stderr)
    result = run_full_scan(args.url)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result.get("valid") else 2

    print(f"\nTarget : {result.get('target')}")
    print(f"Scanned: {result.get('scanned_at')}")
    if not result.get("valid"):
        print(f"Status : could not scan reliably - {result.get('invalid_reason', 'unknown reason')}")
    info = result.get("score_info", {})
    print(f"Grade  : {info.get('grade', '-')}  (score {info.get('score', '-')}/100)\n")
    findings = sorted(info.get("findings", []), key=lambda f: LEVEL_ORDER.get(pick(f, "level", "severity", "tingkat"), 9))
    for i, f in enumerate(findings, 1):
        level = pick(f, "level", "severity", "tingkat") or "Info"
        print(f"{i:>2}. [{level}] {pick(f, 'finding', 'text', 'temuan')}")
        rec = pick(f, "recommendation", "rec", "rekomendasi")
        if rec:
            print(f"    -> {rec}")
    if args.out:
        print(f"\nFull result saved to {args.out}")
    return 0 if result.get("valid") else 2


if __name__ == "__main__":
    sys.exit(main())
