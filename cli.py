"""Cyber Web Scanner from the command line.

Examples:
  python cli.py example.com
  python cli.py https://example.com --json
  python cli.py example.com --out report.json
"""
import argparse
import json
import re
import sys

from scanner import run_full_scan

LEVEL_ORDER = {"Kritis": 0, "Tinggi": 1, "Menengah": 2, "Rendah": 3}


def pick(d, *keys):
    for k in keys:
        if d.get(k):
            return d[k]
    return ""


LEVEL_PREFIX = re.compile(r"^\s*Risiko\s+(Kritis|Tinggi|Menengah|Rendah)\s*:\s*", re.I)


def split_level(f):
    """Level may be a separate field or written at the start of the finding ("Risiko Menengah: ...")."""
    text = pick(f, "finding", "text", "temuan")
    level = pick(f, "level", "severity", "tingkat")
    m = LEVEL_PREFIX.match(text)
    if m:
        level = level or m.group(1).capitalize()
        text = text[m.end():]
    return level or "Info", text, f


def main():
    parser = argparse.ArgumentParser(description="Check your own website for common security misconfigurations (Vulpfest Lab).")
    parser.add_argument("url", help="website to scan, e.g. example.com or https://example.com")
    parser.add_argument("--json", action="store_true", help="print the full result as JSON")
    parser.add_argument("--out", metavar="FILE", help="also save the full result as JSON to FILE")
    parser.add_argument("--surface-only", action="store_true", help="skip the deep web checks (JavaScript, exposed files and endpoints)")
    args = parser.parse_args()

    print("Reminder: scan only websites you own or are authorized to test.", file=sys.stderr)
    result = run_full_scan(args.url, modes=("surface",) if args.surface_only else ("surface", "deep_web"))

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
    print(f"Grade  : {info.get('grade', '-')}  (score {info.get('score', '-')}/100)")
    cov = info.get("coverage") or {}
    if cov.get("percent"):
        print(f"Cover  : {cov.get('label')} ({cov.get('percent')}%); not checked yet: {', '.join(cov.get('not_checked', [])) or '-'}")
    if info.get("grade_capped"):
        print("Note   : grade capped because of critical findings")
    print()
    findings = [split_level(f) for f in info.get("findings", [])]
    findings.sort(key=lambda x: LEVEL_ORDER.get(x[0], 9))
    for i, (level, text, f) in enumerate(findings, 1):
        print(f"{i:>2}. [{level}] {text}")
        rec = pick(f, "recommendation", "rec", "rekomendasi")
        if rec:
            print(f"    -> {rec}")
    if args.out:
        print(f"\nFull result saved to {args.out}")
    return 0 if result.get("valid") else 2


if __name__ == "__main__":
    sys.exit(main())
