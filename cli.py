"""Cyber Web Scanner from the command line.

Examples:
  python cli.py example.com                   # surface + deep web checks
  python cli.py example.com --surface-only    # quick surface checks only
  python cli.py --repo .                      # check a local project folder
  python cli.py example.com --repo .          # both, in one report
  python cli.py --repo . --fail-on critical   # for CI: exit code 3 on critical findings
  python cli.py example.com --json --out report.json
"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone

import json as _json
import manual_review
import repo_scan
import auth_scan
from scanner import calculate_security_score, run_full_scan

LEVEL_ORDER = {"Kritis": 0, "Tinggi": 1, "Menengah": 2, "Rendah": 3}
LEVEL_PREFIX = re.compile(r"^\s*Risiko\s+(Kritis|Tinggi|Menengah|Rendah)\s*:\s*", re.I)
FAIL_ON = {"critical": {"critical"}, "high": {"critical", "high"}}


def pick(d, *keys):
    for k in keys:
        if d.get(k):
            return d[k]
    return ""


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
    parser = argparse.ArgumentParser(description="Check your own website and project for common security problems (Vulpfest Lab).")
    parser.add_argument("url", nargs="?", help="website to scan, e.g. example.com or https://example.com")
    parser.add_argument("--json", action="store_true", help="print the full result as JSON")
    parser.add_argument("--out", metavar="FILE", help="also save the full result as JSON to FILE")
    parser.add_argument("--surface-only", action="store_true", help="skip the deep web checks (JavaScript, exposed files, DNS and email)")
    parser.add_argument("--repo", metavar="PATH", help="also check a local project folder (dependencies, secrets, git history, CI/CD, Docker)")
    parser.add_argument("--offline", action="store_true", help="repository check without internet (no OSV.dev or registry lookups)")
    parser.add_argument("--no-history", action="store_true", help="repository check without reading the git history")
    parser.add_argument("--fail-on", choices=sorted(FAIL_ON), help="exit with code 3 when a finding at this level or higher is found")
    parser.add_argument("--senior", action="store_true", help="show finding ID, category, track and confidence")
    parser.add_argument("--checklist", action="store_true", help="print the manual review checklist (Markdown)")
    parser.add_argument("--auth", metavar="FILE", help="authenticated checks (terminal only) on your own site; see auth.example.json")
    parser.add_argument("--yes", action="store_true", help="skip the confirmation prompt for authenticated checks")
    args = parser.parse_args()
    if args.checklist:
        print(manual_review.to_markdown())
        if not args.url and not args.repo:
            return 0
    if not args.url and not args.repo:
        parser.error("give a website, --repo PATH, or both")

    if args.url:
        print("Reminder: scan only websites you own or are authorized to test.", file=sys.stderr)
        result = run_full_scan(args.url, modes=("surface",) if args.surface_only else ("surface", "deep_web"))
    else:
        result = {"target": None, "valid": True, "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}

    if args.repo:
        print(f"Checking repository {args.repo} ...", file=sys.stderr)
        repo = repo_scan.run(args.repo, online=not args.offline, history=not args.no_history)
        result["repo"] = repo
        if repo.get("error"):
            print(f"Repository: {repo['error']}", file=sys.stderr)
        elif args.url:
            if result.get("valid"):
                result["coverage_modes"] = list(result.get("coverage_modes", ["surface"])) + ["repo"]
                result["score_info"] = calculate_security_score(result)
        else:
            result["target"] = "repo: " + repo["path"]
            result["score_info"] = repo_scan.score(repo)
        if not args.url and repo.get("error"):
            result["valid"] = False
            result["score_info"] = {"score": 0, "grade": "N/A", "findings": [{"finding": repo["error"], "recommendation": "Check the folder path."}]}

    if args.auth and args.url:
        from urllib.parse import urlparse
        host = urlparse(result.get("evidence", {}).get("final_url") or ("https://" + args.url)).hostname
        try:
            cfg = auth_scan.AuthConfig(_json.load(open(args.auth, encoding="utf-8")))
        except (OSError, ValueError) as e:
            print(f"Could not read {args.auth}: {e}", file=sys.stderr)
            return 2
        if not cfg.ok:
            print("The auth file needs at least one test account.", file=sys.stderr)
            return 2
        token, how = auth_scan.verify_ownership(host)
        ok, _method = auth_scan.confirm_ownership(host, token)
        if not ok:
            print("\nAuthenticated checks need proof that you own this site. Add ONE of these, then run again:", file=sys.stderr)
            print("  - file: " + how["file"], file=sys.stderr)
            print("  - DNS : " + how["dns"], file=sys.stderr)
            return 2
        if not args.yes:
            print("\nAuthenticated checks will send a small number of real requests to " + str(host) + ".", file=sys.stderr)
            if input("Type 'ya' to continue: ").strip().lower() not in ("ya", "yes"):
                print("Cancelled.", file=sys.stderr)
                return 0
        result["auth"] = auth_scan.run(cfg)
        if result.get("valid"):
            result["coverage_modes"] = list(dict.fromkeys(list(result.get("coverage_modes", ["surface"])) + ["auth"]))
            result["score_info"] = calculate_security_score(result)
    elif args.auth:
        print("--auth needs a website argument.", file=sys.stderr)
        return 2

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
    info = result.get("score_info", {})
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"\nTarget : {result.get('target')}")
        print(f"Scanned: {result.get('scanned_at')}")
        if not result.get("valid"):
            print(f"Status : could not scan reliably - {result.get('invalid_reason', 'see below')}")
        print(f"Grade  : {info.get('grade', '-')}  (score {info.get('score', '-')}/100)")
        cov = info.get("coverage") or {}
        if cov.get("percent"):
            print(f"Cover  : {cov.get('label')} ({cov.get('percent')}%); not checked yet: {', '.join(cov.get('not_checked', [])) or '-'}")
        subs, labels = info.get("subscores") or {}, info.get("category_labels") or {}
        if subs:
            print("Scores : " + " · ".join(f"{labels.get(k, k)} {v if v is not None else '-'}" for k, v in subs.items()))
        if info.get("grade_capped"):
            print("Note   : grade capped because of critical findings")
        repo = result.get("repo") or {}
        if repo and not repo.get("error"):
            hist = "not a git repository" if not repo.get("git") else ("partial" if repo.get("history_partial") else "yes")
            print(f"Repo   : {repo.get('files_scanned')} files, {repo['deps']['checked']} packages checked"
                  f"{' (offline: no OSV/registry)' if not repo.get('online') else ''}, git history: {hist}")
            for note in repo.get("notes", []):
                print(f"Note   : {note}")
        print()
        items = sorted((split_level(f) for f in info.get("findings", [])), key=lambda x: LEVEL_ORDER.get(x[0], 9))
        for i, (level, text, f) in enumerate(items, 1):
            print(f"{i:>2}. [{level}] {text}")
            if args.senior and f.get("id"):
                print(f"    [{f.get('id')} · {f.get('category', '-')} · track {f.get('track', '-')} · confidence {f.get('confidence', '-')}]")
            rec = pick(f, "recommendation", "rec", "rekomendasi")
            if rec:
                print(f"    -> {rec}")
        if args.out:
            print(f"\nFull result saved to {args.out}")

    if args.fail_on and any(f.get("severity") in FAIL_ON[args.fail_on] for f in info.get("findings", [])):
        return 3
    return 0 if result.get("valid") else 2


if __name__ == "__main__":
    sys.exit(main())
