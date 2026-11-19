<p align="center">
  <a href="https://lab.vulpfest.com">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://cdn.jsdelivr.net/npm/@vulpfest/icons@0.3/svg/vulpfest-logo-night.svg" />
      <source media="(prefers-color-scheme: light)" srcset="https://cdn.jsdelivr.net/npm/@vulpfest/icons@0.3/svg/vulpfest-logo-day.svg" />
      <img src="https://cdn.jsdelivr.net/npm/@vulpfest/icons@0.3/svg/vulpfest-logo-night.svg" height="44" alt="Vulpfest Lab" />
    </picture>
  </a>
</p>

# Cyber Web Scanner

Check your own website for common security misconfigurations.

**Try it online:** [lab.vulpfest.com/scanner](https://lab.vulpfest.com/scanner), part of [Vulpfest Lab](https://lab.vulpfest.com), free and open-source tools from Vulpfest.

## What it does

Cyber Web Scanner checks **your own** website (and, from the terminal, your own project) for common security problems. Every finding comes with evidence and a fix you can copy.

| Mode | Where | What it checks |
|---|---|---|
| **Surface** | web and terminal | security headers, SSL/TLS, HTTPS redirect, CORS, cookies, exposed `.git` and `.env`, DNS CAA, SPF and DMARC, common subdomain takeover |
| **Deep web** | web and terminal | secrets in JavaScript (including Supabase `service_role`, Midtrans and Xendit keys), backups and config files, debug pages, ops endpoints, source maps, outdated JavaScript libraries, API docs, GraphQL introspection, SRI, CT-log subdomains, SPF/DMARC/DKIM/MTA-STS |
| **Repository** | terminal only (`--repo`) | vulnerable dependencies (OSV.dev), AI-invented packages, secrets in code and git history, committed `.env`, risky GitHub Actions, Dockerfile, secrets with public prefixes such as `NEXT_PUBLIC_` |

Reports show a **grade with coverage** (for example "A, coverage 65%"), a grade cap when critical findings exist, scores per category, beginner and senior views, and a manual review checklist for areas that cannot be tested safely from outside. The scanner refuses private and internal addresses (SSRF protection) and never sends exploit payloads.

## Run it yourself

```bash
git clone https://github.com/FebriOsht/Cyber-Web-Scanner.git
cd Cyber-Web-Scanner
pip install -r requirements.txt
gunicorn app:app
# in another terminal:
celery -A tasks worker -l info
```

The web app runs with Gunicorn and background scans run with Celery and Redis (see `Procfile`).

### Configuration

Set these environment variables (or Streamlit secrets) before running:

- `PORT`
- `REDIS_URL`

## Works on Windows, macOS and Linux

Requires Python 3.10 or newer. A virtual environment keeps the packages separate from the rest of your system.

**Windows (PowerShell)**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**macOS and Linux (bash or zsh)**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If PowerShell blocks the activation script, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once and try again.

On Windows, `gunicorn` and `celery` are not supported. Use the command line tool (`python cli.py example.com`, see below), or start the web app with Flask's built-in server: `flask --app app run`.

## Command line

```bash
python cli.py example.com                   # surface + deep web checks
python cli.py example.com --surface-only    # quick surface checks only
python cli.py --repo .                      # check a local project folder
python cli.py example.com --repo .          # both, in one report (coverage 85%)
python cli.py --repo . --offline            # no internet: skip OSV.dev and registry lookups
python cli.py example.com --senior          # show finding ID, category, track and confidence
python cli.py --checklist > review.md       # manual review checklist
python cli.py example.com --json --out report.json
```

The command line only needs `requests` and `beautifulsoup4` (`pip install requests beautifulsoup4`); Redis and Celery are not needed.

Exit codes: `0` finished, `2` could not scan reliably, `3` findings at or above the `--fail-on` level.

### In CI (GitHub Actions)

```yaml
- run: pip install requests beautifulsoup4
- run: python cli.py --repo . --fail-on critical
```

## Responsible use

Scan only websites you own or are authorized to test. Scanning systems without permission may be illegal in your country, including under Indonesia's Electronic Information and Transactions Law (UU ITE).

The software is provided as is, without warranty. You are responsible for how you use it and for any data you collect.

## Security

Found a security issue? Please see [SECURITY.md](SECURITY.md).

## Support this project

This tool is free. If it saves you time, you can support its development:

- [Saweria](https://saweria.co/FebriOsht): QRIS, e-wallet and bank transfer, for supporters in Indonesia
- [PayPal](https://paypal.me/FebriOsht)
- Crypto (USDT BEP20, USDT TRC20, Bitcoin): see the [addresses and QR codes](https://github.com/FebriOsht#support)

Starring the repository helps too. ⭐

## License

MIT © 2026 Febri Osht (Vulpfest). See [LICENSE](LICENSE).