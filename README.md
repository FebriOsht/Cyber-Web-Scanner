# Cyber Web Scanner

Check your own website for common security misconfigurations.

**Try it online:** [lab.vulpfest.com/scanner](https://lab.vulpfest.com/scanner), part of [Vulpfest Lab](https://lab.vulpfest.com), free and open-source tools from Vulpfest.

## What it does

- Passive checks based on real server responses: security headers, SSL, exposed sensitive files such as a .git folder, CORS and email domain settings.
- A risk grade from A to F, with evidence for every finding and suggestions on what to fix first.
- Scan history and a downloadable report.

## Run it yourself

````bash
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

## Command line

Scan a website straight from your terminal, without the web app, Redis or Celery. Only `requests` and `beautifulsoup4` are needed.

```bash
pip install requests beautifulsoup4
python cli.py example.com                     # readable summary
python cli.py https://example.com --json      # full result as JSON
python cli.py example.com --out report.json   # summary, and save the full result
```

The exit code is `0` when the scan completed and `2` when the site could not be scanned reliably, so it can be used in scripts and CI.

## Responsible use

Scan only websites you own or are authorized to test. Scanning systems without permission may be illegal in your country, including under Indonesia's Electronic Information and Transactions Law (UU ITE).

The software is provided as is, without warranty. You are responsible for how you use it and for any data you collect.

## Security

Found a security issue? Please see [SECURITY.md](SECURITY.md).

## License

MIT © 2026 Febri Osht (Vulpfest). See [LICENSE](LICENSE).