# Client Deployment Notes

## Official Client Command

Tell the client:

```text
Go inside your project/repository folder and run this command.
```

```bash
SCAN_ID="SCAN_ID_FROM_DASHBOARD" bash <(curl -fsSL SCANNER_URL/run.sh)
```

For our current Railway deployment:

```bash
SCAN_ID="SCAN_ID_FROM_DASHBOARD" bash <(curl -fsSL https://sh-security-production.up.railway.app/run.sh)
```

Only one value changes per client:

```text
scan id
```

The scanner runs in the current folder, creates a dated JSON report, uploads it when the scan id is valid, and removes temporary runner files.

## Scanner Versions

The default command uses `/run.sh`.

The backend decides which scanner `/run.sh` serves with:

```text
SCAN_DEFAULT_VERSION
```

If the variable is not set, `/run.sh` serves v1.

Explicit versions are available for testing and rollback:

```bash
SCAN_ID="scan id" bash <(curl -fsSL https://sh-security-production.up.railway.app/v1/run.sh)
SCAN_ID="scan id" bash <(curl -fsSL https://sh-security-production.up.railway.app/v2/run.sh)
SCAN_ID="scan id" bash <(curl -fsSL https://sh-security-production.up.railway.app/v3/run.sh)
```

Use v3 for the broadest static coverage. Keep v1/v2 available as fallback channels.

## Basic Client Usage

Client SSHs into their server or CI runner and runs:

```bash
./scan.sh
```

The scanner runs inside the current directory.

## With Your Hosted Server

If you deploy `server.py` on your own server:

```bash
BASE_URL="https://scanner.example.com" SCAN_ID="scan_id_from_dashboard" ./scan.sh
```

This allows:

```text
rule download
optional report upload
```

## Without Upload

If the client does not want to upload reports:

```bash
./scan.sh
```

or:

```bash
./scan.sh --offline
```

The report stays on their server.

## Output

The client receives:

```text
security-report-YYYYMMDD-HHMMSS.json
.scan-sh/
```

If the client does not want to keep raw scanner output, run:

```bash
BASE_URL="https://scanner.example.com" SCAN_ID="scan_id_from_dashboard" ./scan.sh --clean
```

Then only the final report remains.

## Minimum Requirements

Recommended:

```text
bash
python 3
curl or wget
semgrep
```

Optional but valuable:

```text
gitleaks
osv-scanner
```

## Linux Client Servers

Linux is the best target environment.

On Linux, `scan.sh` can automatically download/cache:

```text
gitleaks
osv-scanner
```

Git Bash on Windows is useful for local testing, but real client deployments should prefer Linux SSH servers or CI runners.

Most root/VPS hosting environments such as CloudPanel, Hostinger VPS, cPanel terminal, Ubuntu, Debian, AlmaLinux, and CentOS provide Linux with `bash`. If `curl` is missing, the hosted runner can download with `wget` or Python 3 instead. If `bash` itself is missing, the scanner cannot run because `scan.sh` is a Bash script; install Bash or run it from a normal Linux/CI environment.

## Simple One-Command Client Flow

This is the easiest client workflow. The client only SSHs into the server, goes to the website/app folder, and runs one command.

CloudPanel example path:

```bash
cd /home/<site-user>/htdocs/<domain>
SCAN_ID="scan_id_from_dashboard" bash <(curl -fsSL https://sh-security-production.up.railway.app/run.sh)
```

For example:

```bash
cd /home/siteuser/htdocs/example.com
SCAN_ID="scan_id_from_dashboard" bash <(curl -fsSL https://sh-security-production.up.railway.app/run.sh)
```

The hosted `run.sh` script downloads the scanner files into `.scan-sh-runner/`, runs the scan, writes the dated JSON report, uploads it if a scan id is present, and removes `.scan-sh-runner/` at the end.

The client does not need to clone your GitHub repository. They only need `bash`, `curl`, and `python3`.

Semgrep is optional but improves SAST coverage. The hosted runner tries to install it when missing:

```text
normal Python install      python -m pip install --user semgrep
virtualenv/Railway style   python -m pip install semgrep
```

If Semgrep cannot be installed, the scanner still runs custom checks, gitleaks, and OSV where available. v3 has expanded custom checks so useful findings still appear even when Semgrep is skipped.

Use this when you want high/critical findings to fail CI:

```bash
SCAN_ID="scan_id_from_dashboard" SCAN_ARGS="--fail-on high --clean" bash <(curl -fsSL https://sh-security-production.up.railway.app/run.sh)
```

Use this when the client wants the report to stay only on their server:

```bash
bash <(curl -fsSL https://sh-security-production.up.railway.app/run.sh)
```
