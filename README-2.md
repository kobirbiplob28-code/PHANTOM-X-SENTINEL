# PHANTOM-X Web Assessment Toolkit

Combined recon + XSS + SQLi + brute-force-lockout tester, with a report
generator that outputs a dev-ready Markdown report (finding + impact +
exact fix code).

## ⚠️ Authorization & scope

- Every command requires `--i-have-permission` or it refuses to run.
- The `bruteforce` command only ever tests **one username you provide**.
  Use your own test account — never a real customer's. Its purpose is to
  check whether lockout/rate-limiting exists, not to crack a password.
- You said you don't have code access — that's exactly what this is built
  for: every HIGH/MED finding comes with a **fix snippet for the dev
  team**, not a promise that this tool changes anything on the live site.

## Setup

**Termux:**
```bash
pkg install python -y
pip install requests beautifulsoup4
```

**Linux/Mac/other:**
```bash
pip install requests beautifulsoup4 --break-system-packages
```

All four files (`phantom.py`, `engine.py`, `bruteforce.py`, `report.py`)
must stay in the same folder — `phantom.py` imports the others directly.

## Usage

### Full scan + report (recommended starting point)
```bash
python3 phantom.py full "https://mrkitchenadviser.com/search?q=test" --i-have-permission
```
Generates `./phantom_reports/phantom_report.md` — a ready-to-send report,
grouped by severity, each finding with a fix snippet.

### Individual checks
```bash
python3 phantom.py recon https://mrkitchenadviser.com/ --i-have-permission
python3 phantom.py xss "https://mrkitchenadviser.com/search?q=test" --i-have-permission
python3 phantom.py sqli "https://mrkitchenadviser.com/search?q=test" --i-have-permission
```

### Brute-force / lockout test
You need the login page URL and the exact `name=` attributes of the
username and password `<input>` fields (view page source, or check the
Form Discovery output from `recon`).

```bash
python3 phantom.py bruteforce https://mrkitchenadviser.com/login \
  --i-have-permission \
  --username your_test_account_email \
  --user-field email \
  --pass-field password \
  --delay 2
```
It sends 10 intentionally wrong passwords, 2 seconds apart, and stops the
moment it sees a lockout/CAPTCHA/rate-limit response — or reports that
none was seen after all 10.

## What "boolean-blind" and "time-blind" SQLi mean (new in this version)

Your earlier scan only caught **error-based** SQLi (DB error message shows
up in the response). This version adds two more detection methods used
in real assessments:

- **Boolean-blind**: sends a TRUE condition and a FALSE condition, compares
  response size/content. A difference suggests the query result differs
  based on injected logic — even with no visible error.
- **Time-blind**: sends a payload that makes the DB sleep for 4 seconds if
  injectable. A matching delay in the response = strong signal.

Both are flagged MED (needs manual confirmation) or HIGH — false positives
are possible from network jitter, so verify manually before reporting as
confirmed.

## Next steps once you have the report

1. Read through `phantom_report.md`, sort HIGH items first
2. Hand it to the dev team / include in your deliverable to the company
3. Once real fixes go in, re-run `full` again to confirm they're closed
   — this "before/after" comparison is a strong thing to include in a
   final report
