"""
phantom_toolkit/bruteforce.py
Login rate-limiting / account-lockout tester.

IMPORTANT — SCOPE:
This tool tests ONE username only (the one you provide — use your own
test account, never a real customer's). It does NOT attempt to guess a
real password for account takeover. Its purpose is to answer a single
question for your report: "does this login form have rate-limiting or
account lockout protection?"

It sends a small number of INTENTIONALLY WRONG passwords with a delay
between attempts, and reports at which attempt (if any) the server
started blocking / CAPTCHA-gating / rate-limiting the requests.
"""

import time
import requests

from engine import Finding

requests.packages.urllib3.disable_warnings()

TIMEOUT = 8

# Small, non-exhaustive set — enough to observe lockout behavior,
# not a real cracking wordlist.
SAFE_TEST_PASSWORDS = [
    "wrongpass1", "wrongpass2", "wrongpass3", "wrongpass4", "wrongpass5",
    "wrongpass6", "wrongpass7", "wrongpass8", "wrongpass9", "wrongpass10",
]

LOCKOUT_SIGNS = [
    "too many attempts", "account locked", "temporarily locked",
    "try again later", "captcha", "blocked", "rate limit", "too many requests",
]


def test_lockout(login_url, username, user_field, pass_field, delay=2.0, extra_fields=None):
    """
    Sends SAFE_TEST_PASSWORDS against login_url for `username` only.
    Returns (list_of_Findings, log_of_attempts).
    """
    findings = []
    log = []
    session = requests.Session()

    base_data = extra_fields.copy() if extra_fields else {}

    for i, pwd in enumerate(SAFE_TEST_PASSWORDS, start=1):
        data = base_data.copy()
        data[user_field] = username
        data[pass_field] = pwd

        try:
            r = session.post(login_url, data=data, timeout=TIMEOUT, verify=False, allow_redirects=True)
        except requests.RequestException as e:
            log.append((i, pwd, f"ERROR: {e}"))
            break

        status = r.status_code
        body_lower = r.text.lower()
        lockout_hit = any(sign in body_lower for sign in LOCKOUT_SIGNS) or status in (429, 403)

        log.append((i, pwd, f"HTTP {status}" + (" — lockout/rate-limit signal detected" if lockout_hit else "")))

        if lockout_hit:
            findings.append(Finding(
                "BruteForce", "OK", f"Lockout/rate-limiting triggered at attempt {i}",
                f"Server responded with signs of blocking after {i} failed attempts (HTTP {status}).",
                "Good — protection appears to be in place. Confirm the lockout duration and whether "
                "it applies per-username, per-IP, or both."
            ))
            return findings, log

        time.sleep(delay)

    # Completed all attempts with no lockout signal
    findings.append(Finding(
        "BruteForce", "HIGH", "No lockout/rate-limiting detected",
        f"Sent {len(SAFE_TEST_PASSWORDS)} failed login attempts for '{username}' with no blocking, "
        "CAPTCHA, or rate-limit response observed.",
        "Implement account lockout after N failed attempts (e.g. 5), with either a time-based "
        "cooldown or CAPTCHA challenge. Also consider IP-based rate limiting at the web server or "
        "WAF layer (e.g. fail2ban, or PHP-level: track failed attempts in DB/cache keyed by "
        "username+IP, block for X minutes after threshold). Do not lock out solely on IP if the "
        "site has legitimate shared-IP users (offices, NAT), to avoid denial-of-service on real users."
    ))
    return findings, log
