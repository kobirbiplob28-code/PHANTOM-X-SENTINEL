#!/usr/bin/env python3
"""
phantom.py — PHANTOM-X Web Assessment Toolkit
Author: Ariyan

USE ONLY ON SYSTEMS YOU ARE AUTHORIZED TO TEST (written agreement).

Subcommands:
  recon        Headers, SSL, sensitive paths, open ports, form discovery
  xss          Deep reflected-XSS testing on a URL with query params
  sqli         Deep SQLi testing (error-based + boolean-blind + time-blind)
  bruteforce   Login lockout/rate-limit tester (single username only)
  full         Run recon + xss + sqli, then generate a Markdown report

Examples:
  python3 phantom.py full https://target.com --i-have-permission
  python3 phantom.py full "https://target.com/search?q=x" --i-have-permission
  python3 phantom.py bruteforce https://target.com/login --i-have-permission \\
      --username myTestAccount --user-field email --pass-field password
"""

import argparse
import sys
import os

import engine
import bruteforce as bf
import report as rpt


class C:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"; BOLD = "\033[1m"; END = "\033[0m"


def section(title):
    print(f"\n{C.BOLD}{C.B}== {title} =={C.END}")


def print_finding(f):
    color = {"HIGH": C.R, "MED": C.Y, "LOW": C.Y, "OK": C.G, "INFO": C.B}.get(f.severity, C.END)
    print(f"  [{color}{f.severity}{C.END}] {f.title}")
    if f.detail:
        print(f"        {f.detail}")


def require_permission(args):
    if not getattr(args, "i_have_permission", False):
        print(f"{C.R}{C.BOLD}Refusing to run.{C.END}")
        print("Pass --i-have-permission to confirm you are authorized (written agreement) "
              "to test this target.")
        sys.exit(1)


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def run_recon(url):
    all_findings = []
    section("Security Headers & Server Info")
    f, _ = engine.scan_headers(url)
    all_findings += f
    for x in f:
        print_finding(x)

    section("SSL/TLS Certificate")
    f = engine.check_ssl(url)
    all_findings += f
    for x in f:
        print_finding(x)

    section("Sensitive File / Path Exposure")
    f = engine.check_sensitive_paths(url)
    all_findings += f
    for x in f:
        print_finding(x)

    section("Common Open Ports")
    f = engine.scan_ports(url)
    all_findings += f
    for x in f:
        print_finding(x)

    section("Form / Input Discovery")
    f, forms = engine.discover_forms(url)
    all_findings += f
    for x in f:
        print_finding(x)

    return all_findings


def run_xss(url):
    section("Reflected XSS Deep Test")
    f = engine.test_xss(url)
    for x in f:
        print_finding(x)
    return f


def run_sqli(url):
    section("SQL Injection Deep Test (error / boolean-blind / time-blind)")
    f = engine.test_sqli(url)
    for x in f:
        print_finding(x)
    return f


def cmd_recon(args):
    require_permission(args)
    url = normalize_url(args.url)
    print(f"{C.BOLD}Target: {url}{C.END}")
    run_recon(url)


def cmd_xss(args):
    require_permission(args)
    url = normalize_url(args.url)
    print(f"{C.BOLD}Target: {url}{C.END}")
    run_xss(url)


def cmd_sqli(args):
    require_permission(args)
    url = normalize_url(args.url)
    print(f"{C.BOLD}Target: {url}{C.END}")
    run_sqli(url)


def cmd_bruteforce(args):
    require_permission(args)
    url = normalize_url(args.login_url)
    print(f"{C.BOLD}Login target: {url}{C.END}")
    print(f"Testing lockout behavior for username: {args.username}")
    print(f"{C.Y}Sending intentionally wrong passwords with {args.delay}s delay between attempts...{C.END}")
    section("Brute-force / Lockout Test")
    findings, log = bf.test_lockout(
        url, args.username, args.user_field, args.pass_field,
        delay=args.delay,
    )
    for attempt, pwd, result in log:
        print(f"  attempt {attempt}: {result}")
    for f in findings:
        print_finding(f)


def cmd_full(args):
    require_permission(args)
    url = normalize_url(args.url)
    print(f"{C.BOLD}Target: {url}{C.END}")

    all_findings = []
    all_findings += run_recon(url)
    all_findings += run_xss(url)
    all_findings += run_sqli(url)

    os.makedirs(args.output_dir, exist_ok=True)
    out_path = os.path.join(args.output_dir, "phantom_report.md")
    path, score = rpt.generate_report(url, all_findings, out_path)

    section("Report Generated")
    print(f"  Risk score: {score}")
    print(f"  Report saved to: {path}")


def main():
    parser = argparse.ArgumentParser(description="PHANTOM-X Web Assessment Toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    p_recon = sub.add_parser("recon", help="Headers, SSL, paths, ports, forms")
    p_recon.add_argument("url")
    p_recon.add_argument("--i-have-permission", action="store_true")
    p_recon.set_defaults(func=cmd_recon)

    p_xss = sub.add_parser("xss", help="Deep reflected XSS test")
    p_xss.add_argument("url")
    p_xss.add_argument("--i-have-permission", action="store_true")
    p_xss.set_defaults(func=cmd_xss)

    p_sqli = sub.add_parser("sqli", help="Deep SQLi test")
    p_sqli.add_argument("url")
    p_sqli.add_argument("--i-have-permission", action="store_true")
    p_sqli.set_defaults(func=cmd_sqli)

    p_bf = sub.add_parser("bruteforce", help="Login lockout/rate-limit tester (single username)")
    p_bf.add_argument("login_url")
    p_bf.add_argument("--i-have-permission", action="store_true")
    p_bf.add_argument("--username", required=True, help="YOUR OWN test account username/email only")
    p_bf.add_argument("--user-field", required=True, help="Form field name for username, e.g. 'email'")
    p_bf.add_argument("--pass-field", required=True, help="Form field name for password, e.g. 'password'")
    p_bf.add_argument("--delay", type=float, default=2.0, help="Seconds between attempts (default 2.0)")
    p_bf.set_defaults(func=cmd_bruteforce)

    p_full = sub.add_parser("full", help="Run recon + xss + sqli, generate report")
    p_full.add_argument("url")
    p_full.add_argument("--i-have-permission", action="store_true")
    p_full.add_argument("--output-dir", default="./phantom_reports")
    p_full.set_defaults(func=cmd_full)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
