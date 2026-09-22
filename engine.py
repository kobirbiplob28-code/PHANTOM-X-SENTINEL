"""
phantom_toolkit/engine.py
Core scanning logic shared by the CLI. Part of Ariyan's PHANTOM-X toolkit.

AUTHORIZED TESTING ONLY. See README.md.
"""

import socket
import ssl
import time
import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()

TIMEOUT = 6


# ---------- Finding data structure ----------

class Finding:
    def __init__(self, category, severity, title, detail, fix=""):
        self.category = category      # e.g. "Headers", "XSS", "SQLi"
        self.severity = severity      # HIGH, MED, LOW, INFO, OK
        self.title = title
        self.detail = detail
        self.fix = fix                # dev-facing remediation text/code

    def to_dict(self):
        return {
            "category": self.category, "severity": self.severity,
            "title": self.title, "detail": self.detail, "fix": self.fix,
        }


SEV_WEIGHT = {"HIGH": 5, "MED": 2, "LOW": 1, "INFO": 0, "OK": 0}


# ---------- Recon ----------

EXPECTED_HEADERS = {
    "content-security-policy": ("Mitigates XSS / data injection by whitelisting script sources.",
        "Add to server config (nginx example):\n"
        '  add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'";\n'
        "Or in PHP (top of page):\n"
        '  header("Content-Security-Policy: default-src \'self\'");'),
    "strict-transport-security": ("Forces HTTPS, prevents SSL-stripping/downgrade attacks.",
        "nginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\";\n"
        'PHP: header("Strict-Transport-Security: max-age=31536000; includeSubDomains");'),
    "x-frame-options": ("Prevents clickjacking (site embedded in a hidden iframe).",
        'PHP: header("X-Frame-Options: SAMEORIGIN");'),
    "x-content-type-options": ("Prevents MIME-sniffing based attacks.",
        'PHP: header("X-Content-Type-Options: nosniff");'),
    "referrer-policy": ("Controls how much referrer info leaks to other sites.",
        'PHP: header("Referrer-Policy: strict-origin-when-cross-origin");'),
    "permissions-policy": ("Restricts which browser features (camera, mic, geolocation) the page can use.",
        'PHP: header("Permissions-Policy: geolocation=(), microphone=(), camera=()");'),
}

SENSITIVE_PATHS = [
    ".git/HEAD", ".env", ".env.local", "wp-config.php.bak", "config.php.bak",
    "backup.zip", "backup.sql", "database.sql", ".DS_Store",
    "admin/", "administrator/", "phpinfo.php", ".htaccess",
    "server-status", "web.config", ".well-known/security.txt",
]

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]

RISKY_PORTS = {
    21: "FTP — plaintext credentials, prefer SFTP/FTPS",
    23: "Telnet — plaintext, should never be exposed",
    3306: "MySQL — database port should not be internet-facing",
    3389: "RDP — high-value target for brute force, restrict by IP/VPN",
    445: "SMB — frequent target for worms/lateral movement",
}


def scan_headers(url):
    findings = []
    meta = {}
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
    except requests.RequestException as e:
        findings.append(Finding("Connectivity", "HIGH", "Could not connect", str(e)))
        return findings, meta

    headers = {k.lower(): v for k, v in r.headers.items()}
    meta["status_code"] = r.status_code
    meta["final_url"] = r.url

    for h, (why, fix) in EXPECTED_HEADERS.items():
        if h in headers:
            findings.append(Finding("Headers", "OK", f"{h} present", ""))
        else:
            findings.append(Finding("Headers", "MED", f"Missing header: {h}", why, fix))

    if "server" in headers:
        findings.append(Finding("Recon", "LOW", "Server banner exposed",
                                 f"Server: {headers['server']}",
                                 "Suppress/rename banner in server config (e.g. server_tokens off; for nginx)."))
    if "x-powered-by" in headers:
        findings.append(Finding("Recon", "LOW", "X-Powered-By exposed",
                                 f"X-Powered-By: {headers['x-powered-by']}",
                                 "Disable in php.ini: expose_php = Off"))
        version = headers["x-powered-by"]
        if "php/7." in version.lower() or "php/5." in version.lower():
            findings.append(Finding("Recon", "HIGH", "Outdated / EOL PHP version",
                                     f"{version} — no security patches since end-of-life.",
                                     "Upgrade to a currently supported PHP version (8.1+). "
                                     "This is an infrastructure change, coordinate with hosting/dev team."))
    return findings, meta


def check_ssl(url):
    findings = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        findings.append(Finding("SSL", "HIGH", "No HTTPS", "Site not served over HTTPS.",
                                 "Obtain a TLS certificate (e.g. Let's Encrypt, free) and force HTTPS redirects."))
        return findings
    host, port = parsed.hostname, parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
                if days_left < 0:
                    findings.append(Finding("SSL", "HIGH", "Certificate expired", f"Expired {not_after.date()}",
                                             "Renew certificate immediately."))
                elif days_left < 14:
                    findings.append(Finding("SSL", "MED", "Certificate expiring soon",
                                             f"{days_left} days left ({not_after.date()})",
                                             "Renew certificate; consider auto-renewal (certbot)."))
                else:
                    findings.append(Finding("SSL", "OK", "Certificate valid",
                                             f"Expires {not_after.date()} ({days_left} days)"))
    except Exception as e:
        findings.append(Finding("SSL", "MED", "Certificate check failed", str(e)))
    return findings


def check_sensitive_paths(url):
    findings = []
    base = url if url.endswith("/") else url + "/"
    for path in SENSITIVE_PATHS:
        target = urljoin(base, path)
        try:
            r = requests.get(target, timeout=TIMEOUT, verify=False, allow_redirects=False)
            if r.status_code == 200 and len(r.content) > 0:
                findings.append(Finding("Exposure", "HIGH", f"Exposed path: {path}",
                                         f"{target} returned 200 OK and served content.",
                                         "Remove file from public web root, or block via server config "
                                         "(deny access rule for the path/pattern)."))
        except requests.RequestException:
            continue
    if not any(f.severity != "OK" for f in findings):
        findings.append(Finding("Exposure", "OK", "No exposed sensitive paths found", ""))
    return findings


def scan_ports(url):
    findings = []
    host = urlparse(url).hostname
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        findings.append(Finding("Ports", "HIGH", "DNS resolution failed", f"Could not resolve {host}"))
        return findings
    for port in COMMON_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.2)
        try:
            if s.connect_ex((ip, port)) == 0:
                if port in RISKY_PORTS:
                    findings.append(Finding("Ports", "MED", f"Port {port} open", RISKY_PORTS[port],
                                             "Firewall this port to trusted IPs only, or disable the service "
                                             "if not required."))
                else:
                    findings.append(Finding("Ports", "INFO", f"Port {port} open", "Expected for a web server."))
        except socket.error:
            pass
        finally:
            s.close()
    return findings


def discover_forms(url):
    findings = []
    forms_data = []
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False)
    except requests.RequestException as e:
        findings.append(Finding("Forms", "HIGH", "Could not fetch page", str(e)))
        return findings, forms_data
    soup = BeautifulSoup(r.text, "html.parser")
    for f in soup.find_all("form"):
        action = f.get("action") or "(self)"
        method = (f.get("method") or "GET").upper()
        inputs = [i.get("name") for i in f.find_all(["input", "textarea"]) if i.get("name")]
        forms_data.append({"action": action, "method": method, "fields": inputs})
        findings.append(Finding("Forms", "INFO", f"Form found: {action} [{method}]",
                                 f"Fields: {inputs}"))
    return findings, forms_data


# ---------- XSS deep test ----------

XSS_PAYLOADS = [
    ("<zzqx>test</zzqx>", "zzqx"),                     # raw tag reflection
    ('"><zzqx onmouseover=1>', "zzqx onmouseover"),    # attribute-breakout
    ("'><zzqx>", "zzqx"),                              # single-quote breakout
    ("<img src=x onerror=zzqxmark>", "onerror=zzqxmark"),
]


def test_xss(url):
    findings = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        findings.append(Finding("XSS", "INFO", "No query parameters to test",
                                 "Provide a URL with parameters, e.g. site.com/search?q=test"))
        return findings

    for param in qs:
        reflected_variants = []
        for payload, marker in XSS_PAYLOADS:
            test_qs = qs.copy()
            test_qs[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))
            try:
                r = requests.get(test_url, timeout=TIMEOUT, verify=False)
                if marker.lower() in r.text.lower():
                    reflected_variants.append(payload)
            except requests.RequestException:
                continue
        if reflected_variants:
            findings.append(Finding(
                "XSS", "HIGH", f"Reflected XSS in parameter '{param}'",
                f"{len(reflected_variants)} payload variant(s) reflected unescaped, e.g.: {reflected_variants[0]}",
                "Encode all user input before rendering into HTML. In PHP:\n"
                f'  echo htmlspecialchars($_GET[\'{param}\'], ENT_QUOTES, \'UTF-8\');\n'
                "Never echo raw $_GET/$_POST values into HTML, attributes, or <script> blocks. "
                "Add a Content-Security-Policy header as defense-in-depth."
            ))
        else:
            findings.append(Finding("XSS", "OK", f"Parameter '{param}' — no reflection detected", ""))
    return findings


# ---------- SQLi deep test (error-based + boolean-blind + time-based blind) ----------

SQL_ERROR_SIGNS = [
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated", "sqlstate", "pg_query()", "sqlite3.operationalerror",
    "ora-01756", "microsoft odbc", "mysql_fetch", "mysqli_",
]


def test_sqli(url):
    findings = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        findings.append(Finding("SQLi", "INFO", "No query parameters to test", ""))
        return findings

    for param in qs:
        base_val = qs[param][0]
        vulnerable = False

        # 1. Error-based
        for payload in ["'", "\"", "' OR '1'='1", "1' AND '1'='2"]:
            test_qs = qs.copy()
            test_qs[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))
            try:
                r = requests.get(test_url, timeout=TIMEOUT, verify=False)
                if any(sign in r.text.lower() for sign in SQL_ERROR_SIGNS):
                    findings.append(Finding(
                        "SQLi", "HIGH", f"Error-based SQL injection in '{param}'",
                        f"Payload {payload!r} triggered a database error message in the response.",
                        "Use parameterized queries / prepared statements — never concatenate "
                        "user input into SQL. PHP (PDO) example:\n"
                        '  $stmt = $pdo->prepare("SELECT * FROM items WHERE name = ?");\n'
                        f'  $stmt->execute([${param}]);\n'
                        "Also disable detailed DB error output in production (display_errors = Off)."
                    ))
                    vulnerable = True
                    break
            except requests.RequestException:
                continue

        # 2. Boolean-based blind (compare TRUE vs FALSE condition response)
        if not vulnerable:
            try:
                true_qs = qs.copy()
                true_qs[param] = [f"{base_val}' AND '1'='1"]
                false_qs = qs.copy()
                false_qs[param] = [f"{base_val}' AND '1'='2"]
                r_true = requests.get(urlunparse(parsed._replace(query=urlencode(true_qs, doseq=True))),
                                       timeout=TIMEOUT, verify=False)
                r_false = requests.get(urlunparse(parsed._replace(query=urlencode(false_qs, doseq=True))),
                                        timeout=TIMEOUT, verify=False)
                if len(r_true.text) != len(r_false.text):
                    findings.append(Finding(
                        "SQLi", "MED", f"Possible boolean-based blind SQLi in '{param}'",
                        "TRUE and FALSE injected conditions produced different response sizes "
                        f"({len(r_true.text)} vs {len(r_false.text)} bytes). Needs manual confirmation.",
                        "Same fix as error-based: use parameterized queries. Manually verify this "
                        "finding before reporting as confirmed (could be a false positive)."
                    ))
                    vulnerable = True
            except requests.RequestException:
                pass

        # 3. Time-based blind (only if nothing else found — slower)
        if not vulnerable:
            try:
                payload = f"{base_val}' AND SLEEP(4)-- -"
                test_qs = qs.copy()
                test_qs[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))
                start = time.time()
                requests.get(test_url, timeout=TIMEOUT + 6, verify=False)
                elapsed = time.time() - start
                if elapsed > 3.5:
                    findings.append(Finding(
                        "SQLi", "HIGH", f"Possible time-based blind SQLi in '{param}'",
                        f"SLEEP(4) payload caused a {elapsed:.1f}s response delay.",
                        "Same fix: parameterized queries. Confirm manually — network jitter can "
                        "occasionally cause false positives."
                    ))
                    vulnerable = True
            except requests.RequestException:
                pass

        if not vulnerable:
            findings.append(Finding("SQLi", "OK", f"Parameter '{param}' — no SQLi indicators found", ""))

    return findings
