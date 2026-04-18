"""
modules/osint.py — OSINT Tools for SPECTRE.

Sub-menu:
  [1] DNS Lookup        — resolve domain → IPs (A, AAAA)
  [2] Reverse DNS       — IP → hostname
  [3] WHOIS             — domain registration info
  [4] IP Geolocation    — location + ISP info from IP/domain
  [5] HTTP Headers      — grab server headers from a URL
  [6] Subdomain Enum    — brute-force common subdomains

All pure Python — no third-party deps required.
Uses only: socket, http.client, subprocess (for whois tool).
"""

import socket
import http.client
import ssl
import json
import datetime
import subprocess
import os
from core.display import (
    print_info, print_ok, print_warn, print_err,
    print_section, prompt, Color
)

# ── Sub-menu ───────────────────────────────────────────────────────────────────

def run(status: dict):
    while True:
        print_section("OSINT Tools")
        items = [
            "DNS Lookup     — domain → IP addresses",
            "Reverse DNS    — IP → hostname",
            "WHOIS          — domain registration info",
            "IP Geolocation — location & ISP from IP or domain",
            "HTTP Headers   — grab server response headers",
            "Subdomain Enum — brute-force common subdomains",
            "SSL Inspector  — check certificate details & expiry",
        ]
        for i, label in enumerate(items, 1):
            print(f"  {Color.CYAN}[{i}]{Color.RESET}  {label}")
        print(f"\n  {Color.DIM}[0]  Back{Color.RESET}")

        choice = prompt("OSINT")
        if choice in ("0", ""):
            break
        if not choice.isdigit() or not (1 <= int(choice) <= len(items)):
            print_warn("Invalid choice.")
            continue

        handlers = [
            _dns_lookup,
            _reverse_dns,
            _whois,
            _ip_geolocation,
            _http_headers,
            _subdomain_enum,
            _ssl_inspector,
        ]
        handlers[int(choice) - 1]()
        prompt("Press Enter to continue")


# ── [1] DNS Lookup ─────────────────────────────────────────────────────────────

def _dns_lookup():
    print_section("DNS Lookup")
    target = prompt("Domain")
    if not target:
        return

    target = _strip_scheme(target)
    print_info(f"Resolving {target} ...")

    try:
        results = socket.getaddrinfo(target, None)
        seen = {}
        for r in results:
            ip   = r[4][0]
            kind = "IPv6" if ":" in ip else "IPv4"
            if ip not in seen:
                seen[ip] = kind
    except socket.gaierror as e:
        print_err(f"Resolution failed: {e}")
        return

    if not seen:
        print_warn("No records found.")
        return

    print(f"\n  {'TYPE':<8} ADDRESS")
    print(f"  {'─'*8} {'─'*40}")
    for ip, kind in seen.items():
        color = Color.CYAN if kind == "IPv4" else Color.YELLOW
        print(f"  {Color.DIM}{kind:<8}{Color.RESET} {color}{ip}{Color.RESET}")

    print(f"\n  {Color.CYAN}Found {len(seen)} record(s).{Color.RESET}")


# ── [2] Reverse DNS ────────────────────────────────────────────────────────────

def _reverse_dns():
    print_section("Reverse DNS")
    ip = prompt("IP address")
    if not ip:
        return

    print_info(f"Looking up {ip} ...")
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        print_ok(f"Hostname : {hostname}")
        if aliases:
            for alias in aliases:
                print_ok(f"Alias    : {alias}")
    except socket.herror as e:
        print_warn(f"No PTR record found: {e}")
    except socket.gaierror as e:
        print_err(f"Invalid address: {e}")


# ── [3] WHOIS ─────────────────────────────────────────────────────────────────

def _whois():
    print_section("WHOIS Lookup")
    target = prompt("Domain / IP")
    if not target:
        return

    target = _strip_scheme(target).split("/")[0]
    print_info(f"WHOIS query for {target} ...")

    # Try system whois tool first
    if _cmd_exists("whois"):
        try:
            result = subprocess.run(
                ["whois", target],
                capture_output=True, text=True, timeout=15
            )
            _print_whois_filtered(result.stdout)
            return
        except subprocess.TimeoutExpired:
            print_warn("whois tool timed out.")
        except Exception as e:
            print_warn(f"whois tool error: {e}")

    # Fallback: raw socket to whois.iana.org → find authoritative server → query it
    print_info("Using raw socket WHOIS...")
    _raw_whois(target)


def _raw_whois(target: str):
    """Pure Python WHOIS via socket — no external tools needed."""
    try:
        # Step 1: query IANA to find the right whois server
        server = "whois.iana.org"
        raw    = _whois_query(server, target)

        # Extract 'whois:' field from IANA response
        auth_server = None
        for line in raw.splitlines():
            if line.lower().startswith("whois:"):
                auth_server = line.split(":", 1)[1].strip()
                break

        # Step 2: query the authoritative server
        if auth_server:
            print_info(f"Querying {auth_server} ...")
            raw = _whois_query(auth_server, target)

        _print_whois_filtered(raw)

    except Exception as e:
        print_err(f"WHOIS failed: {e}")


def _whois_query(server: str, target: str) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect((server, 43))
        s.sendall(f"{target}\r\n".encode())
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode(errors="replace")


def _print_whois_filtered(raw: str):
    """Print WHOIS output, skip comment lines and blanks."""
    important_keys = {
        "domain name", "registrar", "creation date", "updated date",
        "registry expiry date", "registrant", "name server",
        "status", "dnssec", "org", "netname", "country", "address",
    }
    printed = 0
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("%") or stripped.startswith("#"):
            continue
        key = stripped.split(":")[0].lower()
        if any(k in key for k in important_keys):
            print(f"  {Color.CYAN}{stripped.split(':')[0]:<28}{Color.RESET}"
                  f":{':'.join(stripped.split(':')[1:])}")
            printed += 1
        elif printed == 0:
            print(f"  {stripped}")


# ── [4] IP Geolocation ────────────────────────────────────────────────────────

def _ip_geolocation():
    print_section("IP Geolocation")
    target = prompt("IP address or domain")
    if not target:
        return

    target = _strip_scheme(target).split("/")[0]

    # Resolve domain to IP if needed
    if not _is_ip(target):
        print_info(f"Resolving {target} ...")
        try:
            target = socket.gethostbyname(target)
            print_ok(f"Resolved to: {target}")
        except socket.gaierror as e:
            print_err(f"Cannot resolve: {e}")
            return

    print_info(f"Geolocating {target} ...")

    try:
        conn = http.client.HTTPConnection("ip-api.com", timeout=10)
        conn.request(
            "GET",
            f"/json/{target}?fields=status,message,country,regionName,city,"
            "zip,lat,lon,timezone,isp,org,as,query",
            headers={"User-Agent": "SPECTRE/2.0"}
        )
        resp = conn.getresponse()
        data = json.loads(resp.read().decode())
        conn.close()
    except Exception as e:
        print_err(f"Geolocation request failed: {e}")
        return

    if data.get("status") != "success":
        print_warn(f"API error: {data.get('message', 'unknown')}")
        return

    fields = [
        ("IP",        "query"),
        ("Country",   "country"),
        ("Region",    "regionName"),
        ("City",      "city"),
        ("ZIP",       "zip"),
        ("Latitude",  "lat"),
        ("Longitude", "lon"),
        ("Timezone",  "timezone"),
        ("ISP",       "isp"),
        ("Org",       "org"),
        ("AS",        "as"),
    ]
    print()
    for label, key in fields:
        val = data.get(key, "—")
        if val:
            print(f"  {Color.CYAN}{label:<12}{Color.RESET} {val}")


# ── [5] HTTP Headers ──────────────────────────────────────────────────────────

def _http_headers():
    print_section("HTTP Headers")
    raw_url = prompt("URL (e.g. example.com or https://example.com)")
    if not raw_url:
        return

    # Parse scheme, host, path
    if raw_url.startswith("https://"):
        use_ssl = True
        host_path = raw_url[8:]
    elif raw_url.startswith("http://"):
        use_ssl = False
        host_path = raw_url[7:]
    else:
        use_ssl = False
        host_path = raw_url

    parts = host_path.split("/", 1)
    host  = parts[0]
    path  = "/" + parts[1] if len(parts) > 1 else "/"

    print_info(f"Connecting to {host}{path} ...")

    try:
        if use_ssl:
            import ssl
            ctx  = ssl.create_default_context()
            conn = http.client.HTTPSConnection(host, timeout=10, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, timeout=10)

        conn.request("HEAD", path, headers={
            "User-Agent": "SPECTRE/2.0",
            "Accept": "*/*",
        })
        resp = conn.getresponse()
        conn.close()
    except Exception as e:
        print_err(f"Connection failed: {e}")
        return

    status_color = Color.GREEN if resp.status < 400 else Color.RED
    print(f"\n  {Color.CYAN}Status{Color.RESET}  {status_color}{resp.status} {resp.reason}{Color.RESET}\n")

    security_headers = {
        "strict-transport-security", "content-security-policy",
        "x-frame-options", "x-content-type-options",
        "x-xss-protection", "referrer-policy",
        "permissions-policy",
    }
    for name, value in resp.getheaders():
        label_color = Color.GREEN if name.lower() in security_headers else Color.DIM
        print(f"  {label_color}{name:<35}{Color.RESET} {value}")


# ── [6] Subdomain Enum ────────────────────────────────────────────────────────

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "vpn", "remote",
    "api", "dev", "staging", "test", "admin", "portal", "app",
    "cdn", "static", "assets", "media", "blog", "shop", "store",
    "git", "gitlab", "jenkins", "jira", "confluence", "wiki",
    "ns1", "ns2", "mx", "webmail", "cpanel", "whm", "secure",
    "beta", "demo", "auth", "sso", "login", "dashboard", "monitor",
]

def _subdomain_enum():
    print_section("Subdomain Enumeration")
    domain = prompt("Domain (e.g. example.com)")
    if not domain:
        return

    domain = _strip_scheme(domain).split("/")[0]
    print_info(f"Testing {len(COMMON_SUBDOMAINS)} subdomains for {domain} ...\n")

    print(f"  {'SUBDOMAIN':<40} IP")
    print(f"  {'─'*40} {'─'*20}")

    found = 0
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            print(f"  {Color.GREEN}{fqdn:<40}{Color.RESET} {ip}")
            found += 1
        except socket.gaierror:
            pass

    print(f"\n  {Color.CYAN}Found {found} subdomain(s).{Color.RESET}")


# ── [7] SSL Inspector ─────────────────────────────────────────────────────────

def _ssl_inspector():
    print_section("SSL / TLS Inspector")
    host = prompt("Domain (e.g. google.com)")
    if not host:
        return

    host = _strip_scheme(host).split("/")[0]
    port_raw = prompt("Port [443]")
    try:
        port = int(port_raw) if port_raw.strip() else 443
    except ValueError:
        port = 443

    print_info(f"Fetching certificate from {host}:{port} ...")

    try:
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((host, port), timeout=10),
            server_hostname=host
        )
        cert = conn.getpeercert()
        conn.close()
    except ssl.SSLCertVerificationError as e:
        print_warn(f"Certificate verification failed: {e}")
        # Try without verification to still show cert info
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode    = ssl.CERT_NONE
            conn = ctx2.wrap_socket(
                socket.create_connection((host, port), timeout=10),
                server_hostname=host
            )
            cert = conn.getpeercert()
            conn.close()
        except Exception as e2:
            print_err(f"Cannot retrieve certificate: {e2}")
            return
    except Exception as e:
        print_err(f"Connection failed: {e}")
        return

    print()

    # Subject
    subject = dict(x[0] for x in cert.get("subject", []))
    print_ok(f"Common Name  : {subject.get('commonName', '—')}")
    print_ok(f"Organization : {subject.get('organizationName', '—')}")

    # Issuer
    issuer = dict(x[0] for x in cert.get("issuer", []))
    print_ok(f"Issuer       : {issuer.get('organizationName', '—')}")

    # Validity
    fmt = "%b %d %H:%M:%S %Y %Z"
    try:
        not_before = datetime.datetime.strptime(cert["notBefore"], fmt)
        not_after  = datetime.datetime.strptime(cert["notAfter"],  fmt)
        now        = datetime.datetime.utcnow()
        days_left  = (not_after - now).days

        print_ok(f"Valid From   : {not_before.strftime('%Y-%m-%d')}")

        if days_left < 0:
            exp_color = Color.RED
            exp_label = f"EXPIRED {abs(days_left)} days ago"
        elif days_left < 30:
            exp_color = Color.YELLOW
            exp_label = f"{days_left} days left — renew soon!"
        else:
            exp_color = Color.GREEN
            exp_label = f"{days_left} days left"

        print(f"  {Color.CYAN}Valid To    {Color.RESET} : "
              f"{exp_color}{not_after.strftime('%Y-%m-%d')}  ({exp_label}){Color.RESET}")
    except Exception:
        print_ok(f"Not After    : {cert.get('notAfter', '—')}")

    # SANs
    sans = cert.get("subjectAltName", [])
    if sans:
        san_list = ", ".join(v for _, v in sans[:8])
        if len(sans) > 8:
            san_list += f" ... +{len(sans)-8} more"
        print_ok(f"SANs         : {san_list}")

    # TLS version
    print_ok(f"Protocol     : TLS")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _strip_scheme(url: str) -> str:
    for prefix in ("https://", "http://", "ftp://"):
        if url.startswith(prefix):
            return url[len(prefix):]
    return url


def _is_ip(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return True
    except socket.error:
        return False


def _cmd_exists(cmd: str) -> bool:
    try:
        subprocess.run(
            [cmd, "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
