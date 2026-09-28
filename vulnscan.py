#!/usr/bin/env python3
"""
vulnscan.py - Website recon + CVE lookup tool (NVD public database)

SIRF apni website ya jiski written permission ho, uspe use karo.

Install:  pip install requests
Usage:    python vulnscan.py example.com --i-have-permission
          python vulnscan.py https://example.com --i-have-permission --ports full --out report.json
Optional: export NVD_API_KEY=xxxx  (free key: nvd.nist.gov/developers/request-an-api-key) -> faster
"""
import argparse, json, os, re, socket, ssl, sys, time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests
requests.packages.urllib3.disable_warnings()

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.getenv("NVD_API_KEY")
UA = {"User-Agent": "vulnscan/1.0 (security-audit)"}

# software name -> (cpe vendor, cpe product)
CPE_MAP = {
    "apache": ("apache", "http_server"), "nginx": ("f5", "nginx"),
    "php": ("php", "php"), "openssh": ("openbsd", "openssh"),
    "wordpress": ("wordpress", "wordpress"), "joomla": ("joomla", "joomla\\!"),
    "drupal": ("drupal", "drupal"), "jquery": ("jquery", "jquery"),
    "bootstrap": ("getbootstrap", "bootstrap"), "openssl": ("openssl", "openssl"),
    "iis": ("microsoft", "internet_information_services"),
    "lighttpd": ("lighttpd", "lighttpd"), "proftpd": ("proftpd", "proftpd"),
    "vsftpd": ("beasts", "vsftpd"), "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"), "postfix": ("postfix", "postfix"),
    "exim": ("exim", "exim"), "tomcat": ("apache", "tomcat"),
    "angular": ("angularjs", "angular.js"), "vue": ("vuejs", "vue.js"),
}

PORTS_COMMON = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433,
                3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
RISKY = {23: "Telnet (unencrypted)", 21: "FTP", 445: "SMB", 3389: "RDP",
         6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
         3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 5900: "VNC"}

SEC_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy",
               "X-Frame-Options", "X-Content-Type-Options",
               "Referrer-Policy", "Permissions-Policy"]

SENSITIVE_PATHS = ["/.git/HEAD", "/.env", "/phpinfo.php", "/server-status",
                   "/wp-login.php", "/admin", "/backup.zip", "/.DS_Store",
                   "/robots.txt", "/sitemap.xml", "/wp-json/", "/xmlrpc.php"]


def info(msg): print(f"[*] {msg}")
def warn(msg): print(f"[!] {msg}")


# ---------------- Recon ----------------
def resolve(host):
    try:
        return sorted({r[4][0] for r in socket.getaddrinfo(host, None)})
    except socket.gaierror:
        return []


def tls_info(host, port=443):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
                if not cert:  # CERT_NONE returns {} -> re-fetch binary form not parsed; use verified ctx
                    ctx2 = ssl.create_default_context()
                    with socket.create_connection((host, port), timeout=5) as s2:
                        with ctx2.wrap_socket(s2, server_hostname=host) as s3:
                            cert = s3.getpeercert()
                return {"version": ss.version(), "cipher": ss.cipher()[0],
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "not_after": cert.get("notAfter"),
                        "san": [v for k, v in cert.get("subjectAltName", [])]}
    except Exception as e:
        return {"error": str(e)}


def http_probe(base):
    out = {"headers": {}, "status": None, "body": "", "final_url": base, "error": None}
    try:
        r = requests.get(base, headers=UA, timeout=10, verify=False, allow_redirects=True)
        out.update(headers=dict(r.headers), status=r.status_code,
                   body=r.text[:300000], final_url=r.url)
        out["cookies"] = [{"name": c.name, "secure": c.secure,
                           "httponly": c.has_nonstandard_attr("HttpOnly")} for c in r.cookies]
    except Exception as e:
        out["error"] = str(e)
    return out


def detect_tech(probe):
    """Returns list of (name, version, source)"""
    found = []
    h = {k.lower(): v for k, v in probe["headers"].items()}
    body = probe["body"]

    for hdr in ("server", "x-powered-by", "x-aspnet-version"):
        for m in re.finditer(r"([A-Za-z][A-Za-z\-_.]+)/(\d+(?:\.\d+)+)", h.get(hdr, "")):
            found.append((m.group(1).lower().replace("microsoft-", ""), m.group(2), f"header:{hdr}"))

    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if m:
        g = re.match(r"([A-Za-z ]+?)\s+(\d+(?:\.\d+)+)", m.group(1))
        if g:
            found.append((g.group(1).strip().lower(), g.group(2), "meta:generator"))

    for m in re.finditer(r"(jquery|bootstrap|angular|vue)[\-.@/]?(?:min[\-.])?v?(\d+\.\d+(?:\.\d+)?)", body, re.I):
        found.append((m.group(1).lower(), m.group(2), "script"))

    # CMS hints (without version)
    hints = []
    if "wp-content" in body or "wp-includes" in body: hints.append("WordPress")
    if "/sites/default/files" in body: hints.append("Drupal")
    if "Joomla" in body: hints.append("Joomla")
    if "cloudflare" in h.get("server", "").lower() or "cf-ray" in h: hints.append("Cloudflare CDN")
    if "x-shopify-stage" in h: hints.append("Shopify")
    return list({(a, b, c) for a, b, c in found}), hints


def check_security_headers(probe):
    h = {k.lower() for k in probe["headers"]}
    return [x for x in SEC_HEADERS if x.lower() not in h]


def check_paths(base):
    hits = []
    def chk(p):
        try:
            r = requests.get(base.rstrip("/") + p, headers=UA, timeout=6,
                             verify=False, allow_redirects=False)
            if r.status_code in (200, 401, 403):
                return {"path": p, "status": r.status_code, "size": len(r.content)}
        except Exception:
            pass
    with ThreadPoolExecutor(8) as ex:
        hits = [x for x in ex.map(chk, SENSITIVE_PATHS) if x]
    return hits


def scan_port(host, port):
    try:
        with socket.create_connection((host, port), timeout=2) as s:
            banner = ""
            try:
                s.settimeout(2)
                if port in (80, 8080):
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(256).decode(errors="ignore").strip().split("\n")[0]
            except Exception:
                pass
            return {"port": port, "banner": banner}
    except Exception:
        return None


def port_scan(host, full=False):
    ports = range(1, 1025) if full else PORTS_COMMON
    with ThreadPoolExecutor(100) as ex:
        return sorted([r for r in ex.map(lambda p: scan_port(host, p), ports) if r],
                      key=lambda x: x["port"])


def banner_tech(banner):
    m = re.search(r"OpenSSH[_\-](\d+\.\d+(?:p\d+)?)", banner)
    if m: return ("openssh", re.sub(r"p\d+$", "", m.group(1)))
    m = re.search(r"(ProFTPD|vsFTPd|Postfix|Exim)[ /](\d+(?:\.\d+)+)", banner, re.I)
    if m: return (m.group(1).lower(), m.group(2))
    return None


# ---------------- NVD CVE lookup ----------------
def nvd_query(params):
    headers = dict(UA)
    if API_KEY: headers["apiKey"] = API_KEY
    for attempt in range(3):
        try:
            r = requests.get(NVD_URL, params=params, headers=headers, timeout=30)
            if r.status_code == 200:
                return r.json()
            if r.status_code in (403, 429):
                time.sleep(8)
        except Exception:
            time.sleep(3)
    return None


def parse_cves(data, limit):
    cves = []
    for v in (data or {}).get("vulnerabilities", []):
        c = v["cve"]
        score, sev = None, "N/A"
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in c.get("metrics", {}):
                d = c["metrics"][key][0]["cvssData"]
                score, sev = d.get("baseScore"), d.get("baseSeverity") or c["metrics"][key][0].get("baseSeverity", "N/A")
                break
        desc = next((x["value"] for x in c["descriptions"] if x["lang"] == "en"), "")
        cves.append({"id": c["id"], "score": score, "severity": sev,
                     "published": c["published"][:10], "description": desc[:300]})
    cves.sort(key=lambda x: x["score"] or 0, reverse=True)
    return cves[:limit]


def lookup_cves(name, version, limit=10):
    delay = 0.7 if API_KEY else 6.5  # NVD rate limits
    if name in CPE_MAP:
        vendor, product = CPE_MAP[name]
        cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        data = nvd_query({"virtualMatchString": cpe, "resultsPerPage": 100})
        time.sleep(delay)
        return parse_cves(data, limit), "cpe-match (accurate)"
    data = nvd_query({"keywordSearch": f"{name} {version}", "resultsPerPage": 50})
    time.sleep(delay)
    return parse_cves(data, limit), "keyword (may have false positives)"


# ---------------- Main ----------------
def main():
    ap = argparse.ArgumentParser(description="Website recon + NVD CVE scanner")
    ap.add_argument("target", help="domain or URL")
    ap.add_argument("--i-have-permission", action="store_true", required=True,
                    help="confirm you are authorised to scan this target")
    ap.add_argument("--ports", choices=["common", "full", "none"], default="common")
    ap.add_argument("--max-cves", type=int, default=10)
    ap.add_argument("--out", default="report.json")
    a = ap.parse_args()

    url = a.target if a.target.startswith("http") else f"https://{a.target}"
    host = urlparse(url).hostname
    report = {"target": host, "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S")}

    info(f"Target: {host}")
    ips = resolve(host)
    report["ips"] = ips
    if not ips:
        warn("DNS resolve nahi hua"); sys.exit(1)
    info(f"IPs: {', '.join(ips)}")

    info("HTTP probe...")
    probe = http_probe(url)
    if probe["error"] and url.startswith("https"):
        probe = http_probe(url.replace("https://", "http://", 1))
    if probe["error"]:
        warn(f"HTTP error: {probe['error']}")
    report["http"] = {"status": probe["status"], "final_url": probe["final_url"],
                      "headers": probe["headers"], "cookies": probe.get("cookies", [])}

    techs, hints = detect_tech(probe)
    report["missing_security_headers"] = check_security_headers(probe)
    report["cms_hints"] = hints

    info("TLS info...")
    report["tls"] = tls_info(host)

    info("Sensitive paths check...")
    report["exposed_paths"] = check_paths(probe["final_url"].split("?")[0].rstrip("/") if probe["final_url"] else url)

    report["open_ports"] = []
    if a.ports != "none":
        info(f"Port scan ({a.ports})...")
        report["open_ports"] = port_scan(ips[0], a.ports == "full")
        for p in report["open_ports"]:
            bt = banner_tech(p["banner"])
            if bt: techs.append((bt[0], bt[1], f"banner:port{p['port']}"))
            p["risk_note"] = RISKY.get(p["port"])

    report["technologies"] = [{"name": n, "version": v, "source": s} for n, v, s in techs]

    info(f"CVE lookup NVD se ({len(techs)} technologies)... thoda time lagega")
    report["cve_findings"] = []
    seen = set()
    for n, v, s in techs:
        if (n, v) in seen: continue
        seen.add((n, v))
        cves, method = lookup_cves(n, v, a.max_cves)
        report["cve_findings"].append({"software": n, "version": v, "detected_via": s,
                                       "match_method": method, "cves": cves})

    # ---- Print summary ----
    print("\n" + "=" * 60 + f"\nREPORT: {host}\n" + "=" * 60)
    print(f"Status: {probe['status']}  |  IPs: {', '.join(ips)}")
    if hints: print(f"Hints: {', '.join(hints)}")
    tls = report["tls"]
    if "error" not in tls:
        print(f"TLS: {tls['version']} | expires {tls['not_after']}")
    if report["missing_security_headers"]:
        print("\nMissing security headers:", ", ".join(report["missing_security_headers"]))
    if report["exposed_paths"]:
        print("\nInteresting paths:")
        for p in report["exposed_paths"]:
            print(f"  {p['status']}  {p['path']}  ({p['size']} bytes)")
    if report["open_ports"]:
        print("\nOpen ports:")
        for p in report["open_ports"]:
            print(f"  {p['port']:<6} {p.get('risk_note') or '':<22} {p['banner'][:60]}")
    print("\nTechnologies & CVEs:")
    for f in report["cve_findings"]:
        print(f"\n  {f['software']} {f['version']}  [{f['detected_via']}] - {f['match_method']}")
        if not f["cves"]:
            print("    koi CVE nahi mili")
        for c in f["cves"]:
            print(f"    {c['id']}  {c['severity']} ({c['score']})  {c['published']}")
            print(f"      {c['description'][:140]}")

    with open(a.out, "w") as fh:
        json.dump(report, fh, indent=2)
    info(f"Full report saved: {a.out}")
    print("\nNote: version-based match ka matlab 'vulnerable ho sakta hai' — backported patches "
          "ki wajah se false positives possible hain. Manually verify karo.")


if __name__ == "__main__":
    main()
