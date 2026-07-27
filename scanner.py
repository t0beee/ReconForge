"""
ReconForge v5.0 — All scan modules in one clean file
"""

import socket, ssl, re, json, time, datetime, requests, dns.resolver
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
from wordlists import (SUBDOMAINS, PHP_FILES, DIRECTORIES, WAF_SIGNATURES,
                       TOP_PORTS, PORT_RISK, PORT_REASON, SECURITY_HEADERS,
                       HEADER_RISK, TECH_SIGNATURES, WP_PATHS)

HEADERS = {"User-Agent": "ReconForge/5.0 Security Scanner"}

def info(msg):  print(f"  {Fore.BLUE}[*]{Style.RESET_ALL} {msg}")
def good(msg):  print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg):  print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def bad(msg):   print(f"  {Fore.RED}[-]{Style.RESET_ALL} {msg}")

def pbar(cur, tot, label="", width=38):
    import sys
    sys.stdout.write(f"\r  {Fore.BLUE}[*]{Style.RESET_ALL} {cur}/{tot} — {label[:50]:<50}")
    sys.stdout.flush()
    if cur == tot:
        sys.stdout.write("\r" + " "*80 + "\r")
        sys.stdout.flush()

def section(title):
    print(f"\n{Fore.CYAN}╔{'═'*(len(title)+4)}╗")
    print(f"║  {Fore.YELLOW}{title}{Fore.CYAN}  ║")
    print(f"╚{'═'*(len(title)+4)}╝{Style.RESET_ALL}")


# ═══════════════════════════════════════════════
# 1. DNS RESOLUTION & RECORDS
# ═══════════════════════════════════════════════
def resolve(domain, timeout=3):
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(domain)
    except Exception:
        return None

def get_dns_records(domain):
    section("DNS RECORDS")
    records = {}
    for rtype in ["A","AAAA","MX","NS","TXT","CNAME","SOA"]:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            records[rtype] = [str(r) for r in answers]
            for v in records[rtype]:
                good(f"{rtype:<6}  {v}")
        except Exception:
            records[rtype] = []
    return records


# ═══════════════════════════════════════════════
# 2. GEOIP
# ═══════════════════════════════════════════════
def geoip(ip):
    section("GEO-IP LOCATION")
    result = {"ip":ip,"country":"N/A","region":"N/A","city":"N/A",
              "isp":"N/A","org":"N/A","lat":None,"lon":None,
              "timezone":"N/A","hosting":False,"asn":"N/A"}
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,lat,lon,timezone,hosting,as",
            timeout=6, headers=HEADERS)
        d = r.json()
        if d.get("status") == "success":
            result.update({
                "country":  d.get("country","N/A"),
                "region":   d.get("regionName","N/A"),
                "city":     d.get("city","N/A"),
                "isp":      d.get("isp","N/A"),
                "org":      d.get("org","N/A"),
                "lat":      d.get("lat"),
                "lon":      d.get("lon"),
                "timezone": d.get("timezone","N/A"),
                "hosting":  d.get("hosting",False),
                "asn":      d.get("as","N/A"),
            })
            good(f"Location  : {result['city']}, {result['region']}, {result['country']}")
            good(f"ISP       : {result['isp']}")
            good(f"Org/ASN   : {result['org']}  {result['asn']}")
            good(f"Timezone  : {result['timezone']}")
            if result["hosting"]:
                warn("Hosted on cloud/datacenter infrastructure")
    except Exception as e:
        bad(f"GeoIP failed: {e}")
    return result


# ═══════════════════════════════════════════════
# 3. WHOIS
# ═══════════════════════════════════════════════
def whois_lookup(domain):
    section("WHOIS LOOKUP")
    result = {"registrar":"N/A","created":"N/A","expires":"N/A",
              "updated":"N/A","name_servers":[],"status":"N/A","org":"N/A"}
    try:
        r = requests.get(f"https://api.whois.vu/?q={domain}&format=json", timeout=8, headers=HEADERS)
        d = r.json()
        result["registrar"]    = d.get("registrar","N/A")
        result["created"]      = d.get("creation_date","N/A")
        result["expires"]      = d.get("expiration_date","N/A")
        result["updated"]      = d.get("updated_date","N/A")
        result["status"]       = d.get("status","N/A")
        ns = d.get("name_servers",[])
        result["name_servers"] = ns if isinstance(ns,list) else [ns]
        result["org"]          = d.get("org","N/A")
        good(f"Registrar    : {result['registrar']}")
        good(f"Created      : {result['created']}")
        good(f"Expires      : {result['expires']}")
        good(f"Updated      : {result['updated']}")
        good(f"Name Servers : {', '.join(result['name_servers'])}")
        good(f"Status       : {result['status']}")
    except Exception:
        # fallback raw WHOIS socket
        try:
            tld = domain.split(".")[-1]
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((f"whois.{tld}.com", 43))
            s.send((domain+"\r\n").encode())
            raw = b""
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                raw += chunk
            s.close()
            result["raw"] = raw.decode(errors="ignore")[:500]
            good("Raw WHOIS data retrieved")
        except Exception as e:
            bad(f"WHOIS failed: {e}")
    return result


# ═══════════════════════════════════════════════
# 4. SSL CERTIFICATE
# ═══════════════════════════════════════════════
def inspect_ssl(domain):
    section("SSL / TLS CERTIFICATE")
    result = {"valid":False,"subject":"N/A","issuer":"N/A","org":"N/A",
              "expires":"N/A","days_left":None,"protocol":"N/A",
              "san":[],"self_signed":False,"expired":False,"weak_cipher":False}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert   = s.getpeercert()
            cipher = s.cipher()
            result["valid"]    = True
            result["protocol"] = cipher[1] if cipher else "N/A"
            result["weak_cipher"] = result["protocol"] in ["TLSv1","TLSv1.1","SSLv2","SSLv3"]
            subj = dict(x[0] for x in cert.get("subject",[]))
            result["subject"] = subj.get("commonName","N/A")
            result["org"]     = subj.get("organizationName","N/A")
            iss = dict(x[0] for x in cert.get("issuer",[]))
            result["issuer"]      = iss.get("organizationName","N/A")
            result["self_signed"] = (result["subject"] == result["issuer"])
            exp = cert.get("notAfter","")
            if exp:
                exp_dt = datetime.datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z")
                result["expires"]   = exp_dt.strftime("%Y-%m-%d")
                result["days_left"] = (exp_dt - datetime.datetime.utcnow()).days
                result["expired"]   = result["days_left"] < 0
            result["san"] = [v for t,v in cert.get("subjectAltName",[]) if t=="DNS"]

            status = "EXPIRED" if result["expired"] else "VALID"
            color  = Fore.RED if result["expired"] else Fore.GREEN
            good(f"Status       : {color}{status}{Style.RESET_ALL}")
            good(f"Subject      : {result['subject']}")
            good(f"Issuer       : {result['issuer']}")
            good(f"Organization : {result['org']}")
            good(f"Protocol     : {result['protocol']}")
            good(f"Expires      : {result['expires']}  ({result['days_left']} days remaining)")
            if result["days_left"] is not None and result["days_left"] < 30:
                warn(f"Certificate expires in {result['days_left']} days — renew soon!")
            if result["self_signed"]:
                warn("Self-signed certificate — not trusted by browsers")
            if result["weak_cipher"]:
                warn(f"Weak protocol {result['protocol']} detected — upgrade to TLS 1.2+")
            if result["san"]:
                good(f"SANs ({len(result['san'])}) : {', '.join(result['san'][:6])}")
    except ssl.SSLError as e:
        warn(f"SSL error: {e}")
    except Exception as e:
        bad(f"SSL inspection failed: {e}")
    return result


# ═══════════════════════════════════════════════
# 5. WAF DETECTION
# ═══════════════════════════════════════════════
def detect_waf(domain):
    section("WAF / FIREWALL DETECTION")
    result = {"detected":False,"name":None,"evidence":[]}
    probes = [
        f"https://{domain}/?id=1'%20OR%20'1'='1",
        f"https://{domain}/?q=<script>alert(1)</script>",
        f"http://{domain}/?id=1'%20OR%20'1'='1",
    ]
    for url in probes:
        try:
            r = requests.get(url, timeout=5, allow_redirects=True, headers=HEADERS)
            combined = (str(r.headers) + r.text).lower()
            for name, sigs in WAF_SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in combined:
                        result.update({"detected":True,"name":name,"evidence":[sig]})
                        warn(f"WAF Detected : {name}")
                        warn(f"Evidence     : signature '{sig}' found in response")
                        return result
            if r.status_code in [403,406,429,503]:
                result.update({"detected":True,"name":"Unknown WAF",
                               "evidence":[f"HTTP {r.status_code}"]})
                warn(f"Possible WAF : Blocked request with HTTP {r.status_code}")
                return result
            break
        except Exception:
            continue
    if not result["detected"]:
        good("No WAF detected — direct access to server")
    return result


# ═══════════════════════════════════════════════
# 6. SUBDOMAIN ENUMERATION
# ═══════════════════════════════════════════════
def enumerate_subdomains(domain, timeout=3):
    section("SUBDOMAIN ENUMERATION")
    info(f"Wordlist: {len(SUBDOMAINS)} entries — testing DNS resolution...")
    found = []
    total = len(SUBDOMAINS)

    def check(args):
        i, sub = args
        full = f"{sub}.{domain}"
        ip   = resolve(full, timeout)
        pbar(i+1, total, sub)
        if ip:
            return {"subdomain": full, "ip": ip}
        return None

    with ThreadPoolExecutor(max_workers=60) as ex:
        for r in ex.map(check, enumerate(SUBDOMAINS)):
            if r:
                found.append(r)
                good(f"Found : {r['subdomain']:<45} → {r['ip']}")

    info(f"Subdomain enumeration complete — {len(found)} found")
    return found


# ═══════════════════════════════════════════════
# 7. PORT SCANNING
# ═══════════════════════════════════════════════
def scan_ports(ip, timeout=1.5):
    section("PORT SCANNING")
    info(f"Scanning {len(TOP_PORTS)} common ports on {ip}...")
    open_ports = []
    ports = list(TOP_PORTS.keys())
    total = len(ports)

    for i, port in enumerate(ports):
        pbar(i+1, total, f"port {port}")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    svc  = TOP_PORTS.get(port,"unknown")
                    risk = PORT_RISK.get(port,"INFO")
                    open_ports.append({"port":port,"service":svc,"risk":risk})
                    color = {
                        "CRITICAL":Fore.RED,"HIGH":Fore.YELLOW,
                        "MEDIUM":Fore.CYAN,"LOW":Fore.WHITE,"INFO":Fore.GREEN
                    }.get(risk, Fore.WHITE)
                    good(f"Port {port:>5}/tcp  {svc:<16}  [{color}{risk}{Style.RESET_ALL}]")
        except Exception:
            pass

    return sorted(open_ports, key=lambda x: x["port"])


# ═══════════════════════════════════════════════
# 8. HTTP HEADERS & TECH FINGERPRINT
# ═══════════════════════════════════════════════
def check_http(domain, timeout=5):
    section("HTTP HEADERS & TECHNOLOGY FINGERPRINT")
    result = {"url":"","status_code":None,"server":"N/A","x_powered_by":"N/A",
              "headers_found":[],"headers_missing":[],"technologies":[],
              "cookies":[],"redirect_chain":[]}
    for scheme in ["https","http"]:
        try:
            r = requests.get(f"{scheme}://{domain}", timeout=timeout,
                             allow_redirects=True, headers=HEADERS)
            result["url"]         = r.url
            result["status_code"] = r.status_code
            result["server"]      = r.headers.get("Server","Hidden")
            result["x_powered_by"]= r.headers.get("X-Powered-By","N/A")

            # Headers audit
            h_lower = [h.lower() for h in r.headers]
            for h in SECURITY_HEADERS:
                if h.lower() in h_lower:
                    result["headers_found"].append(h)
                    good(f"[PRESENT] {h}")
                else:
                    result["headers_missing"].append(h)
                    sev, reason = HEADER_RISK.get(h,("LOW",""))
                    warn(f"[MISSING] {h}  →  {sev} risk")

            # Tech fingerprint
            body     = r.text.lower()
            combined = body + str({k.lower():v for k,v in r.headers.items()})
            result["technologies"] = [t for t,sigs in TECH_SIGNATURES.items()
                                      if any(s in combined for s in sigs)]

            # Cookies
            for c in r.cookies:
                flags = []
                if not c.has_nonstandard_attr("HttpOnly"): flags.append("No HttpOnly")
                if not c.has_nonstandard_attr("Secure"):   flags.append("No Secure flag")
                if not c.has_nonstandard_attr("SameSite"): flags.append("No SameSite")
                result["cookies"].append({"name":c.name,"flags":flags})

            info(f"URL          : {result['url']}")
            info(f"Status       : {result['status_code']}")
            info(f"Server       : {result['server']}")
            info(f"X-Powered-By : {result['x_powered_by']}")
            if result["technologies"]:
                info(f"Technologies : {', '.join(result['technologies'])}")
            if result["cookies"]:
                for c in result["cookies"]:
                    if c["flags"]:
                        warn(f"Cookie '{c['name']}' — {', '.join(c['flags'])}")
            break
        except Exception:
            continue
    return result


# ═══════════════════════════════════════════════
# 9. ROBOTS.TXT & SITEMAP
# ═══════════════════════════════════════════════
def parse_robots(domain):
    section("ROBOTS.TXT & SITEMAP")
    result = {"found":False,"disallowed":[],"allowed":[],"sitemaps":[],"interesting":[]}
    INTERESTING = ["admin","login","dashboard","backup","config","secret",
                   "private","internal","api","dev","test","staging","upload","manage","panel"]
    for scheme in ["https","http"]:
        try:
            r = requests.get(f"{scheme}://{domain}/robots.txt", timeout=5, headers=HEADERS)
            if r.status_code == 200 and ("disallow" in r.text.lower() or "allow" in r.text.lower()):
                result["found"] = True
                good("robots.txt found!")
                for line in r.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":",1)[1].strip()
                        if path:
                            result["disallowed"].append(path)
                            if any(k in path.lower() for k in INTERESTING):
                                result["interesting"].append(path)
                                warn(f"Interesting disallowed path : {path}")
                            else:
                                info(f"Disallowed : {path}")
                    elif line.lower().startswith("sitemap:"):
                        url = line.split(":",1)[1].strip()
                        result["sitemaps"].append(url)
                        info(f"Sitemap    : {url}")
            break
        except Exception:
            continue
    # Sitemap.xml
    for scheme in ["https","http"]:
        try:
            r = requests.get(f"{scheme}://{domain}/sitemap.xml", timeout=5, headers=HEADERS)
            if r.status_code == 200:
                urls = re.findall(r"<loc>(.*?)</loc>", r.text)
                result["sitemap_urls"] = urls[:30]
                good(f"sitemap.xml found — {len(urls)} URLs")
                break
        except Exception:
            continue
    if not result["found"]:
        info("robots.txt not found or empty")
    return result


# ═══════════════════════════════════════════════
# 10. WORDPRESS SCAN
# ═══════════════════════════════════════════════
def wordpress_scan(domain):
    section("WORDPRESS SCAN")
    result = {"is_wp":False,"version":None,"theme":None,"plugins":[],
              "exposed":[],"xmlrpc":False,"readme":False,"users":[]}
    base = None
    for scheme in ["https","http"]:
        try:
            r = requests.get(f"{scheme}://{domain}", timeout=5, headers=HEADERS)
            body = r.text.lower()
            if "wp-content" in body or "wp-includes" in body or "wordpress" in body:
                result["is_wp"] = True
                base = f"{scheme}://{domain}"
                warn("WordPress detected!")
                ver = re.search(r'wordpress[/ ](\d+\.\d+[\.\d]*)', body)
                if ver:
                    result["version"] = ver.group(1)
                    warn(f"WordPress version : {result['version']}")
                theme = re.search(r'wp-content/themes/([^/\"\']+)', body)
                if theme:
                    result["theme"] = theme.group(1)
                    info(f"Active theme      : {result['theme']}")
                plugins = re.findall(r'wp-content/plugins/([^/\"\']+)', body)
                result["plugins"] = list(set(plugins))[:10]
                if result["plugins"]:
                    info(f"Detected plugins  : {', '.join(result['plugins'])}")
            break
        except Exception:
            continue

    if not result["is_wp"] or not base:
        good("WordPress not detected")
        return result

    def check_path(path):
        try:
            url = urljoin(base+"/", path.lstrip("/"))
            r = requests.get(url, timeout=4, headers=HEADERS, allow_redirects=False)
            if r.status_code in [200,301,302,403]:
                return {"path":path,"status":r.status_code,"url":url}
        except Exception:
            pass
        return None

    info("Scanning WordPress paths...")
    with ThreadPoolExecutor(max_workers=15) as ex:
        for r in ex.map(check_path, WP_PATHS):
            if r:
                result["exposed"].append(r)
                warn(f"[{r['status']}] {r['path']}")

    # xmlrpc
    try:
        r = requests.post(urljoin(base+"/","xmlrpc.php"),
                          data="<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName></methodCall>",
                          timeout=4, headers=HEADERS)
        if r.status_code == 200 and "methodResponse" in r.text:
            result["xmlrpc"] = True
            warn("XML-RPC ENABLED — brute-force amplification risk!")
    except Exception:
        pass

    # readme
    try:
        r = requests.get(urljoin(base+"/","readme.html"), timeout=4, headers=HEADERS)
        if r.status_code == 200:
            result["readme"] = True
            warn("readme.html exposed — version disclosure!")
    except Exception:
        pass

    # user enum
    info("Attempting user enumeration via ?author=...")
    for i in range(1,6):
        try:
            r = requests.get(f"{base}/?author={i}", timeout=4,
                             allow_redirects=True, headers=HEADERS)
            u = re.search(r'/author/([^/]+)/', r.url)
            if u:
                result["users"].append({"id":i,"username":u.group(1)})
                warn(f"WordPress user found : {u.group(1)} (ID {i})")
        except Exception:
            pass

    return result


# ═══════════════════════════════════════════════
# 11. PHP FILE ENUMERATION
# ═══════════════════════════════════════════════
def php_enumeration(domain):
    section("PHP FILE ENUMERATION")
    info(f"Testing {len(PHP_FILES)} PHP files...")
    result = {"found":[],"interesting":[],"total":len(PHP_FILES)}
    INTERESTING_KW = ["admin","config","shell","cmd","backup","debug","install","db","c99","r57","phpinfo"]
    base = f"https://{domain}"
    try:
        requests.get(base, timeout=4, headers=HEADERS)
    except Exception:
        base = f"http://{domain}"
    total = len(PHP_FILES)

    def check(args):
        i, path = args
        pbar(i+1, total, path)
        try:
            url = f"{base}/{path.lstrip('/')}"
            r = requests.get(url, timeout=3, headers=HEADERS, allow_redirects=False)
            if r.status_code in [200,301,302,403]:
                is_int = any(k in path.lower() for k in INTERESTING_KW)
                return {"path":path,"status":r.status_code,"url":url,"interesting":is_int}
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=30) as ex:
        for r in ex.map(check, enumerate(PHP_FILES)):
            if r:
                result["found"].append(r)
                if r["interesting"]:
                    result["interesting"].append(r)
                    warn(f"[{r['status']}] *** {r['path']}  ← INTERESTING")
                else:
                    good(f"[{r['status']}] {r['path']}")

    info(f"PHP enum done — {len(result['found'])} found  ({len(result['interesting'])} interesting)")
    return result


# ═══════════════════════════════════════════════
# 12. DIRECTORY BRUTEFORCE
# ═══════════════════════════════════════════════
def directory_brute(domain):
    section("DIRECTORY BRUTEFORCE")
    info(f"Testing {len(DIRECTORIES)} directories...")
    result = {"found":[],"total":len(DIRECTORIES)}
    base = f"https://{domain}"
    try:
        requests.get(base, timeout=4, headers=HEADERS)
    except Exception:
        base = f"http://{domain}"
    total = len(DIRECTORIES)

    def check(args):
        i, d = args
        pbar(i+1, total, d)
        try:
            url = f"{base}/{d}/"
            r = requests.get(url, timeout=3, headers=HEADERS, allow_redirects=False)
            if r.status_code in [200,301,302,403]:
                return {"path":d,"status":r.status_code,"url":url}
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=30) as ex:
        for r in ex.map(check, enumerate(DIRECTORIES)):
            if r:
                result["found"].append(r)
                color = Fore.YELLOW if r["status"]==403 else Fore.GREEN
                good(f"[{color}{r['status']}{Style.RESET_ALL}] /{r['path']}/")

    info(f"Directory brute done — {len(result['found'])} found")
    return result


# ═══════════════════════════════════════════════
# 13. RISK SCORING
# ═══════════════════════════════════════════════
def score_risk(results):
    findings = []
    score = 0
    SEV_SCORE = {"CRITICAL":10,"HIGH":7,"MEDIUM":4,"LOW":1,"INFO":0}

    for p in results.get("ports",[]):
        sev = p["risk"]
        findings.append({"sev":sev,"cat":"Open Port",
                         "item":f"Port {p['port']}/tcp ({p['service']})",
                         "detail":PORT_REASON.get(p["port"],"")})
        score += SEV_SCORE.get(sev,0)

    for h in results.get("http",{}).get("headers_missing",[]):
        sev, reason = HEADER_RISK.get(h,("LOW",""))
        findings.append({"sev":sev,"cat":"Missing Header","item":h,"detail":reason})
        score += SEV_SCORE.get(sev,0)

    ssl = results.get("ssl",{})
    if ssl.get("expired"):
        findings.append({"sev":"CRITICAL","cat":"SSL","item":"Certificate EXPIRED",
                         "detail":"Expired certificate causes browser warnings and breaks trust"})
        score += 10
    elif isinstance(ssl.get("days_left"),int) and ssl["days_left"] < 30:
        findings.append({"sev":"HIGH","cat":"SSL","item":f"Cert expires in {ssl['days_left']} days",
                         "detail":"Certificate expiring very soon — renew immediately"})
        score += 7
    if ssl.get("self_signed"):
        findings.append({"sev":"HIGH","cat":"SSL","item":"Self-signed certificate",
                         "detail":"Not trusted by browsers, trivial MITM attack"})
        score += 7
    if ssl.get("weak_cipher"):
        findings.append({"sev":"HIGH","cat":"SSL","item":f"Weak protocol: {ssl.get('protocol')}",
                         "detail":"TLS 1.0/1.1 deprecated, vulnerable to BEAST/POODLE"})
        score += 7

    wp = results.get("wordpress",{})
    if wp.get("xmlrpc"):
        findings.append({"sev":"HIGH","cat":"WordPress","item":"XML-RPC enabled",
                         "detail":"Allows brute-force amplification — 1 request = 1000 password attempts"})
        score += 7
    if wp.get("readme"):
        findings.append({"sev":"MEDIUM","cat":"WordPress","item":"readme.html exposed",
                         "detail":"Reveals exact WordPress version to attackers"})
        score += 4
    if wp.get("users"):
        findings.append({"sev":"MEDIUM","cat":"WordPress",
                         "item":f"Users exposed: {[u['username'] for u in wp['users']]}",
                         "detail":"Username enumeration aids targeted brute-force"})
        score += 4

    if not results.get("waf",{}).get("detected"):
        findings.append({"sev":"MEDIUM","cat":"WAF","item":"No WAF detected",
                         "detail":"No web application firewall protecting the server"})
        score += 4

    for f in results.get("php",{}).get("interesting",[]):
        findings.append({"sev":"HIGH","cat":"PHP File",
                         "item":f"{f['path']} [{f['status']}]",
                         "detail":"Sensitive PHP file accessible — possible RCE or info disclosure"})
        score += 7

    for c in results.get("http",{}).get("cookies",[]):
        if c["flags"]:
            findings.append({"sev":"LOW","cat":"Cookie",
                             "item":f"Cookie '{c['name']}': {', '.join(c['flags'])}",
                             "detail":"Insecure cookie flags enable session hijacking"})
            score += 1

    order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    findings.sort(key=lambda x: order.index(x["sev"]))

    if score == 0:      rating,color = "SECURE",       "#00ff88"
    elif score <= 10:   rating,color = "LOW RISK",     "#44aaff"
    elif score <= 25:   rating,color = "MEDIUM RISK",  "#ffcc00"
    elif score <= 50:   rating,color = "HIGH RISK",    "#ff8800"
    else:               rating,color = "CRITICAL RISK","#ff2222"

    return {
        "findings": findings, "score": score, "rating": rating, "color": color,
        "critical": sum(1 for f in findings if f["sev"]=="CRITICAL"),
        "high":     sum(1 for f in findings if f["sev"]=="HIGH"),
        "medium":   sum(1 for f in findings if f["sev"]=="MEDIUM"),
        "low":      sum(1 for f in findings if f["sev"]=="LOW"),
    }


# ═══════════════════════════════════════════════
# 14. AI ANALYSIS
# ═══════════════════════════════════════════════
def ai_analyze(results, risk):
    section("AI-ASSISTED ANALYSIS")
    import os
    api_key = os.environ.get("ANTHROPIC_API_KEY","")
    if not api_key:
        warn("ANTHROPIC_API_KEY not set — skipping AI analysis")
        info("To enable: set ANTHROPIC_API_KEY=your_key_here  (Windows CMD)")
        info("           export ANTHROPIC_API_KEY=your_key_here  (Linux/Mac)")
        return {"available":False}

    info("Sending findings to Claude AI for analysis...")
    ctx = {
        "target":          results.get("target"),
        "ip":              results.get("ip"),
        "risk_rating":     risk.get("rating"),
        "risk_score":      risk.get("score"),
        "open_ports":      [f"{p['port']}/tcp ({p['service']})" for p in results.get("ports",[])],
        "technologies":    results.get("http",{}).get("technologies",[]),
        "missing_headers": results.get("http",{}).get("headers_missing",[]),
        "waf":             results.get("waf",{}).get("name","None"),
        "wordpress":       results.get("wordpress",{}).get("is_wp",False),
        "ssl_days_left":   results.get("ssl",{}).get("days_left"),
        "subdomains_count":len(results.get("subdomains",[])),
        "interesting_php": [f["path"] for f in results.get("php",{}).get("interesting",[])],
        "exposed_dirs":    [d["path"] for d in results.get("dirs",{}).get("found",[])[:8]],
        "top_findings":    [f"{f['sev']}: {f['item']}" for f in risk.get("findings",[])[:8]],
    }
    prompt = f"""You are a senior penetration tester reviewing automated recon results.
Target: {ctx['target']}
Data: {json.dumps(ctx, indent=2)}

Respond ONLY in valid JSON (no markdown, no backticks):
{{
  "summary": "2-3 sentence security posture overview",
  "top_attack_vectors": [
    {{"vector": "...", "likelihood": "HIGH/MEDIUM/LOW", "impact": "HIGH/MEDIUM/LOW", "detail": "..."}}
  ],
  "immediate_actions": ["action 1", "action 2", "action 3"],
  "recommendations": [
    {{"title": "...", "detail": "...", "effort": "LOW/MEDIUM/HIGH", "priority": "CRITICAL/HIGH/MEDIUM/LOW"}}
  ],
  "interesting_targets": ["most interesting subdomain/path/port for further testing"]
}}
Keep it technical, specific, max 5 items per list."""

    try:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key":api_key,"anthropic-version":"2023-06-01","content-type":"application/json"},
            json={"model":"claude-sonnet-4-6","max_tokens":1500,
                  "messages":[{"role":"user","content":prompt}]},
            timeout=30,
        )
        if r.status_code == 200:
            raw = r.json()["content"][0]["text"].strip()
            raw = raw.replace("```json","").replace("```","").strip()
            data = json.loads(raw)
            data["available"] = True
            good("AI analysis complete")
            return data
        else:
            bad(f"AI API error: {r.status_code}")
            return {"available":False}
    except Exception as e:
        bad(f"AI analysis failed: {e}")
        return {"available":False}


# ═══════════════════════════════════════════════
# 15. HISTORICAL COMPARISON
# ═══════════════════════════════════════════════
import os, json as _json

HISTORY_DIR = "reconforge_history"

def save_history(results):
    os.makedirs(HISTORY_DIR, exist_ok=True)
    safe = results.get("target","unknown").replace(".","_")
    path = os.path.join(HISTORY_DIR, f"{safe}.json")
    history = []
    if os.path.exists(path):
        with open(path) as f:
            try: history = _json.load(f)
            except Exception: history = []
    history.append({
        "scan_time":     results.get("scan_time"),
        "ip":            results.get("ip"),
        "subdomains":    [s["subdomain"] for s in results.get("subdomains",[])],
        "ports":         [p["port"] for p in results.get("ports",[])],
        "technologies":  results.get("http",{}).get("technologies",[]),
        "headers_missing":results.get("http",{}).get("headers_missing",[]),
        "waf":           results.get("waf",{}).get("name"),
        "ssl_days":      results.get("ssl",{}).get("days_left"),
        "wp_version":    results.get("wordpress",{}).get("version"),
        "php_found":     [f["path"] for f in results.get("php",{}).get("found",[])],
        "dirs_found":    [d["path"] for d in results.get("dirs",{}).get("found",[])],
        "risk_score":    results.get("risk",{}).get("score",0),
        "risk_rating":   results.get("risk",{}).get("rating","N/A"),
    })
    with open(path,"w") as f:
        _json.dump(history, f, indent=2)

def compare_history(domain, current):
    safe = domain.replace(".","_")
    path = os.path.join(HISTORY_DIR, f"{safe}.json")
    if not os.path.exists(path):
        return {"available":False,"reason":"First scan for this target — no history yet"}
    with open(path) as f:
        try: history = _json.load(f)
        except Exception: return {"available":False,"reason":"History file corrupted"}
    if not history:
        return {"available":False,"reason":"No previous scan data"}

    prev = history[-1]
    diff = {"available":True,"prev_time":prev.get("scan_time","?"),
            "new":[],"removed":[],"changed":[]}

    # IP
    if prev.get("ip") != current.get("ip"):
        diff["changed"].append(f"IP address: {prev.get('ip')} → {current.get('ip')} ⚠️ Possible DNS hijack!")

    # Ports
    prev_ports = set(prev.get("ports",[]))
    curr_ports = set(p["port"] for p in current.get("ports",[]))
    for p in curr_ports - prev_ports: diff["new"].append(f"New open port: {p}/tcp")
    for p in prev_ports - curr_ports: diff["removed"].append(f"Port closed: {p}/tcp")

    # Subdomains
    prev_subs = set(prev.get("subdomains",[]))
    curr_subs = set(s["subdomain"] for s in current.get("subdomains",[]))
    for s in curr_subs - prev_subs: diff["new"].append(f"New subdomain: {s}")
    for s in prev_subs - curr_subs: diff["removed"].append(f"Subdomain gone: {s}")

    # Technologies
    prev_tech = set(prev.get("technologies",[]))
    curr_tech = set(current.get("http",{}).get("technologies",[]))
    for t in curr_tech - prev_tech: diff["new"].append(f"New technology: {t}")
    for t in prev_tech - curr_tech: diff["removed"].append(f"Technology removed: {t}")

    # Headers
    prev_miss = set(prev.get("headers_missing",[]))
    curr_miss = set(current.get("http",{}).get("headers_missing",[]))
    for h in curr_miss - prev_miss: diff["new"].append(f"Header now missing: {h} ⚠️")
    for h in prev_miss - curr_miss: diff["changed"].append(f"Header now present (fixed): {h} ✅")

    # WAF
    if prev.get("waf") != current.get("waf",{}).get("name"):
        diff["changed"].append(f"WAF changed: {prev.get('waf','None')} → {current.get('waf',{}).get('name','None')}")

    # SSL expiry
    curr_ssl = current.get("ssl",{}).get("days_left")
    if isinstance(curr_ssl,int) and curr_ssl < 14:
        diff["changed"].append(f"SSL expiring in {curr_ssl} days — URGENT!")

    # WP version
    pv = prev.get("wp_version"); cv = current.get("wordpress",{}).get("version")
    if pv and cv and pv != cv:
        diff["changed"].append(f"WordPress updated: v{pv} → v{cv}")

    # Risk score
    prev_score = prev.get("risk_score",0)
    curr_score = current.get("risk",{}).get("score",0)
    if curr_score != prev_score:
        arrow = "↑ WORSE" if curr_score > prev_score else "↓ BETTER"
        diff["changed"].append(f"Risk score: {prev_score} → {curr_score}  ({arrow})")

    diff["total"] = len(diff["new"]) + len(diff["removed"]) + len(diff["changed"])
    return diff
