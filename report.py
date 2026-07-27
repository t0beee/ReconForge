"""
ReconForge v1.0 — Report Generator
Saves ONE .txt and ONE .html file with everything inside
"""
from datetime import datetime


SEV_COLOR = {
    "CRITICAL": "#ff2222", "HIGH": "#ff8800",
    "MEDIUM":   "#ffcc00", "LOW":  "#44aaff", "INFO": "#888888",
}

def _txt_divider(char="═", width=65):
    return char * width

def save_txt(results, path):
    R   = results
    div = _txt_divider()
    thn = _txt_divider("─")
    lines = []

    def hdr(title):
        lines.append("")
        lines.append(thn)
        lines.append(f"  ▶  {title}")
        lines.append(thn)

    def row(label, value, indent=4):
        lines.append(f"{' '*indent}{label:<22} {value}")

    # ── Banner ──
    lines += [
        div,
        "  RECONFORGE v1.0 — ATTACK SURFACE REPORT",
        div,
    ]
    row("Target",    R.get("target","N/A"))
    row("IP Address",R.get("ip","N/A"))
    row("Scan Time", R.get("scan_time","N/A"))
    risk = R.get("risk",{})
    row("Risk Rating",f"{risk.get('rating','N/A')}  (score: {risk.get('score',0)})")
    row("Findings",  f"{risk.get('critical',0)} CRITICAL  {risk.get('high',0)} HIGH  {risk.get('medium',0)} MEDIUM  {risk.get('low',0)} LOW")
    lines.append(div)

    # ── Risk Findings ──
    hdr("RISK FINDINGS (Prioritized)")
    if risk.get("findings"):
        for f in risk["findings"]:
            lines.append(f"    [{f['sev']:<8}] {f['cat']}: {f['item']}")
            if f.get("detail"):
                lines.append(f"    {' '*11}→ {f['detail']}")
            lines.append("")
    else:
        lines.append("    No significant risks found.")

    # ── AI Analysis ──
    ai = R.get("ai",{})
    if ai.get("available"):
        hdr("AI-ASSISTED ANALYSIS")
        lines.append(f"    Summary: {ai.get('summary','')}")
        lines.append("")
        lines.append("    Top Attack Vectors:")
        for v in ai.get("top_attack_vectors",[]):
            lines.append(f"      • {v.get('vector','')}  [Likelihood:{v.get('likelihood','')} / Impact:{v.get('impact','')}]")
            lines.append(f"        {v.get('detail','')}")
        lines.append("")
        lines.append("    Immediate Actions:")
        for a in ai.get("immediate_actions",[]):
            lines.append(f"      → {a}")
        lines.append("")
        lines.append("    Recommendations:")
        for rec in ai.get("recommendations",[]):
            lines.append(f"      [{rec.get('priority','')} / Effort:{rec.get('effort','')}] {rec.get('title','')}")
            lines.append(f"        {rec.get('detail','')}")
        lines.append("")
        lines.append("    Interesting Targets for Further Testing:")
        for t in ai.get("interesting_targets",[]):
            lines.append(f"      ★ {t}")

    # ── History diff ──
    diff = R.get("history",{})
    if diff.get("available"):
        hdr(f"CHANGES SINCE LAST SCAN  (prev: {diff.get('prev_time','?')})")
        if diff.get("total",0) == 0:
            lines.append("    ✓ No changes detected since last scan")
        else:
            for item in diff.get("new",[]): lines.append(f"    [NEW]     {item}")
            for item in diff.get("removed",[]): lines.append(f"    [REMOVED] {item}")
            for item in diff.get("changed",[]): lines.append(f"    [CHANGED] {item}")
    else:
        hdr("HISTORICAL COMPARISON")
        lines.append(f"    {diff.get('reason','No history available')}")

    # ── GeoIP ──
    geo = R.get("geoip",{})
    if geo:
        hdr("GEO-IP LOCATION")
        row("Country",  geo.get("country","N/A"))
        row("Region",   geo.get("region","N/A"))
        row("City",     geo.get("city","N/A"))
        row("ISP",      geo.get("isp","N/A"))
        row("Org / ASN",f"{geo.get('org','N/A')}  {geo.get('asn','')}")
        row("Timezone", geo.get("timezone","N/A"))
        row("Hosting",  "Yes — Cloud/Datacenter" if geo.get("hosting") else "No")
        if geo.get("lat") and geo.get("lon"):
            row("Coordinates", f"{geo['lat']}, {geo['lon']}")

    # ── WHOIS ──
    w = R.get("whois",{})
    if w:
        hdr("WHOIS")
        row("Registrar",    w.get("registrar","N/A"))
        row("Created",      w.get("created","N/A"))
        row("Expires",      w.get("expires","N/A"))
        row("Updated",      w.get("updated","N/A"))
        row("Name Servers", ", ".join(w.get("name_servers",[])))
        row("Status",       w.get("status","N/A"))
        row("Org",          w.get("org","N/A"))

    # ── SSL ──
    ssl = R.get("ssl",{})
    if ssl:
        hdr("SSL / TLS CERTIFICATE")
        row("Valid",       str(ssl.get("valid","?")))
        row("Subject",     ssl.get("subject","N/A"))
        row("Issuer",      ssl.get("issuer","N/A"))
        row("Organization",ssl.get("org","N/A"))
        row("Protocol",    ssl.get("protocol","N/A"))
        row("Expires",     f"{ssl.get('expires','N/A')}  ({ssl.get('days_left','?')} days remaining)")
        row("Self-Signed", str(ssl.get("self_signed",False)))
        row("Weak Cipher", str(ssl.get("weak_cipher",False)))
        if ssl.get("san"):
            row("SANs", ", ".join(ssl["san"][:8]))

    # ── WAF ──
    waf = R.get("waf",{})
    if waf:
        hdr("WAF / FIREWALL DETECTION")
        row("Detected", str(waf.get("detected",False)))
        row("Name",     waf.get("name","None"))
        if waf.get("evidence"):
            row("Evidence", ", ".join(waf["evidence"]))

    # ── DNS ──
    dns = R.get("dns",{})
    if dns:
        hdr("DNS RECORDS")
        for rtype, vals in dns.items():
            for v in vals:
                lines.append(f"    {rtype:<8} {v}")

    # ── Subdomains ──
    subs = R.get("subdomains",[])
    hdr(f"SUBDOMAINS  ({len(subs)} found / {len(__import__('wordlists').SUBDOMAINS)} tested)")
    if subs:
        for s in subs:
            lines.append(f"    {s['subdomain']:<50} {s['ip']}")
    else:
        lines.append("    None discovered")

    # ── Ports ──
    ports = R.get("ports",[])
    hdr(f"OPEN PORTS  ({len(ports)} found)")
    if ports:
        lines.append(f"    {'PORT':<10} {'SERVICE':<18} {'RISK':<10} DETAIL")
        lines.append(f"    {_txt_divider('-',58)}")
        for p in ports:
            from wordlists import PORT_REASON
            detail = PORT_REASON.get(p["port"],"")[:40]
            lines.append(f"    {str(p['port'])+'/tcp':<10} {p['service']:<18} {p['risk']:<10} {detail}")
    else:
        lines.append("    No open ports found in scan range")

    # ── HTTP Headers ──
    http = R.get("http",{})
    if http:
        total_h = len(http.get("headers_found",[])) + len(http.get("headers_missing",[]))
        score   = round(len(http.get("headers_found",[]))/total_h*100) if total_h else 0
        hdr(f"HTTP HEADERS  (Security Score: {score}%)")
        row("URL",         http.get("url","N/A"))
        row("Status Code", str(http.get("status_code","N/A")))
        row("Server",      http.get("server","N/A"))
        row("X-Powered-By",http.get("x_powered_by","N/A"))
        lines.append("")
        lines.append("    Header Audit:")
        from wordlists import HEADER_RISK
        for h in http.get("headers_found",[]):
            lines.append(f"      [PRESENT ✓] {h}")
        for h in http.get("headers_missing",[]):
            sev, reason = HEADER_RISK.get(h,("LOW",""))
            lines.append(f"      [MISSING ✗] {h}  [{sev}]")
            lines.append(f"                   → {reason}")
        if http.get("cookies"):
            lines.append("")
            lines.append("    Cookies:")
            for c in http["cookies"]:
                flag_str = ", ".join(c["flags"]) if c["flags"] else "OK"
                lines.append(f"      {c['name']:<30} {flag_str}")

        # Technologies
        hdr("DETECTED TECHNOLOGIES")
        if http.get("technologies"):
            for t in http["technologies"]:
                lines.append(f"    • {t}")
        else:
            lines.append("    None detected")

    # ── Robots.txt ──
    robots = R.get("robots",{})
    if robots:
        hdr("ROBOTS.TXT & SITEMAP")
        row("Found", str(robots.get("found",False)))
        if robots.get("disallowed"):
            lines.append("    Disallowed paths:")
            for p in robots["disallowed"]:
                lines.append(f"      {p}")
        if robots.get("interesting"):
            lines.append("    *** Interesting paths (hidden endpoints):")
            for p in robots["interesting"]:
                lines.append(f"      *** {p}")
        if robots.get("sitemaps"):
            lines.append("    Sitemaps:")
            for s in robots["sitemaps"]:
                lines.append(f"      {s}")

    # ── WordPress ──
    wp = R.get("wordpress",{})
    hdr("WORDPRESS SCAN")
    if wp.get("is_wp"):
        row("Detected",   "YES")
        row("Version",    wp.get("version","Unknown"))
        row("Theme",      wp.get("theme","Unknown"))
        row("XML-RPC",    "ENABLED ⚠️" if wp.get("xmlrpc") else "Disabled")
        row("readme.html","EXPOSED ⚠️" if wp.get("readme") else "Not found")
        if wp.get("plugins"):
            row("Plugins", ", ".join(wp["plugins"]))
        if wp.get("users"):
            lines.append("    Enumerated Users:")
            for u in wp["users"]:
                lines.append(f"      ID {u['id']}: {u['username']}")
        if wp.get("exposed"):
            lines.append("    Exposed WP Paths:")
            for p in wp["exposed"]:
                lines.append(f"      [{p['status']}] {p['path']}")
    else:
        lines.append("    WordPress not detected on this target")

    # ── PHP Enum ──
    php = R.get("php",{})
    if php:
        hdr(f"PHP FILE ENUMERATION  ({len(php.get('found',[]))} found / {php.get('total',0)} tested)")
        if php.get("interesting"):
            lines.append("    *** INTERESTING FILES (potential vulnerabilities):")
            for f in php["interesting"]:
                lines.append(f"      [{f['status']}] {f['path']}  ← {f['url']}")
            lines.append("")
        if php.get("found"):
            lines.append("    All discovered files:")
            for f in php["found"]:
                lines.append(f"      [{f['status']}] {f['path']}")
        else:
            lines.append("    No PHP files found")

    # ── Dirs ──
    dirs = R.get("dirs",{})
    if dirs:
        hdr(f"DIRECTORY BRUTEFORCE  ({len(dirs.get('found',[]))} found / {dirs.get('total',0)} tested)")
        if dirs.get("found"):
            for d in dirs["found"]:
                lines.append(f"    [{d['status']}] /{d['path']}/")
        else:
            lines.append("    No directories found")

    # ── Footer ──
    lines += ["", div,
              "  ReconForge v5.0 — For authorized and ethical use only",
              f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
              div]

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def save_html(results, path):
    R   = results
    risk = R.get("risk",{})
    geo  = R.get("geoip",{})
    ssl  = R.get("ssl",{})
    http = R.get("http",{})
    waf  = R.get("waf",{})
    wp   = R.get("wordpress",{})
    php  = R.get("php",{})
    dirs = R.get("dirs",{})
    ai   = R.get("ai",{})
    diff = R.get("history",{})

    total_h = len(http.get("headers_found",[])) + len(http.get("headers_missing",[]))
    hdr_score = round(len(http.get("headers_found",[]))/total_h*100) if total_h else 0
    risk_color = risk.get("color","#888")
    rating     = risk.get("rating","N/A")

    def badge(sev):
        c = SEV_COLOR.get(sev,"#888")
        return f'<span style="background:{c}22;color:{c};border:1px solid {c};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{sev}</span>'

    def card(title, value, sub="", color="#00ff88"):
        return f'''<div class="card">
          <div class="card-val" style="color:{color}">{value}</div>
          <div class="card-label">{title}</div>
          {"<div class='card-sub'>"+sub+"</div>" if sub else ""}
        </div>'''

    def section_html(title, icon, content):
        return f'''<div class="section">
          <div class="section-hdr"><span class="icon">{icon}</span>{title}</div>
          <div class="section-body">{content}</div>
        </div>'''

    def table(headers, rows, col_colors=None):
        ths = "".join(f"<th>{h}</th>" for h in headers)
        trs = ""
        for row in rows:
            tds = "".join(f'<td style="color:{col_colors[i] if col_colors and i<len(col_colors) else "#c9d1d9"}">{v}</td>'
                          for i,v in enumerate(row))
            trs += f"<tr>{tds}</tr>"
        return f'<table><thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table>'

    # Risk findings table
    findings_rows = [
        [badge(f["sev"]), f["cat"], f["item"], f.get("detail","")]
        for f in risk.get("findings",[])
    ]
    findings_html = table(["Severity","Category","Finding","Detail"], findings_rows) if findings_rows else "<p style='color:#666'>No significant risks found.</p>"

    # AI section
    ai_html = ""
    if ai.get("available"):
        vecs = "".join(f'''<div class="ai-item">
            <span style="color:{SEV_COLOR.get(v.get('likelihood','LOW'),'#888')}">[{v.get('likelihood','?')} likelihood / {v.get('impact','?')} impact]</span>
            <strong>{v.get('vector','')}</strong><br><small>{v.get('detail','')}</small></div>'''
            for v in ai.get("top_attack_vectors",[]))
        actions = "".join(f'<li>{a}</li>' for a in ai.get("immediate_actions",[]))
        recs = "".join(f'''<div class="ai-item">
            {badge(r.get('priority','LOW'))} <strong>{r.get('title','')}</strong> — Effort: {r.get('effort','')}
            <br><small>{r.get('detail','')}</small></div>'''
            for r in ai.get("recommendations",[]))
        targets = "".join(f'<li>★ {t}</li>' for t in ai.get("interesting_targets",[]))
        ai_html = section_html("AI-Assisted Analysis","🤖", f'''
            <p style="color:#c9d1d9;margin-bottom:16px">{ai.get("summary","")}</p>
            <h4 style="color:#58a6ff;margin-bottom:8px">Top Attack Vectors</h4>{vecs}
            <h4 style="color:#58a6ff;margin:16px 0 8px">Immediate Actions</h4><ul style="color:#c9d1d9;padding-left:20px">{actions}</ul>
            <h4 style="color:#58a6ff;margin:16px 0 8px">Recommendations</h4>{recs}
            <h4 style="color:#58a6ff;margin:16px 0 8px">Interesting Targets</h4><ul style="color:#c9d1d9;padding-left:20px">{targets}</ul>
        ''')
    else:
        ai_html = section_html("AI Analysis","🤖",
            '<p style="color:#666">Set ANTHROPIC_API_KEY environment variable to enable AI analysis.</p>')

    # History diff
    if diff.get("available"):
        diff_items = ""
        for item in diff.get("new",[]): diff_items += f'<div class="diff-new">⊕ {item}</div>'
        for item in diff.get("removed",[]): diff_items += f'<div class="diff-rm">⊖ {item}</div>'
        for item in diff.get("changed",[]): diff_items += f'<div class="diff-ch">⟳ {item}</div>'
        diff_html = section_html("Changes Since Last Scan","📅",
            f'<p style="color:#666;margin-bottom:12px">Previous scan: {diff.get("prev_time","?")}</p>' +
            (diff_items if diff.get("total",0) > 0 else '<p style="color:#00ff88">✓ No changes detected</p>'))
    else:
        diff_html = section_html("Historical Comparison","📅",
            f'<p style="color:#666">{diff.get("reason","No history available")}</p>')

    # Subdomains table
    sub_rows = [[s["subdomain"],s["ip"]] for s in R.get("subdomains",[])]
    subs_html = table(["Subdomain","IP Address"], sub_rows) if sub_rows else "<p style='color:#666'>None discovered</p>"

    # Ports table
    from wordlists import PORT_REASON
    port_rows = [[f"{p['port']}/tcp", p["service"], badge(p["risk"]),
                  PORT_REASON.get(p["port"],"")[:60]] for p in R.get("ports",[])]
    ports_html = table(["Port","Service","Risk","Reason"], port_rows) if port_rows else "<p style='color:#666'>No open ports found</p>"

    # Headers table
    from wordlists import HEADER_RISK
    header_rows = (
        [[h, '<span style="color:#00ff88">✓ Present</span>', ""] for h in http.get("headers_found",[])] +
        [[h, badge(HEADER_RISK.get(h,("LOW",""))[0]), HEADER_RISK.get(h,("",""))[1]] for h in http.get("headers_missing",[])]
    )
    hdrs_html = table(["Header","Status","Risk Reason"], header_rows) if header_rows else ""

    # Cookie table
    cookie_rows = [[c["name"], ", ".join(c["flags"]) if c["flags"] else "✓ OK"] for c in http.get("cookies",[])]
    cookie_html = ("<h4 style='color:#58a6ff;margin:16px 0 8px'>Cookies</h4>" +
                   table(["Cookie Name","Issues"], cookie_rows)) if cookie_rows else ""

    # PHP table
    php_rows = [[f['path'], str(f['status']),
                 '<span style="color:#ff8800">⚠ INTERESTING</span>' if f.get("interesting") else ""]
                for f in php.get("found",[])]
    php_html = table(["File","Status","Note"], php_rows) if php_rows else "<p style='color:#666'>No PHP files found</p>"

    # Dir table
    dir_rows = [[f"/{d['path']}/", str(d["status"])] for d in dirs.get("found",[])]
    dirs_html = table(["Directory","Status"], dir_rows) if dir_rows else "<p style='color:#666'>No directories found</p>"

    # WP section
    if wp.get("is_wp"):
        wp_rows = [[p["path"], str(p["status"])] for p in wp.get("exposed",[])]
        wp_paths = table(["Path","Status"], wp_rows) if wp_rows else ""
        user_rows = [[str(u["id"]), u["username"]] for u in wp.get("users",[])]
        wp_users = table(["ID","Username"], user_rows) if user_rows else ""
        wp_body = f'''
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:16px">
              <div class="kv"><span>Version</span><span style="color:#ff8800">{wp.get("version","Unknown")}</span></div>
              <div class="kv"><span>Theme</span><span>{wp.get("theme","Unknown")}</span></div>
              <div class="kv"><span>XML-RPC</span><span style="color:{'#ff4444' if wp.get('xmlrpc') else '#00ff88'}">{'ENABLED ⚠️' if wp.get('xmlrpc') else 'Disabled'}</span></div>
              <div class="kv"><span>readme.html</span><span style="color:{'#ff4444' if wp.get('readme') else '#00ff88'}">{'EXPOSED ⚠️' if wp.get('readme') else 'Not found'}</span></div>
            </div>
            {'<h4 style="color:#58a6ff;margin-bottom:8px">Exposed Paths</h4>'+wp_paths if wp_rows else ""}
            {'<h4 style="color:#58a6ff;margin:16px 0 8px">Enumerated Users</h4>'+wp_users if user_rows else ""}
        '''
        wp_html = section_html("WordPress Scan","🔍", wp_body)
    else:
        wp_html = section_html("WordPress Scan","🔍","<p style='color:#666'>WordPress not detected</p>")

    # DNS table
    dns = R.get("dns",{})
    dns_rows = [[rtype, v] for rtype,vals in dns.items() for v in vals]
    dns_html = table(["Type","Value"], dns_rows) if dns_rows else "<p style='color:#666'>No DNS records found</p>"

    # Geo / WHOIS / SSL kvs
    def kv(label, val):
        return f'<div class="kv"><span>{label}</span><span>{val}</span></div>'

    geo_html = "".join([
        kv("Country",  geo.get("country","N/A")),
        kv("Region",   geo.get("region","N/A")),
        kv("City",     geo.get("city","N/A")),
        kv("ISP",      geo.get("isp","N/A")),
        kv("Org / ASN",f"{geo.get('org','N/A')} {geo.get('asn','')}"),
        kv("Timezone", geo.get("timezone","N/A")),
        kv("Hosting",  "Yes — Cloud/Datacenter" if geo.get("hosting") else "No"),
    ]) if geo else "<p style='color:#666'>GeoIP unavailable</p>"

    wh = R.get("whois",{})
    whois_html = "".join([
        kv("Registrar",    wh.get("registrar","N/A")),
        kv("Created",      wh.get("created","N/A")),
        kv("Expires",      wh.get("expires","N/A")),
        kv("Updated",      wh.get("updated","N/A")),
        kv("Name Servers", ", ".join(wh.get("name_servers",[]))),
        kv("Status",       wh.get("status","N/A")),
        kv("Org",          wh.get("org","N/A")),
    ]) if wh else "<p style='color:#666'>WHOIS unavailable</p>"

    days = ssl.get("days_left","?")
    days_color = "#ff4444" if isinstance(days,int) and days<30 else "#00ff88"
    ssl_html = "".join([
        kv("Valid",        str(ssl.get("valid","?"))),
        kv("Subject",      ssl.get("subject","N/A")),
        kv("Issuer",       ssl.get("issuer","N/A")),
        kv("Organization", ssl.get("org","N/A")),
        kv("Protocol",     ssl.get("protocol","N/A")),
        f'<div class="kv"><span>Expires</span><span style="color:{days_color}">{ssl.get("expires","N/A")} ({days} days)</span></div>',
        kv("Self-Signed",  str(ssl.get("self_signed",False))),
        kv("Weak Cipher",  str(ssl.get("weak_cipher",False))),
    ]) if ssl else "<p style='color:#666'>SSL inspection unavailable</p>"

    waf_html = "".join([
        kv("Detected", str(waf.get("detected",False))),
        kv("Name",     waf.get("name","None")),
        kv("Evidence", ", ".join(waf.get("evidence",[]))),
    ]) if waf else ""

    techs = http.get("technologies",[])
    tech_html = "".join(f'<span class="tech">{t}</span>' for t in techs) if techs else "<span style='color:#666'>None detected</span>"

    robots = R.get("robots",{})
    robot_rows  = [[p, "⚠️ INTERESTING" if p in robots.get("interesting",[]) else ""] for p in robots.get("disallowed",[])]
    robots_html = table(["Disallowed Path","Note"], robot_rows) if robot_rows else "<p style='color:#666'>No entries or not found</p>"

    # HTML ─────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconForge — {R.get('target','')}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0a0a0f;color:#c9d1d9;font-family:'Courier New',monospace;font-size:13px}}
a{{color:#58a6ff}}
.top{{background:linear-gradient(135deg,#0d1117,#161b22);border-bottom:2px solid #00ff88;padding:20px 30px;display:flex;justify-content:space-between;align-items:center}}
.logo{{font-size:22px;font-weight:bold;color:#00ff88;letter-spacing:3px}}.logo span{{color:#58a6ff}}
.meta{{text-align:right;color:#666;font-size:12px;line-height:1.8}}
.meta strong{{color:#c9d1d9}}
.disclaimer{{background:#1a0e00;border:1px solid #664400;border-radius:6px;padding:10px 16px;margin:16px 20px;font-size:12px;color:#997700}}
.cards{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;padding:16px 20px}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center}}
.card:hover{{border-color:#00ff8866}}
.card-val{{font-size:26px;font-weight:bold;margin-bottom:4px}}
.card-label{{font-size:10px;color:#666;text-transform:uppercase;letter-spacing:1px}}
.card-sub{{font-size:10px;color:#444;margin-top:4px}}
.wrap{{max-width:1200px;margin:0 auto;padding:0 20px 40px}}
.section{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:16px;overflow:hidden}}
.section-hdr{{background:#0d1117;padding:12px 18px;border-bottom:1px solid #30363d;display:flex;align-items:center;gap:10px;font-size:13px;font-weight:bold;color:#58a6ff;text-transform:uppercase;letter-spacing:1px}}
.icon{{font-size:16px}}
.section-body{{padding:16px 18px}}
table{{width:100%;border-collapse:collapse;margin-top:4px}}
th{{background:#0d1117;padding:8px 12px;text-align:left;font-size:11px;color:#666;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #30363d}}
td{{padding:9px 12px;border-bottom:1px solid #21262d;vertical-align:top;word-break:break-all}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#1c2128}}
.kv{{display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid #21262d;gap:20px}}
.kv:last-child{{border-bottom:none}}
.kv span:first-child{{color:#666;min-width:130px;flex-shrink:0}}
.kv span:last-child{{color:#c9d1d9;text-align:right;word-break:break-all}}
.tech{{display:inline-block;background:#1c2128;border:1px solid #30363d;color:#c9d1d9;padding:3px 10px;border-radius:20px;font-size:11px;margin:3px}}
.ai-item{{background:#0d1117;border-left:3px solid #58a6ff;padding:10px 14px;margin:8px 0;border-radius:0 6px 6px 0}}
.ai-item small{{color:#666;line-height:1.6}}
.diff-new{{color:#00ff88;padding:5px 0;border-bottom:1px solid #21262d}}
.diff-rm{{color:#ff8800;padding:5px 0;border-bottom:1px solid #21262d}}
.diff-ch{{color:#58a6ff;padding:5px 0;border-bottom:1px solid #21262d}}
h4{{color:#58a6ff;margin:12px 0 8px}}
ul{{padding-left:20px;color:#c9d1d9;line-height:1.8}}
p{{line-height:1.7}}
.footer{{text-align:center;padding:24px;color:#444;font-size:11px;border-top:1px solid #21262d}}
</style>
</head>
<body>
<div class="top">
  <div>
    <div class="logo">RECON<span>FORGE</span> <span style="font-size:14px;color:#666">v5.0</span></div>
    <div style="color:#666;font-size:11px;margin-top:4px">Intelligent Attack Surface Mapper</div>
  </div>
  <div class="meta">
    <div><strong>Target:</strong> {R.get('target','N/A')}</div>
    <div><strong>IP:</strong> {R.get('ip','N/A')}</div>
    <div><strong>Location:</strong> {geo.get('city','?')}, {geo.get('country','?')}</div>
    <div><strong>Scan Time:</strong> {R.get('scan_time','N/A')}</div>
    <div><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
  </div>
</div>
<div class="disclaimer">⚠️ <strong>DISCLAIMER:</strong> This report is for authorized security assessment only. Unauthorized scanning is illegal.</div>

<div class="cards">
  {card("Risk Rating", rating, f"Score: {risk.get('score',0)}", risk_color)}
  {card("Subdomains", len(R.get('subdomains',[])), "discovered", "#58a6ff")}
  {card("Open Ports", len(R.get('ports',[])), "of 20 scanned", "#ff8800")}
  {card("Sec Headers", f"{hdr_score}%", f"{len(http.get('headers_missing',[]))} missing", "#00ff88" if hdr_score>=70 else "#ffcc00" if hdr_score>=40 else "#ff4444")}
  {card("Technologies", len(http.get('technologies',[])), "detected", "#cc99ff")}
  {card("SSL Days", ssl.get('days_left','N/A'), ssl.get('expires',''), "#00ff88" if isinstance(ssl.get('days_left'),int) and ssl['days_left']>30 else "#ff4444")}
</div>

<div class="wrap">
  {section_html("Risk Findings","⚠️", findings_html)}
  {ai_html}
  {diff_html}
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
    {section_html("Geo-IP Location","🌍", geo_html)}
    {section_html("WHOIS","📋", whois_html)}
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
    {section_html("SSL Certificate","🔐", ssl_html)}
    {section_html("WAF Detection","🛡️", waf_html)}
  </div>
  {section_html("DNS Records","📡", dns_html)}
  {section_html(f"Subdomains ({len(R.get('subdomains',[]))} found)","🌐", subs_html)}
  {section_html(f"Open Ports ({len(R.get('ports',[]))} found)","🔌", ports_html)}
  {section_html(f"Security Headers (Score: {hdr_score}%)","🔒", hdrs_html + cookie_html)}
  {section_html("Technologies","⚙️", f'<div style="padding:8px 0">{tech_html}</div>')}
  {section_html("robots.txt & Sitemap","🤖", robots_html)}
  {wp_html}
  {section_html(f"PHP Enumeration ({len(php.get('found',[]))} found)","🐘", php_html)}
  {section_html(f"Directory Bruteforce ({len(dirs.get('found',[]))} found)","📁", dirs_html)}
</div>
<div class="footer">Generated by <strong style="color:#00ff88">ReconForge v1.0</strong> — For authorized security assessments only</div>
</body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
