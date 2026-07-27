#!/usr/bin/env python3
"""
ReconForge v1.0 — Intelligent Attack Surface Mapper
Usage: python reconforge.py <domain> [options]
"""

import sys, os, argparse, json
from datetime import datetime
from colorama import Fore, Style, init

from scanner import (
    resolve, get_dns_records, geoip, whois_lookup, inspect_ssl,
    detect_waf, enumerate_subdomains, scan_ports, check_http,
    parse_robots, wordpress_scan, php_enumeration, directory_brute,
    score_risk, ai_analyze, save_history, compare_history,
    section, info, good, warn, bad,
)
from report import save_txt, save_html

init(autoreset=True)
VERSION = "1.0.0"

BANNER = f"""
{Fore.CYAN}
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
{Fore.YELLOW}               Intelligent Attack Surface Mapper  v{VERSION}
{Fore.GREEN}        -s Subdomains  -p Ports  -w WHOIS  -d Dirs  --all Full Scan
{Fore.CYAN}        Risk Scoring · AI Analysis · History · Async · Plugins
{Style.RESET_ALL}"""


def run(domain, args):
    silent = getattr(args, "silent", False)
    timeout= getattr(args, "timeout", 3.0)
    delay  = getattr(args, "delay",   0.0)

    if not silent:
        print(BANNER)
        print(f"  {Fore.YELLOW}[!] For authorized and ethical use only.{Style.RESET_ALL}\n")

    # Resolve
    ip = resolve(domain, timeout)
    if not ip:
        bad(f"Cannot resolve domain: {domain}")
        sys.exit(1)

    if not silent:
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Target   : {Fore.CYAN}{domain}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} IP       : {Fore.CYAN}{ip}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Started  : {Fore.CYAN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")

    results = {
        "target":    domain,
        "ip":        ip,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "dns":  {}, "geoip": {}, "whois": {}, "ssl":  {},
        "waf":  {}, "subdomains": [], "ports": [], "http": {},
        "robots":{}, "wordpress":{}, "php":   {}, "dirs": {},
        "risk": {}, "ai":    {}, "history": {},
    }

    # Determine which modules to run
    run_all   = getattr(args, "all", False)
    run_subs  = run_all or getattr(args, "subdomains", False)
    run_ports = run_all or getattr(args, "ports",      False)
    run_whois = run_all or getattr(args, "whois",      False)
    run_dirs  = run_all or getattr(args, "dirs",       False)
    run_waf   = run_all or getattr(args, "waf",        False)
    run_ssl   = run_all or getattr(args, "ssl",        False)
    run_geo   = run_all or getattr(args, "geoip",      False)
    run_rob   = run_all or getattr(args, "robots",     False)
    run_wp    = run_all or getattr(args, "wordpress",  False)
    run_php   = run_all or getattr(args, "php",        False)
    run_http  = run_all

    # If no module flag at all — run everything
    no_flag = not any([run_subs, run_ports, run_whois, run_dirs,
                       run_waf, run_ssl, run_geo, run_rob, run_wp, run_php])
    if no_flag:
        run_all=run_subs=run_ports=run_whois=run_dirs=True
        run_waf=run_ssl=run_geo=run_rob=run_wp=run_php=run_http=True

    import time

    # History diff — check BEFORE scan
    if not getattr(args,"no_history",False):
        results["history"] = compare_history(domain, results)
        if not silent:
            diff = results["history"]
            if diff.get("available"):
                section("HISTORICAL COMPARISON")
                if diff.get("total",0) == 0:
                    good("No changes since last scan")
                else:
                    for item in diff.get("new",[]): good(f"[NEW]     {item}")
                    for item in diff.get("removed",[]): warn(f"[REMOVED] {item}")
                    for item in diff.get("changed",[]): warn(f"[CHANGED] {item}")
            else:
                section("HISTORICAL COMPARISON")
                info(diff.get("reason",""))

    if run_all:
        results["dns"] = get_dns_records(domain)
        if delay: time.sleep(delay)

    if run_geo:
        results["geoip"] = geoip(ip)
        if delay: time.sleep(delay)

    if run_whois:
        results["whois"] = whois_lookup(domain)
        if delay: time.sleep(delay)

    if run_ssl:
        results["ssl"] = inspect_ssl(domain)
        if delay: time.sleep(delay)

    if run_waf:
        results["waf"] = detect_waf(domain)
        if delay: time.sleep(delay)

    if run_subs:
        results["subdomains"] = enumerate_subdomains(domain, timeout)
        if delay: time.sleep(delay)

    if run_ports:
        results["ports"] = scan_ports(ip, timeout)
        if delay: time.sleep(delay)

    if run_http:
        results["http"] = check_http(domain, timeout)
        if delay: time.sleep(delay)

    if run_rob:
        results["robots"] = parse_robots(domain)
        if delay: time.sleep(delay)

    if run_wp:
        results["wordpress"] = wordpress_scan(domain)
        if delay: time.sleep(delay)

    if run_php:
        results["php"] = php_enumeration(domain)
        if delay: time.sleep(delay)

    if run_dirs:
        results["dirs"] = directory_brute(domain)

    # Risk scoring — always runs
    section("RISK SCORING")
    results["risk"] = score_risk(results)
    risk = results["risk"]
    color = {
        "CRITICAL RISK":"CRITICAL","HIGH RISK":"HIGH",
        "MEDIUM RISK":"MEDIUM","LOW RISK":"LOW","SECURE":"INFO"
    }
    sev_colors = {
        "CRITICAL":Fore.RED,"HIGH":Fore.YELLOW,
        "MEDIUM":Fore.CYAN,"LOW":Fore.WHITE,"INFO":Fore.GREEN
    }
    rating_color = sev_colors.get(color.get(risk.get("rating",""),"INFO"), Fore.WHITE)
    good(f"Risk Rating : {rating_color}{risk.get('rating','N/A')}{Style.RESET_ALL}  (score: {risk.get('score',0)})")
    good(f"Findings    : {Fore.RED}{risk.get('critical',0)} CRITICAL{Style.RESET_ALL}  "
         f"{Fore.YELLOW}{risk.get('high',0)} HIGH{Style.RESET_ALL}  "
         f"{Fore.CYAN}{risk.get('medium',0)} MEDIUM{Style.RESET_ALL}  "
         f"{Fore.WHITE}{risk.get('low',0)} LOW{Style.RESET_ALL}")

    # AI analysis
    if not getattr(args,"no_ai",False):
        results["ai"] = ai_analyze(results, risk)

    # Save history
    if not getattr(args,"no_history",False):
        save_history(results)

    # Output — ONE txt + ONE html
    base = getattr(args,"output",None) or f"reconforge_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    base = base.rstrip(".txt").rstrip(".html")

    txt_path  = base + ".txt"
    html_path = base + ".html"

    save_txt(results,  txt_path)
    save_html(results, html_path)

    section("SCAN COMPLETE")
    good(f"TXT  report → {txt_path}")
    good(f"HTML report → {html_path}")

    if getattr(args,"json",False):
        json_path = base + ".json"
        with open(json_path,"w") as f:
            json.dump(results, f, indent=2, default=str)
        good(f"JSON        → {json_path}")

    return results


def main():
    parser = argparse.ArgumentParser(
        prog="reconforge",
        description=f"ReconForge v{VERSION} — Intelligent Attack Surface Mapper",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  python reconforge.py example.com --all
  python reconforge.py example.com -s -p
  python reconforge.py example.com -w --ssl --waf
  python reconforge.py example.com --all --silent -o report
  python reconforge.py --file targets.txt --all"""
    )

    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("domain", nargs="?", help="Target domain (e.g. example.com)")
    grp.add_argument("-f","--file", metavar="FILE", help="File with one domain per line")

    mods = parser.add_argument_group("Scan Modules")
    mods.add_argument("--all",       action="store_true", help="Run ALL modules (full scan)")
    mods.add_argument("-s","--subdomains", action="store_true", help="Subdomain enumeration (200+ wordlist)")
    mods.add_argument("-p","--ports",      action="store_true", help="Port scan (top 20 ports)")
    mods.add_argument("-w","--whois",      action="store_true", help="WHOIS lookup")
    mods.add_argument("-d","--dirs",       action="store_true", help="Directory bruteforce (100+ dirs)")
    mods.add_argument("--waf",       action="store_true", help="WAF/firewall detection")
    mods.add_argument("--ssl",       action="store_true", help="SSL/TLS certificate inspection")
    mods.add_argument("--geoip",     action="store_true", help="GeoIP location lookup")
    mods.add_argument("--robots",    action="store_true", help="robots.txt & sitemap parser")
    mods.add_argument("--wordpress", action="store_true", help="WordPress deep scanner")
    mods.add_argument("--php",       action="store_true", help="PHP file enumeration (60+ files)")

    opts = parser.add_argument_group("Options")
    opts.add_argument("-o","--output",   metavar="NAME",  help="Output base name (e.g. -o myreport)")
    opts.add_argument("--timeout", type=float, default=3.0, metavar="SEC", help="Timeout in seconds (default: 3)")
    opts.add_argument("--delay",   type=float, default=0.0, metavar="SEC", help="Delay between requests — stealth mode (default: 0)")
    opts.add_argument("--silent",  action="store_true", help="Silent mode — no banner, minimal output")
    opts.add_argument("--json",    action="store_true", help="Also save JSON output")
    opts.add_argument("--no-ai",   action="store_true", dest="no_ai",      help="Skip AI analysis")
    opts.add_argument("--no-history",action="store_true",dest="no_history",help="Skip historical comparison")
    opts.add_argument("--version", action="version", version=f"ReconForge v{VERSION}")

    args = parser.parse_args()

    if args.file:
        if not os.path.exists(args.file):
            bad(f"File not found: {args.file}")
            sys.exit(1)
        with open(args.file) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        if not args.silent:
            print(BANNER)
            info(f"Multi-target mode: {len(targets)} targets loaded from {args.file}")
        for i, target in enumerate(targets,1):
            if not args.silent:
                print(f"\n{Fore.CYAN}[{i}/{len(targets)}] Scanning: {target}{Style.RESET_ALL}")
            orig = args.output
            if args.output:
                args.output = f"{args.output}_{target}"
            run(target, args)
            args.output = orig
    else:
        run(args.domain, args)


if __name__ == "__main__":
    main()
