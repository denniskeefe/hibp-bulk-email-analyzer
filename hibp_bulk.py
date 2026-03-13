#!/usr/bin/env python3
"""
HIBP Bulk Email Analyzer
========================
Checks multiple email addresses against Have I Been Pwned (v3 API).
Requires a HIBP API key: https://haveibeenpwned.com/API/Key

Usage:
    python hibp_bulk.py -k YOUR_API_KEY -e emails.txt
    python hibp_bulk.py -k YOUR_API_KEY -e "alice@example.com,bob@corp.com"
    python hibp_bulk.py --help
"""

import argparse
import csv
import json
import re
import ssl
import sys
import time
import os
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import quote


# ── SSL Fix (macOS Python.org installs ship without CA certs) ─────────────────
def _make_ssl_context() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        pass
    try:
        return ssl.create_default_context()
    except Exception:
        pass
    print("\033[93m  ⚠ SSL cert verification unavailable. Falling back to unverified context.\033[0m")
    print('\033[93m    Fix: open "/Applications/Python 3.13/Install Certificates.command"\033[0m\n')
    return ssl._create_unverified_context()

_SSL_CTX = _make_ssl_context()


# ── ANSI Colors ───────────────────────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    GRAY   = "\033[90m"

def no_color():
    for attr in vars(C):
        if not attr.startswith('_'):
            setattr(C, attr, '')


# ── Helpers ───────────────────────────────────────────────────────────────────
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')

def extract_emails(text: str) -> list[str]:
    return EMAIL_RE.findall(text)

def load_emails_from_file(path: str) -> list[str]:
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return extract_emails(f.read())

def dedupe(emails: list[str]) -> list[str]:
    seen = set()
    out = []
    for e in emails:
        lo = e.lower()
        if lo not in seen:
            seen.add(lo)
            out.append(lo)
    return out

def fmt_time(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    return f"{seconds/60:.1f}m"

def bar(pct: int, width: int = 30) -> str:
    filled = int(width * pct / 100)
    return f"[{'█' * filled}{'░' * (width - filled)}]"


# ── HIBP API ──────────────────────────────────────────────────────────────────
HIBP_BASE = "https://haveibeenpwned.com/api/v3"

# HIBP enforces separate rate limits per endpoint:
#   /breachedaccount/  ~1 req / 1.5s
#   /pasteaccount/     ~1 req / 3s  (stricter, less documented)
DEFAULT_BREACH_DELAY = 1.6
DEFAULT_PASTE_DELAY  = 3.0
MAX_RETRIES          = 3

def hibp_request(endpoint: str, api_key: str, retry_delay: float = 5.0) -> tuple[int, any]:
    """
    Returns (status_code, data).
    Automatically retries up to MAX_RETRIES times on 429 with exponential backoff.
    """
    url = f"{HIBP_BASE}/{endpoint}"
    req = Request(url, headers={
        "hibp-api-key": api_key,
        "User-Agent": "OSINT-HIBP-BulkAnalyzer/2.0"
    })
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urlopen(req, timeout=15, context=_SSL_CTX) as resp:
                raw = resp.read()
                data = json.loads(raw) if raw else None
                return resp.status, data
        except HTTPError as e:
            if e.code == 429:
                wait = retry_delay * attempt  # 5s, 10s, 15s
                print(f"    {C.YELLOW}↺ Rate limited (attempt {attempt}/{MAX_RETRIES}) — waiting {wait:.0f}s...{C.RESET}")
                time.sleep(wait)
                continue
            return e.code, None
        except URLError as e:
            raise  # network-level errors bubble up immediately
    # All retries exhausted
    return 429, None


def check_email(email: str, api_key: str, check_pastes: bool,
                breach_delay: float, paste_delay: float) -> dict:
    result = {
        "email": email,
        "status": "unknown",
        "breaches": [],
        "breach_count": 0,
        "paste_count": 0,
        "error": None,
        "checked_at": datetime.now().isoformat(timespec='seconds')
    }

    encoded = quote(email, safe='')

    # ── Breach lookup ──────────────────────────────────────────────────────────
    status, data = hibp_request(
        f"breachedaccount/{encoded}?truncateResponse=false",
        api_key,
        retry_delay=breach_delay * 3
    )

    if status == 200 and data:
        result["breaches"] = [b.get("Name", b) if isinstance(b, dict) else b for b in data]
        result["breach_count"] = len(result["breaches"])
        result["status"] = "pwned"
    elif status == 404:
        result["status"] = "safe"
    elif status == 401:
        result["status"] = "error"
        result["error"] = "Unauthorized — check API key"
        return result  # fatal
    elif status == 403:
        result["status"] = "error"
        result["error"] = "Forbidden — API plan may not cover this endpoint"
    elif status == 429:
        result["status"] = "error"
        result["error"] = f"Rate limited after {MAX_RETRIES} retries — try --breach-delay {breach_delay + 1:.0f}"
    else:
        result["status"] = "error"
        result["error"] = f"HTTP {status}"

    # ── Paste lookup ───────────────────────────────────────────────────────────
    if check_pastes and result["status"] in ("pwned", "safe"):
        time.sleep(paste_delay)
        p_status, p_data = hibp_request(
            f"pasteaccount/{encoded}",
            api_key,
            retry_delay=paste_delay * 3
        )
        if p_status == 200 and p_data:
            result["paste_count"] = len(p_data)
        elif p_status == 429:
            result["paste_count"] = -1
            print(f"    {C.YELLOW}⚠ Paste lookup rate limited for {email} — try --paste-delay {paste_delay + 1:.0f}{C.RESET}")
        elif p_status not in (404,):
            result["paste_count"] = -1

    return result


# ── Output ────────────────────────────────────────────────────────────────────
def print_header():
    print(f"\n{C.CYAN}{C.BOLD}{'═' * 60}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  HIBP BULK ANALYZER  //  haveibeenpwned.com v3 API{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{'═' * 60}{C.RESET}\n")

def print_result(r: dict, index: int, total: int):
    if r["status"] == "pwned":
        icon        = f"{C.RED}✗{C.RESET}"
        status_str  = f"{C.RED}{C.BOLD}PWNED{C.RESET}"
        detail      = f"{C.RED}{r['breach_count']} breach{'es' if r['breach_count'] != 1 else ''}{C.RESET}"
        if r["paste_count"] > 0:
            detail += f"{C.GRAY}, {r['paste_count']} pastes{C.RESET}"
    elif r["status"] == "safe":
        icon        = f"{C.GREEN}✓{C.RESET}"
        status_str  = f"{C.GREEN}CLEAN{C.RESET}"
        detail      = f"{C.GRAY}no breaches found{C.RESET}"
    else:
        icon        = f"{C.YELLOW}⚠{C.RESET}"
        status_str  = f"{C.YELLOW}ERROR{C.RESET}"
        detail      = f"{C.YELLOW}{r['error']}{C.RESET}"

    print(f"  {icon} {C.WHITE}{r['email']:<40}{C.RESET} {status_str:<20} {detail}")

    if r["status"] == "pwned" and r["breaches"]:
        breach_list = ", ".join(r["breaches"][:10])
        if len(r["breaches"]) > 10:
            breach_list += f" (+{len(r['breaches']) - 10} more)"
        print(f"    {C.DIM}└─ {breach_list}{C.RESET}")

def print_summary(results: list[dict], elapsed: float):
    total  = len(results)
    pwned  = sum(1 for r in results if r["status"] == "pwned")
    safe   = sum(1 for r in results if r["status"] == "safe")
    errors = sum(1 for r in results if r["status"] == "error")

    print(f"\n{C.CYAN}{'─' * 60}{C.RESET}")
    print(f"{C.BOLD}  SUMMARY{C.RESET}")
    print(f"{C.CYAN}{'─' * 60}{C.RESET}")
    print(f"  Total checked : {C.WHITE}{total}{C.RESET}")
    if total:
        print(f"  Pwned         : {C.RED}{C.BOLD}{pwned}{C.RESET}  ({pwned/total*100:.1f}%)")
    print(f"  Clean         : {C.GREEN}{safe}{C.RESET}")
    print(f"  Errors        : {C.YELLOW}{errors}{C.RESET}")
    print(f"  Elapsed       : {C.GRAY}{fmt_time(elapsed)}{C.RESET}")

    if pwned:
        print(f"\n{C.RED}{C.BOLD}  ⚠ COMPROMISED ADDRESSES:{C.RESET}")
        for r in results:
            if r["status"] == "pwned":
                print(f"    {C.RED}• {r['email']}{C.RESET}")
    print()


# ── Export ────────────────────────────────────────────────────────────────────
def export_csv(results: list[dict], path: str):
    fields = ["email", "status", "breach_count", "paste_count", "breaches", "error", "checked_at"]
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            row = dict(r)
            row["breaches"] = "; ".join(r["breaches"])
            w.writerow({k: row.get(k, '') for k in fields})
    print(f"  {C.CYAN}→ CSV:{C.RESET} {path}")

def export_json(results: list[dict], path: str):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    print(f"  {C.CYAN}→ JSON:{C.RESET} {path}")

def export_pwned_txt(results: list[dict], path: str):
    pwned = [r["email"] for r in results if r["status"] == "pwned"]
    with open(path, 'w') as f:
        f.write("\n".join(pwned))
    print(f"  {C.CYAN}→ Pwned list:{C.RESET} {path} ({len(pwned)} addresses)")


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="HIBP Bulk Email Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python hibp_bulk.py -k MY_KEY -e emails.txt
  python hibp_bulk.py -k MY_KEY -e "alice@x.com,bob@y.com" --no-pastes
  python hibp_bulk.py -k MY_KEY -e emails.txt --out results/ --format all
  python hibp_bulk.py -k MY_KEY -e emails.csv --breach-delay 2 --paste-delay 4
        """
    )
    parser.add_argument('-k', '--key',          required=True,  help='HIBP API key')
    parser.add_argument('-e', '--emails',       required=True,  help='File path OR inline comma-separated list')
    parser.add_argument('--no-pastes',          action='store_true', help='Skip paste lookups (faster, avoids paste rate limit)')
    parser.add_argument('--breach-delay',       type=float, default=DEFAULT_BREACH_DELAY,
                        help=f'Seconds between breach lookups (default: {DEFAULT_BREACH_DELAY})')
    parser.add_argument('--paste-delay',        type=float, default=DEFAULT_PASTE_DELAY,
                        help=f'Seconds between paste lookups (default: {DEFAULT_PASTE_DELAY}, stricter limit)')
    parser.add_argument('--out',                default='.', help='Output directory (default: current dir)')
    parser.add_argument('--format',             choices=['csv', 'json', 'txt', 'all'], default='csv')
    parser.add_argument('--no-color',           action='store_true')
    parser.add_argument('--quiet',              action='store_true', help='Show summary only')
    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        no_color()

    breach_delay = args.breach_delay
    paste_delay  = args.paste_delay

    if os.path.isfile(args.emails):
        emails_raw = load_emails_from_file(args.emails)
        print(f"{C.GRAY}  Loaded: {args.emails}{C.RESET}")
    else:
        emails_raw = extract_emails(args.emails)

    emails = dedupe(emails_raw)
    dupes  = len(emails_raw) - len(emails)

    print_header()
    print(f"  {C.BOLD}Targets:{C.RESET}      {len(emails)} email{'s' if len(emails) != 1 else ''}", end='')
    if dupes:
        print(f" {C.GRAY}({dupes} dupes removed){C.RESET}", end='')
    print()

    per_email = breach_delay + (paste_delay if not args.no_pastes else 0)
    est = len(emails) * per_email
    print(f"  {C.BOLD}Est. time:{C.RESET}    ~{fmt_time(est)}")
    print(f"  {C.BOLD}Breach delay:{C.RESET} {breach_delay}s")
    if not args.no_pastes:
        print(f"  {C.BOLD}Paste delay:{C.RESET}  {paste_delay}s  {C.GRAY}(use --no-pastes to skip){C.RESET}")
    else:
        print(f"  {C.BOLD}Pastes:{C.RESET}       skipped")
    print(f"\n{C.GRAY}{'─' * 60}{C.RESET}\n")

    if not emails:
        print(f"{C.RED}  No valid email addresses found.{C.RESET}\n")
        sys.exit(1)

    results = []
    start   = time.time()

    for i, email in enumerate(emails, 1):
        result = check_email(email, args.key, not args.no_pastes, breach_delay, paste_delay)
        results.append(result)

        if not args.quiet:
            print_result(result, i, len(emails))

        if result.get("error") and "Unauthorized" in str(result.get("error", "")):
            print(f"\n{C.RED}  Fatal: Invalid API key. Aborting.{C.RESET}\n")
            sys.exit(1)

        if i < len(emails):
            time.sleep(breach_delay)

    elapsed = time.time() - start
    print_summary(results, elapsed)

    os.makedirs(args.out, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    print(f"{C.BOLD}  Exports:{C.RESET}")
    if args.format in ('csv', 'all'):
        export_csv(results, os.path.join(args.out, f"hibp_{ts}.csv"))
    if args.format in ('json', 'all'):
        export_json(results, os.path.join(args.out, f"hibp_{ts}.json"))
    if args.format in ('txt', 'all'):
        export_pwned_txt(results, os.path.join(args.out, f"hibp_pwned_{ts}.txt"))
    print()

if __name__ == '__main__':
    main()
