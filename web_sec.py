#!/usr/bin/env python3
"""
WebSec Education & Recon Tool
A Python-based ethical web security learning tool.
"""

import sys
import time
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich import box
from rich.columns import Columns
from rich.rule import Rule

console = Console()

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────
SECURITY_KEYWORDS = [
    "vulnerability", "CVE", "exploit", "breach", "malware",
    "ransomware", "zero-day", "phishing", "injection", "XSS",
    "backdoor", "hack", "security", "patch", "disclosure"
]

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HN_TOP_STORIES = "https://hacker-news.firebaseio.com/v0/topstories.json"
HN_ITEM = "https://hacker-news.firebaseio.com/v0/item/{}.json"

COMMON_SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/wp-config.php", "/config.php",
    "/admin", "/admin/login", "/phpmyadmin", "/backup.zip",
    "/db.sql", "/robots.txt", "/sitemap.xml", "/.htaccess",
    "/server-status", "/elmah.axd", "/trace.axd",
    "/api/swagger", "/swagger.json", "/openapi.json",
]

SECURITY_HEADERS = {
    "Content-Security-Policy": "Prevents XSS and data injection attacks",
    "X-Frame-Options": "Prevents clickjacking attacks",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "Strict-Transport-Security": "Enforces HTTPS (HSTS)",
    "Referrer-Policy": "Controls referrer information leakage",
    "Permissions-Policy": "Controls browser feature access",
    "X-XSS-Protection": "Legacy XSS filter (deprecated but informative)",
    "Cache-Control": "Controls caching of sensitive pages",
}


# ─────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────
def banner():
    console.print(Panel.fit(
        "[bold cyan]██╗    ██╗███████╗██████╗ ███████╗███████╗ ██████╗[/bold cyan]\n"
        "[bold cyan]██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝[/bold cyan]\n"
        "[bold cyan]██║ █╗ ██║█████╗  ██████╔╝███████╗█████╗  ██║[/bold cyan]\n"
        "[bold cyan]██║███╗██║██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║[/bold cyan]\n"
        "[bold cyan]╚███╔███╔╝███████╗██████╔╝███████║███████╗╚██████╗[/bold cyan]\n"
        "[bold cyan] ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝[/bold cyan]\n\n"
        "[bold green]  Web Security Education & Reconnaissance Tool[/bold green]\n"
        "[dim]  For ethical, authorized testing and learning only[/dim]",
        title="[bold yellow]⚡ WebSec Tool v1.0[/bold yellow]",
        border_style="cyan"
    ))


def ethical_disclaimer():
    console.print()
    console.print(Panel(
        "[bold red]⚠  IMPORTANT ETHICAL DISCLAIMER ⚠[/bold red]\n\n"
        "This tool is intended [bold]ONLY[/bold] for:\n"
        "  • Systems you [bold green]own[/bold green]\n"
        "  • Systems you have [bold green]explicit written permission[/bold green] to test\n"
        "  • Educational environments & CTF challenges\n\n"
        "[bold yellow]Unauthorized scanning is illegal under computer fraud laws[/bold yellow]\n"
        "[dim](e.g. CFAA in the US, Computer Misuse Act in the UK)[/dim]\n\n"
        "The authors accept [bold red]no liability[/bold red] for misuse of this tool.",
        title="[bold red]Legal Notice[/bold red]",
        border_style="red"
    ))
    console.print()
    if not Confirm.ask("[bold yellow]Do you confirm you have permission to use this tool on your target?[/bold yellow]"):
        console.print("[red]Exiting. Please only test systems you own or have permission to test.[/red]")
        sys.exit(0)


def get_headers():
    return {
        "User-Agent": "WebSecEduTool/1.0 (Educational Security Scanner; contact your admin)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }


def safe_get(url, timeout=10, **kwargs):
    try:
        return requests.get(url, headers=get_headers(), timeout=timeout, allow_redirects=False, **kwargs)
    except requests.exceptions.SSLError:
        try:
            return requests.get(url, headers=get_headers(), timeout=timeout, allow_redirects=False, verify=False, **kwargs)
        except Exception:
            return None
    except Exception:
        return None


# ─────────────────────────────────────────────
# FEATURE 1: VULNERABILITY SCANNER
# ─────────────────────────────────────────────
def check_security_headers(response, results):
    """Check for missing or misconfigured security headers."""
    findings = []
    for header, description in SECURITY_HEADERS.items():
        if header.lower() not in [k.lower() for k in response.headers.keys()]:
            findings.append(("MISSING", header, description))
        else:
            val = response.headers.get(header, "")
            findings.append(("PRESENT", header, val[:60] + "..." if len(val) > 60 else val))
    results["headers"] = findings

    # Check clickjacking specifically
    xfo = response.headers.get("X-Frame-Options", "")
    csp = response.headers.get("Content-Security-Policy", "")
    if not xfo and "frame-ancestors" not in csp.lower():
        results["clickjacking"] = True
    else:
        results["clickjacking"] = False


def check_sensitive_files(base_url, results):
    """Check for exposed sensitive files/paths."""
    exposed = []
    with Progress(SpinnerColumn(), TextColumn("[cyan]Checking sensitive paths..."), transient=True) as p:
        p.add_task("scan")
        for path in COMMON_SENSITIVE_PATHS:
            url = urljoin(base_url, path)
            resp = safe_get(url, timeout=6)
            if resp and resp.status_code in (200, 301, 302, 403):
                exposed.append((path, resp.status_code, "⚠ Accessible" if resp.status_code == 200 else f"Redirects/Forbidden ({resp.status_code})"))
            time.sleep(0.05)
    results["sensitive_files"] = exposed


def check_xss_reflections(url, response, results):
    """Basic reflected XSS probe (non-destructive)."""
    parsed = urlparse(url)
    if parsed.query:
        probe = "<script>alert(1)</script>"
        params = {}
        for part in parsed.query.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                params[k] = probe
        test_url = parsed._replace(query="&".join(f"{k}={v}" for k, v in params.items())).geturl()
        resp = safe_get(test_url)
        if resp and probe in resp.text:
            results["xss"] = ("LIKELY VULNERABLE", test_url)
        else:
            results["xss"] = ("Not obviously reflected", test_url)
    else:
        results["xss"] = ("No query params to test", url)


def check_sql_injection_hints(url, response, results):
    """Passive SQLi indicator check — look for error messages in page."""
    sql_errors = [
        "you have an error in your sql syntax",
        "warning: mysql", "unclosed quotation mark",
        "odbc driver", "ora-01756", "postgresql error",
        "microsoft ole db", "syntax error", "sqlstate",
    ]
    body = response.text.lower()
    found = [e for e in sql_errors if e in body]
    results["sqli_hints"] = found


def check_csrf(response, results):
    """Check for CSRF tokens in forms."""
    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")
    csrf_findings = []
    for form in forms:
        action = form.get("action", "(no action)")
        inputs = form.find_all("input")
        has_csrf = any(
            "csrf" in (inp.get("name", "") + inp.get("id", "")).lower()
            for inp in inputs
        )
        method = form.get("method", "GET").upper()
        csrf_findings.append((action[:50], method, "✓ Token found" if has_csrf else "✗ No CSRF token"))
    results["csrf"] = csrf_findings


def check_open_redirect(base_url, results):
    """Test for open redirect via common parameters."""
    redirect_params = ["redirect", "url", "next", "return", "goto", "dest", "target"]
    test_url_val = "https://evil-example.com"
    parsed = urlparse(base_url)
    findings = []
    for param in redirect_params:
        test = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={test_url_val}"
        resp = safe_get(test)
        if resp:
            loc = resp.headers.get("Location", "")
            if "evil-example.com" in loc:
                findings.append((param, "⚠ OPEN REDIRECT DETECTED", test))
            else:
                findings.append((param, "OK", ""))
    results["open_redirect"] = findings


def check_server_info(response, results):
    """Extract server version info that may be outdated."""
    server = response.headers.get("Server", "Not disclosed")
    x_powered = response.headers.get("X-Powered-By", "Not disclosed")
    results["server_info"] = {"Server": server, "X-Powered-By": x_powered}


def run_vulnerability_scanner():
    console.print()
    console.rule("[bold cyan]🔍 Vulnerability Scanner[/bold cyan]")
    target = Prompt.ask("[bold]Enter target URL[/bold] (e.g. https://example.com)")

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    if not Confirm.ask(f"[yellow]Confirm you own or have permission to scan[/yellow] [bold]{target}[/bold]?"):
        console.print("[red]Scan cancelled.[/red]")
        return

    console.print(f"\n[cyan]Scanning[/cyan] [bold]{target}[/bold]...\n")

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True) as p:
        t = p.add_task("Fetching page...", total=None)
        response = safe_get(target)
        p.update(t, description="Done")

    if not response:
        console.print("[red]Failed to connect to target. Please check the URL and your network.[/red]")
        return

    results = {}
    check_security_headers(response, results)
    check_xss_reflections(target, response, results)
    check_sql_injection_hints(target, response, results)
    check_csrf(response, results)
    check_open_redirect(target, results)
    check_server_info(response, results)
    check_sensitive_files(target, results)

    # ── Print Results ──────────────────────────
    console.print()
    console.print(Rule("[bold cyan]Scan Results[/bold cyan]"))

    # Security Headers
    console.print()
    console.print("[bold yellow]📋 Security Headers[/bold yellow]")
    htable = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
    htable.add_column("Status", width=10)
    htable.add_column("Header", width=35)
    htable.add_column("Value / Note", width=55)
    for status, header, note in results.get("headers", []):
        color = "green" if status == "PRESENT" else "red"
        icon = "✓" if status == "PRESENT" else "✗"
        htable.add_row(f"[{color}]{icon} {status}[/{color}]", header, note)
    console.print(htable)

    # Server Info
    console.print()
    si = results.get("server_info", {})
    server_text = f"[cyan]Server:[/cyan] {si.get('Server')}  |  [cyan]X-Powered-By:[/cyan] {si.get('X-Powered-By')}"
    console.print(Panel(server_text, title="[bold]Server Fingerprint[/bold]", border_style="dim"))

    # XSS
    console.print()
    xss_status, xss_url = results.get("xss", ("N/A", ""))
    xss_color = "red" if "LIKELY" in xss_status else "green"
    console.print(Panel(
        f"[{xss_color}]{xss_status}[/{xss_color}]\n[dim]{xss_url}[/dim]",
        title="[bold]🔴 Reflected XSS Check[/bold]", border_style=xss_color
    ))

    # SQLi
    console.print()
    sqli = results.get("sqli_hints", [])
    sqli_color = "red" if sqli else "green"
    sqli_text = "\n".join(f"  • {e}" for e in sqli) if sqli else "No SQL error strings detected in response."
    console.print(Panel(sqli_text, title="[bold]💉 SQL Injection Hints[/bold]", border_style=sqli_color))

    # CSRF
    console.print()
    csrf_data = results.get("csrf", [])
    if csrf_data:
        ctable = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta")
        ctable.add_column("Form Action", width=40)
        ctable.add_column("Method", width=8)
        ctable.add_column("CSRF Token", width=20)
        for action, method, tok in csrf_data:
            color = "green" if "Token found" in tok else "red"
            ctable.add_row(action, method, f"[{color}]{tok}[/{color}]")
        console.print(Panel(ctable, title="[bold]🛡  CSRF Form Analysis[/bold]", border_style="cyan"))
    else:
        console.print(Panel("[dim]No forms found on page.[/dim]", title="[bold]🛡  CSRF[/bold]", border_style="dim"))

    # Clickjacking
    console.print()
    cj = results.get("clickjacking", False)
    console.print(Panel(
        "[red]⚠ No X-Frame-Options or CSP frame-ancestors set — CLICKJACKING POSSIBLE[/red]" if cj
        else "[green]✓ Clickjacking protection present[/green]",
        title="[bold]🖱  Clickjacking[/bold]",
        border_style="red" if cj else "green"
    ))

    # Open Redirect
    console.print()
    or_data = results.get("open_redirect", [])
    if or_data:
        ortable = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta")
        ortable.add_column("Param", width=15)
        ortable.add_column("Result", width=35)
        for param, status, _ in or_data:
            color = "red" if "REDIRECT" in status else "dim"
            ortable.add_row(param, f"[{color}]{status}[/{color}]")
        console.print(Panel(ortable, title="[bold]↪  Open Redirect Check[/bold]", border_style="cyan"))

    # Sensitive Files
    console.print()
    sf = results.get("sensitive_files", [])
    accessible = [x for x in sf if x[1] == 200]
    if accessible:
        sftable = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta")
        sftable.add_column("Path", width=30)
        sftable.add_column("Status", width=8)
        sftable.add_column("Note", width=25)
        for path, code, note in sf:
            color = "red" if code == 200 else "yellow"
            sftable.add_row(f"[{color}]{path}[/{color}]", str(code), note)
        console.print(Panel(sftable, title="[bold]📂 Sensitive File Exposure[/bold]", border_style="red"))
    else:
        console.print(Panel(
            f"[green]No obviously exposed sensitive files found.[/green]\n"
            f"[dim]Checked {len(COMMON_SENSITIVE_PATHS)} paths.[/dim]",
            title="[bold]📂 Sensitive File Exposure[/bold]", border_style="green"
        ))

    console.print()
    console.print("[dim]Scan complete. Always verify findings manually before reporting.[/dim]")


# ─────────────────────────────────────────────
# FEATURE 2: SECURITY NEWS FEED
# ─────────────────────────────────────────────
def fetch_hn_security_news(limit=10):
    console.print()
    console.rule("[bold cyan]📰 Security News Feed (Hacker News)[/bold cyan]")

    with Progress(SpinnerColumn(), TextColumn("[cyan]Fetching top stories..."), transient=True) as p:
        p.add_task("fetch")
        try:
            resp = requests.get(HN_TOP_STORIES, timeout=10)
            story_ids = resp.json()[:100]
        except Exception as e:
            console.print(f"[red]Error fetching stories: {e}[/red]")
            return

    security_stories = []
    with Progress(SpinnerColumn(), TextColumn("[cyan]Filtering for security topics..."), transient=True) as p:
        t = p.add_task("filter", total=None)
        for sid in story_ids:
            if len(security_stories) >= limit:
                break
            try:
                r = requests.get(HN_ITEM.format(sid), timeout=6)
                item = r.json()
                if not item:
                    continue
                title = item.get("title", "").lower()
                if any(kw.lower() in title for kw in SECURITY_KEYWORDS):
                    security_stories.append(item)
            except Exception:
                pass
            time.sleep(0.02)

    if not security_stories:
        console.print("[yellow]No security-related stories found in current top 100. Try again later.[/yellow]")
        return

    table = Table(
        title=f"[bold cyan]Top {len(security_stories)} Security Stories on Hacker News[/bold cyan]",
        box=box.ROUNDED, show_lines=True, header_style="bold magenta"
    )
    table.add_column("#", width=4, justify="right")
    table.add_column("Title", width=60)
    table.add_column("Score", width=7, justify="right")
    table.add_column("Comments", width=10, justify="right")
    table.add_column("Link", width=40)

    for i, story in enumerate(security_stories, 1):
        title = story.get("title", "N/A")
        score = str(story.get("score", "?"))
        comments = str(story.get("descendants", 0))
        url = story.get("url", f"https://news.ycombinator.com/item?id={story.get('id')}")
        table.add_row(str(i), title, f"[yellow]{score}[/yellow]", f"[cyan]{comments}[/cyan]", f"[dim]{url[:38]}[/dim]")

    console.print()
    console.print(table)
    console.print(f"\n[dim]Filtered from HN top 100 using security keywords: {', '.join(SECURITY_KEYWORDS[:6])}...[/dim]")


# ─────────────────────────────────────────────
# FEATURE 3: CVE DATABASE BROWSER
# ─────────────────────────────────────────────
CVE_PRESETS = {
    "1": ("XSS (Cross-Site Scripting)", "XSS"),
    "2": ("SQL Injection", "SQL Injection"),
    "3": ("Remote Code Execution", "Remote Code Execution"),
    "4": ("CSRF", "CSRF"),
    "5": ("Buffer Overflow", "Buffer Overflow"),
    "6": ("Path Traversal", "Path Traversal"),
    "7": ("SSRF", "Server-Side Request Forgery"),
    "8": ("Custom keyword", None),
}


def fetch_cves(keyword, results_per_page=10):
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
        "startIndex": 0,
    }
    try:
        resp = requests.get(NVD_API_BASE, params=params, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        else:
            console.print(f"[red]NVD API returned status {resp.status_code}[/red]")
            return None
    except Exception as e:
        console.print(f"[red]Error querying NVD: {e}[/red]")
        return None


def parse_cvss_score(cve_item):
    """Extract CVSS score from CVE metrics."""
    metrics = cve_item.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            score = m.get("cvssData", {}).get("baseScore", "N/A")
            severity = m.get("cvssData", {}).get("baseSeverity", m.get("baseSeverity", "?"))
            return score, severity
    return "N/A", "N/A"


def severity_color(severity):
    s = str(severity).upper()
    return {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green"}.get(s, "white")


def browse_cve_database():
    console.print()
    console.rule("[bold cyan]🛡  CVE Database Browser (NVD)[/bold cyan]")
    console.print()

    console.print("[bold]Choose a vulnerability type to explore:[/bold]")
    for k, (label, _) in CVE_PRESETS.items():
        console.print(f"  [cyan]{k}[/cyan]. {label}")

    choice = Prompt.ask("\n[bold]Enter choice[/bold]", choices=list(CVE_PRESETS.keys()), default="1")
    label, keyword = CVE_PRESETS[choice]

    if keyword is None:
        keyword = Prompt.ask("[bold]Enter custom keyword[/bold]")
        label = keyword

    count_str = Prompt.ask("[bold]How many CVEs to display?[/bold]", default="10")
    try:
        count = max(1, min(int(count_str), 20))
    except ValueError:
        count = 10

    console.print(f"\n[cyan]Querying NVD for:[/cyan] [bold]{keyword}[/bold]...\n")

    with Progress(SpinnerColumn(), TextColumn("[cyan]Fetching CVE data from NVD API..."), transient=True) as p:
        p.add_task("query")
        data = fetch_cves(keyword, count)

    if not data:
        return

    vuln_list = data.get("vulnerabilities", [])
    total = data.get("totalResults", 0)

    if not vuln_list:
        console.print("[yellow]No CVEs found for this query.[/yellow]")
        return

    console.print(f"[green]Found[/green] [bold]{total:,}[/bold] total CVEs. Showing top {len(vuln_list)}:\n")

    table = Table(
        title=f"[bold cyan]CVEs related to: {label}[/bold cyan]",
        box=box.ROUNDED, show_lines=True, header_style="bold magenta"
    )
    table.add_column("CVE ID", width=18, style="bold cyan")
    table.add_column("CVSS", width=7, justify="center")
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Published", width=12)
    table.add_column("Description", width=70)

    for vuln in vuln_list:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "N/A")
        published = cve.get("published", "")[:10]
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "No description")
        desc = desc[:160] + "..." if len(desc) > 160 else desc
        score, severity = parse_cvss_score(cve)
        sc = severity_color(severity)
        table.add_row(
            cve_id,
            f"[{sc}]{score}[/{sc}]",
            f"[bold {sc}]{severity}[/bold {sc}]",
            published,
            desc
        )

    console.print(table)
    console.print(f"\n[dim]Data sourced from National Vulnerability Database (NVD) — nvd.nist.gov[/dim]")
    console.print(f"[dim]CVE details: https://nvd.nist.gov/vuln/detail/<CVE-ID>[/dim]")


# ─────────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────────
def main_menu():
    while True:
        console.print()
        console.rule("[bold cyan]Main Menu[/bold cyan]")
        console.print()
        options = [
            Panel("[bold cyan]1[/bold cyan]\n[white]Vulnerability\nScanner[/white]", expand=True, border_style="cyan"),
            Panel("[bold green]2[/bold green]\n[white]Security\nNews Feed[/white]", expand=True, border_style="green"),
            Panel("[bold yellow]3[/bold yellow]\n[white]CVE\nDatabase[/white]", expand=True, border_style="yellow"),
            Panel("[bold red]4[/bold red]\n[white]Exit[/white]", expand=True, border_style="red"),
        ]
        console.print(Columns(options, equal=True, expand=True))
        console.print()

        choice = Prompt.ask(
            "[bold]Select option[/bold]",
            choices=["1", "2", "3", "4"],
            default="1"
        )

        if choice == "1":
            run_vulnerability_scanner()
        elif choice == "2":
            n = Prompt.ask("[bold]How many security stories?[/bold]", default="10")
            try:
                fetch_hn_security_news(limit=int(n))
            except ValueError:
                fetch_hn_security_news(10)
        elif choice == "3":
            browse_cve_database()
        elif choice == "4":
            console.print("\n[bold cyan]Stay safe. Always hack ethically. 👋[/bold cyan]\n")
            sys.exit(0)


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    banner()
    ethical_disclaimer()
    main_menu()