"""
AttackTrace - Forensic Log Analyzer
--------------------------------------
Reads an Apache/Nginx-style access log (real or simulated) and
reconstructs what happened WITHOUT assuming prior knowledge of the
attack -- exactly how a DFIR (Digital Forensics & Incident Response)
analyst would approach raw evidence.

Detects and timelines:
    - Reconnaissance (scanning for admin panels, backups, .git, etc.)
    - SQL Injection indicators
    - Cross-Site Scripting (XSS) indicators
    - Suspicious file uploads / double extensions (webshells)
    - Post-exploitation command execution via a webshell

Run:
    python3 forensic_analyzer.py access.log

Output:
    - Printed summary to console
    - forensic_report.md  (full incident report you can submit)
"""

import re
import sys
from collections import defaultdict

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
)

RECON_PATTERNS = [
    r"/admin", r"/wp-login", r"/phpmyadmin", r"\.git", r"backup",
    r"\.bak", r"/uploads/$",
]

SQLI_PATTERNS = [
    r"'--", r"' OR '1'='1", r"UNION\s+SELECT", r"information_schema",
    r"\bOR\s+1=1\b", r"SLEEP\(", r"benchmark\(",
]

XSS_PATTERNS = [
    r"<script", r"%3Cscript", r"document\.cookie", r"onerror=", r"onload=",
]

UPLOAD_PATTERNS = [
    r"/upload", r"\.php\.jpg$", r"\.php\.png$", r"\.phtml$", r"shell",
]

RCE_PATTERNS = [
    r"cmd=", r"whoami", r"\bid\b", r"/etc/passwd", r"wget\+", r"curl\+",
]


def classify(path):
    """Return a list of matching attack categories for a request path."""
    hits = []
    for pat in RECON_PATTERNS:
        if re.search(pat, path, re.IGNORECASE):
            hits.append("RECON")
            break
    for pat in SQLI_PATTERNS:
        if re.search(pat, path, re.IGNORECASE):
            hits.append("SQLI")
            break
    for pat in XSS_PATTERNS:
        if re.search(pat, path, re.IGNORECASE):
            hits.append("XSS")
            break
    for pat in UPLOAD_PATTERNS:
        if re.search(pat, path, re.IGNORECASE):
            hits.append("UPLOAD")
            break
    for pat in RCE_PATTERNS:
        if re.search(pat, path, re.IGNORECASE):
            hits.append("RCE")
            break
    return hits


def parse_log(filepath):
    events = []
    with open(filepath, "r") as f:
        for line_num, line in enumerate(f, 1):
            m = LOG_PATTERN.match(line.strip())
            if not m:
                continue
            d = m.groupdict()
            categories = classify(d["path"])
            events.append({
                "line_num": line_num,
                "ip": d["ip"],
                "time": d["time"],
                "method": d["method"],
                "path": d["path"],
                "status": d["status"],
                "agent": d["agent"],
                "categories": categories,
            })
    return events


def build_report(events, outfile="forensic_report.md"):
    suspicious = [e for e in events if e["categories"]]

    # Score IPs by number and variety of suspicious categories triggered
    ip_scores = defaultdict(lambda: defaultdict(int))
    for e in suspicious:
        for c in e["categories"]:
            ip_scores[e["ip"]][c] += 1

    # Rank IPs by total suspicious hits
    ranked_ips = sorted(ip_scores.items(), key=lambda kv: sum(kv[1].values()), reverse=True)

    lines = []
    lines.append("# AttackTrace - Forensic Incident Report\n")
    lines.append(f"Total log entries analyzed: **{len(events)}**")
    lines.append(f"Suspicious entries flagged: **{len(suspicious)}**\n")

    lines.append("## 1. Suspicious Source IP Ranking\n")
    lines.append("| IP Address | Total Flags | Categories Triggered |")
    lines.append("|---|---|---|")
    for ip, cats in ranked_ips:
        total = sum(cats.values())
        cat_str = ", ".join(f"{k}({v})" for k, v in cats.items())
        lines.append(f"| {ip} | {total} | {cat_str} |")

    if ranked_ips:
        primary_suspect = ranked_ips[0][0]
        lines.append(f"\n**Primary suspect IP:** `{primary_suspect}` "
                      f"(highest and most varied suspicious activity)\n")
    else:
        primary_suspect = None
        lines.append("\nNo suspicious activity detected in this log.\n")

    lines.append("## 2. Reconstructed Attack Timeline\n")
    if primary_suspect:
        timeline_events = [e for e in events if e["ip"] == primary_suspect and e["categories"]]
        lines.append("| Time | Method | Path | Status | Categories |")
        lines.append("|---|---|---|---|---|")
        for e in timeline_events:
            cats = ", ".join(e["categories"])
            lines.append(f"| {e['time']} | {e['method']} | `{e['path']}` | {e['status']} | {cats} |")
    else:
        lines.append("_No timeline to reconstruct -- no suspicious IP identified._")

    lines.append("\n## 3. Attack Stage Interpretation\n")
    stage_map = {
        "RECON": "**Reconnaissance** - attacker probed for admin panels, backups, or exposed config/version-control files.",
        "SQLI": "**SQL Injection** - attacker attempted to manipulate database queries, likely to bypass authentication or exfiltrate data (note any `UNION SELECT` / `information_schema` usage, which indicates schema enumeration or data theft).",
        "XSS": "**Cross-Site Scripting** - attacker injected script content, likely to steal session cookies from a victim who later views the affected page.",
        "UPLOAD": "**Malicious File Upload** - attacker uploaded a file with a suspicious name/extension pattern (commonly used to disguise a webshell, e.g. `shell.php.jpg`).",
        "RCE": "**Post-Exploitation / Remote Code Execution** - attacker used an uploaded webshell to execute commands on the server (evidence of commands like `whoami`, `id`, or reading `/etc/passwd`).",
    }
    seen_categories = set()
    for ip, cats in ranked_ips:
        for c in cats:
            seen_categories.add(c)
    stage_order = ["RECON", "SQLI", "XSS", "UPLOAD", "RCE"]
    for stage in stage_order:
        if stage in seen_categories:
            lines.append(f"- {stage_map[stage]}")

    lines.append("\n## 4. Recommended Mitigations\n")
    mitigations = {
        "RECON": "- Return generic 404s and avoid exposing `.git`, backup files, or default admin paths publicly.",
        "SQLI": "- Use parameterized queries / prepared statements everywhere; deploy a WAF rule for `UNION SELECT` and comment-based injection patterns.",
        "XSS": "- Sanitize and encode all user-supplied input before rendering; set a strict Content-Security-Policy header; use `HttpOnly` and `Secure` cookie flags.",
        "UPLOAD": "- Validate file type by content (magic bytes), not extension; store uploads outside the web root; disable script execution in the uploads directory.",
        "RCE": "- Restrict outbound connections from the web server; monitor for unexpected child processes spawned by the web server user; apply least-privilege file permissions.",
    }
    for stage in stage_order:
        if stage in seen_categories:
            lines.append(mitigations[stage])

    lines.append("\n## 5. Evidence Notes\n")
    lines.append("- This timeline was reconstructed purely from web server access log entries.")
    lines.append("- For a complete investigation, also collect: database query logs, "
                  "file system timestamps on the uploads directory, and (if available) "
                  "a memory dump analyzed with Volatility for any live malicious process.")

    with open(outfile, "w") as f:
        f.write("\n".join(lines) + "\n")

    return outfile, primary_suspect, len(suspicious)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 forensic_analyzer.py <path-to-access.log>")
        sys.exit(1)

    logfile = sys.argv[1]
    events = parse_log(logfile)
    outfile, suspect, n_suspicious = build_report(events)

    print(f"Parsed {len(events)} log entries.")
    print(f"Flagged {n_suspicious} suspicious entries.")
    if suspect:
        print(f"Primary suspect IP: {suspect}")
    print(f"Full report written to: {outfile}")
