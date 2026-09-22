# AttackTrace
### Simulated Web Attack + Digital Forensic Reconstruction Toolkit

A second-year cybersecurity/digital forensics project: attack a web
application, then reconstruct exactly what happened using only the
evidence a real DFIR analyst would have (logs, timestamps, artifacts) —
without relying on prior knowledge of the attack.

## What's in this project

| File | Purpose |
|---|---|
| `attack_log_simulator.py` | Generates a realistic access log containing normal traffic + a hidden 5-stage attack (recon → SQLi → XSS → malicious upload → RCE via webshell) |
| `forensic_analyzer.py` | Parses ANY Apache/Nginx-style access log, flags suspicious activity, ranks suspect IPs, and writes a full Markdown incident report |
| `access.log` | Example generated log (delete and regenerate anytime) |
| `forensic_report.md` | Example output report |

## Quick start

```bash
# 1. Generate a practice log with a hidden attack
python3 attack_log_simulator.py

# 2. Investigate it cold, as if you're a DFIR analyst
python3 forensic_analyzer.py access.log

# 3. Open the result
cat forensic_report.md
```

## How to extend this into your full college project

### Phase 1 — Do the attack for real (this is what makes it "yours")
1. Set up VirtualBox with two VMs: Kali Linux (attacker) and
   Metasploitable2 or a DVWA Docker container (target).
2. Perform the same attack chain manually:
   - Recon with `dirb`/`gobuster`
   - SQL injection with `sqlmap` or manual payloads on DVWA's SQLi page
   - Stored XSS on DVWA's XSS page
   - File upload → PHP webshell on DVWA's upload page
   - Run commands through your webshell
3. **Capture the target's real Apache access log** (`/var/log/apache2/access.log`)
   during this — that's your real evidence.

### Phase 2 — Point the analyzer at your real log
```bash
python3 forensic_analyzer.py /path/to/real/access.log
```
You may need to add a few patterns to `RECON_PATTERNS`, `SQLI_PATTERNS`,
etc. in `forensic_analyzer.py` to match your specific DVWA payloads —
this is expected and is a good thing to discuss in your report ("I
tuned my detection signatures after seeing my own attack traffic").

### Phase 3 — Level up the forensics (optional, impresses examiners)
- Add MySQL query log parsing (`general_log` in DVWA's DB) to
  correlate web requests with actual DB queries executed.
- If you captured a memory dump during the attack, run `Volatility3`
  against it to find the webshell process, and add a section to your
  report showing process-level evidence alongside the log evidence.
- Use `Autopsy` on a disk image of the target VM to show the uploaded
  webshell file's creation timestamp lines up with your log timeline.

## Why this project is a good fit for a 2nd-year DFIR student

- It's legally and technically safe: everything happens in your own
  VMs against DVWA/Metasploitable, which are built to be attacked.
- It teaches you to read raw evidence cold — the actual skill DFIR
  analysts use, not just running a scanner.
- The code is simple regex + log parsing (Python fundamentals you
  already have) rather than requiring deep exploit-development
  knowledge.
- It naturally extends: each "Phase 3" idea above is a legitimate
  "future work" section for your report or a follow-up project next
  year.

## Report structure for submission

Use `forensic_report.md` as your template. A strong final report should
have:
1. Executive summary (1 paragraph)
2. Attack methodology (what you did, Phase 1)
3. Forensic findings (the reconstructed timeline)
4. Attack stage interpretation (the "so what")
5. Mitigations
6. Evidence/limitations notes

This structure mirrors real incident response reports used in industry.
