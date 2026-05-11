# web-security-tools

A collection of Python tools for web application security testing and penetration testing practice.

> ⚠️ **For authorized use only.** Only use these tools on systems you own or have explicit written permission to test.

---

## Tools

### 1. `basic_port_scanner.py`
A multithreaded TCP port scanner that identifies open ports and common services on a target host.

**What it does:**
- Scans a range of TCP ports using threading for speed
- Identifies common services (SSH, HTTP, MySQL, RDP, Redis, etc.)
- Supports custom port ranges, thread count, and timeout settings
- Resolves hostnames to IP addresses automatically

**Usage:**
```bash
# Scan default ports (1-1024)
python basic_port_scanner.py -t 192.168.1.1

# Scan specific range
python basic_port_scanner.py -t example.com -p 1-1000

# Scan specific ports
python basic_port_scanner.py -t example.com -p 80,443,8080,3306

# Full scan with more threads
python basic_port_scanner.py -t example.com -p 1-65535 --threads 200
```

**Example output:**
```
=======================================================
  Basic Port Scanner
  Target : example.com (93.184.216.34)
  Ports  : 1024 ports
  Threads: 100  |  Timeout: 1.0s
=======================================================
[*] Scanning — please wait...

PORT       SERVICE              STATE
----------------------------------------
22         SSH                  OPEN
80         HTTP                 OPEN
443        HTTPS                OPEN
3306       MySQL                OPEN
----------------------------------------

[+] Scan complete — 4 open port(s) found
```

**Skills demonstrated:**
- Python `socket` library
- Multithreading with `threading.Semaphore`
- CLI argument parsing with `argparse`
- Networking fundamentals (TCP, ports, services)

---

### 2. `burp_request_parser.py`
Parses raw HTTP requests copied from Burp Suite and analyzes them for common security test points.

**What it does:**
- Parses raw HTTP requests (method, path, headers, body, parameters)
- Detects IDOR/BOLA-prone parameters (id, user_id, account_id, etc.)
- Identifies authentication headers and JWT tokens
- Flags sensitive parameters (password, api_key, token, etc.)
- Suggests injection test points (XSS, SQLi, SSTI)
- Provides actionable test suggestions for each finding

**Usage:**
```bash
# Parse a request file
python burp_request_parser.py -f request.txt

# Parse and run security analysis
python burp_request_parser.py -f request.txt --analyze

# Read from stdin (pipe from Burp copy)
cat request.txt | python burp_request_parser.py --stdin --analyze

# Save output to file
python burp_request_parser.py -f request.txt --analyze --output report.txt
```

**Example input (`request.txt`):**
```
POST /api/v1/user/profile HTTP/1.1
Host: example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
Content-Type: application/json

{"userId": 12345, "email": "test@example.com"}
```

**Example output:**
```
=======================================================
  REQUEST SUMMARY
=======================================================
  Method  : POST
  Host    : example.com
  Path    : /api/v1/user/profile

  Headers (3):
    authorization: Bearer eyJhbGc...
    content-type: application/json

  Body Parameters:
    userId = 12345
    email = test@example.com

=======================================================
  SECURITY ANALYSIS
=======================================================

  [HIGH] IDOR / BOLA
  Detail     : ID-like parameter(s) found: ['userid']
  Test ideas : Try changing the value to another user's ID.
               Test: remove auth token entirely and retry.

  [MEDIUM] JWT Token
  Detail     : JWT (Bearer token) detected
  Test ideas : Decode at jwt.io — check algorithm and claims.
               Test: change 'alg' to 'none'.

  [INFO] JSON Body
  Detail     : Request has a JSON body
  Test ideas : Add extra fields (role, isAdmin, balance).
               Mass assignment may be possible.

  Summary: 1 HIGH  |  1 MEDIUM  |  3 total
```

**Skills demonstrated:**
- HTTP request structure and parsing
- Web application security concepts (IDOR, JWT, injection)
- Object-oriented Python (classes, methods)
- Security analysis automation

---

## Requirements

```bash
pip install requests  # for future tools
```

`basic_port_scanner.py` and `burp_request_parser.py` use only Python standard library — no installation needed.

**Python version:** 3.10+

---

## Setup

```bash
# Clone the repo
git clone https://github.com/ahuvjbivjjg/web-security-tools.git
cd web-security-tools

# Run directly
python basic_port_scanner.py -t scanme.nmap.org
```

> **Legal test target:** `scanme.nmap.org` is Nmap's official test server — always legal to scan.

---

## Roadmap

- [ ] `subdomain_enum.py` — DNS-based subdomain enumeration
- [ ] `xss_payload_tester.py` — Reflected XSS payload automation
- [ ] `directory_bruteforce.py` — Web directory discovery
- [ ] `header_analyzer.py` — HTTP security header checker

---

## Author

**Ahmed Ashraf Mohamed**
Cybersecurity student | Junior Penetration Tester
- LinkedIn: [linkedin.com/in/ahmed-a-912283254](https://linkedin.com/in/ahmed-a-912283254)
- TryHackMe | Hack The Box | HackenProof

---

## Disclaimer

These tools are built for **educational purposes** and **authorized security testing only**.
Unauthorized use against systems you do not own is illegal.
The author is not responsible for any misuse.
