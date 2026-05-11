#!/usr/bin/env python3
"""
burp_request_parser.py
───────────────────────
Parse and analyze raw HTTP requests copied from Burp Suite.
Identifies parameters, headers, and potential security test points.

Usage:
  python burp_request_parser.py -f request.txt
  python burp_request_parser.py -f request.txt --analyze
  python burp_request_parser.py -f request.txt --analyze --output report.txt

  Or pipe directly:
  cat request.txt | python burp_request_parser.py --stdin

Author : Ahmed Ashraf Mohamed
Purpose: Cybersecurity portfolio — web security workflow tooling
"""

import argparse
import sys
import json
from urllib.parse import urlparse, parse_qs, unquote


# ── Patterns that suggest interesting parameters ────────────────────────────

IDOR_PARAMS = [
    "id", "user_id", "userid", "account_id", "accountid",
    "order_id", "orderid", "customer_id", "uid", "oid",
    "profile_id", "member_id", "doc_id", "file_id", "invoice_id",
]

AUTH_HEADERS = [
    "authorization", "x-auth-token", "x-api-key", "token",
    "session", "cookie", "x-access-token", "bearer",
]

SENSITIVE_PARAMS = [
    "password", "passwd", "pwd", "secret", "key", "api_key",
    "token", "auth", "credit_card", "ssn", "email",
]

INJECTION_PARAMS = [
    "search", "query", "q", "input", "name", "username",
    "comment", "message", "text", "content", "data",
]


# ── Parser ───────────────────────────────────────────────────────────────────

class BurpRequestParser:

    def __init__(self, raw: str):
        self.raw     = raw.strip()
        self.method  = ""
        self.path    = ""
        self.version = ""
        self.host    = ""
        self.headers = {}
        self.body    = ""
        self.params  = {}   # URL params
        self.bparams = {}   # Body params
        self._parse()

    def _parse(self) -> None:
        """Split raw request into components."""
        lines = self.raw.replace("\r\n", "\n").split("\n")
        if not lines:
            return

        # Request line
        request_line = lines[0].strip()
        parts = request_line.split(" ")
        if len(parts) >= 3:
            self.method  = parts[0].upper()
            self.path    = parts[1]
            self.version = parts[2]

        # Headers + body split
        header_section = True
        header_lines   = []
        body_lines     = []

        for line in lines[1:]:
            if header_section:
                if line.strip() == "":
                    header_section = False
                else:
                    header_lines.append(line)
            else:
                body_lines.append(line)

        # Parse headers
        for line in header_lines:
            if ":" in line:
                key, _, value = line.partition(":")
                self.headers[key.strip().lower()] = value.strip()
                if key.strip().lower() == "host":
                    self.host = value.strip()

        # Parse body
        self.body = "\n".join(body_lines).strip()

        # Parse URL params
        parsed = urlparse(self.path)
        self.params = parse_qs(parsed.query)

        # Parse body params
        content_type = self.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in content_type:
            self.bparams = parse_qs(self.body)
        elif "application/json" in content_type:
            try:
                self.bparams = json.loads(self.body)
            except json.JSONDecodeError:
                self.bparams = {}


# ── Analyzer ─────────────────────────────────────────────────────────────────

class SecurityAnalyzer:

    def __init__(self, parser: BurpRequestParser):
        self.p       = parser
        self.findings = []

    def analyze(self) -> list[dict]:
        self._check_idor()
        self._check_auth()
        self._check_sensitive()
        self._check_injection()
        self._check_method()
        self._check_content_type()
        return self.findings

    def _add(self, severity: str, category: str, detail: str, suggestion: str) -> None:
        self.findings.append({
            "severity":   severity,
            "category":   category,
            "detail":     detail,
            "suggestion": suggestion,
        })

    def _all_params(self) -> dict:
        """Merge URL params and body params."""
        merged = {}
        for k, v in self.p.params.items():
            merged[k.lower()] = v
        if isinstance(self.p.bparams, dict):
            for k, v in self.p.bparams.items():
                merged[str(k).lower()] = v
        return merged

    def _check_idor(self) -> None:
        params = self._all_params()
        found  = [p for p in IDOR_PARAMS if p in params]

        # Also check path segments
        path_parts = self.p.path.split("/")
        numeric    = [seg for seg in path_parts if seg.isdigit()]

        if found:
            self._add(
                "HIGH", "IDOR / BOLA",
                f"ID-like parameter(s) found: {found}",
                f"Try changing the value(s) to another user's ID. "
                f"Test: remove auth token entirely and retry."
            )
        if numeric:
            self._add(
                "MEDIUM", "IDOR / Path Traversal",
                f"Numeric path segment(s) in URL: {numeric}",
                f"Replace the number with another ID (e.g. +1 or -1). "
                f"Check if response changes to another user's data."
            )

    def _check_auth(self) -> None:
        found_headers = [h for h in AUTH_HEADERS if h in self.p.headers]
        if not found_headers:
            self._add(
                "INFO", "Authentication",
                "No auth header detected in this request",
                "Check if this endpoint requires authentication. "
                "Try accessing it without any auth token."
            )
        else:
            self._add(
                "INFO", "Authentication",
                f"Auth header(s) present: {found_headers}",
                "Test: remove the header completely and resend. "
                "Test: replace token with an expired/invalid one. "
                "Test: use another account's token."
            )

        # JWT check
        auth_val = self.p.headers.get("authorization", "")
        if auth_val.lower().startswith("bearer ey"):
            self._add(
                "MEDIUM", "JWT Token",
                "JWT (Bearer token) detected",
                "Decode at jwt.io — check algorithm, expiry, and claims. "
                "Test: change 'alg' to 'none'. "
                "Test: modify payload claims (role, userId)."
            )

    def _check_sensitive(self) -> None:
        params = self._all_params()
        found  = [p for p in SENSITIVE_PARAMS if p in params]
        if found:
            self._add(
                "HIGH", "Sensitive Parameters",
                f"Sensitive param(s) in request: {found}",
                "Ensure these are sent over HTTPS only. "
                "Check if they appear in server logs or responses."
            )

    def _check_injection(self) -> None:
        params = self._all_params()
        found  = [p for p in INJECTION_PARAMS if p in params]
        if found:
            self._add(
                "MEDIUM", "Injection Testing",
                f"User-input parameter(s) found: {found}",
                "Test for XSS: <script>alert(1)</script> "
                "Test for SQLi: ' OR '1'='1 "
                "Test for SSTI: {{7*7}}"
            )

    def _check_method(self) -> None:
        if self.p.method in ("PUT", "DELETE", "PATCH"):
            self._add(
                "MEDIUM", "HTTP Method",
                f"Sensitive HTTP method: {self.p.method}",
                f"Test: change {self.p.method} to GET or POST — does it still work? "
                "Test: try the same action without auth token."
            )

    def _check_content_type(self) -> None:
        ct = self.p.headers.get("content-type", "")
        if "application/json" in ct and self.p.body:
            self._add(
                "INFO", "JSON Body",
                "Request has a JSON body",
                "Test: add extra fields (role, isAdmin, balance, permissions). "
                "Test: change data types (string → number, bool). "
                "Mass assignment may be possible."
            )


# ── Printer ──────────────────────────────────────────────────────────────────

SEV_COLORS = {
    "HIGH":   "\033[91m",   # red
    "MEDIUM": "\033[93m",   # yellow
    "INFO":   "\033[94m",   # blue
    "LOW":    "\033[92m",   # green
}
RESET = "\033[0m"


def print_parsed(p: BurpRequestParser) -> None:
    print("\n" + "=" * 55)
    print("  REQUEST SUMMARY")
    print("=" * 55)
    print(f"  Method  : {p.method}")
    print(f"  Host    : {p.host}")
    print(f"  Path    : {p.path}")
    print(f"  Version : {p.version}")

    if p.headers:
        print(f"\n  Headers ({len(p.headers)}):")
        for k, v in p.headers.items():
            display = v if len(v) < 60 else v[:57] + "..."
            print(f"    {k}: {display}")

    if p.params:
        print(f"\n  URL Parameters:")
        for k, v in p.params.items():
            print(f"    {k} = {v}")

    if p.bparams:
        print(f"\n  Body Parameters:")
        if isinstance(p.bparams, dict):
            for k, v in p.bparams.items():
                print(f"    {k} = {v}")
        else:
            print(f"    {p.bparams}")

    if p.body and not p.bparams:
        preview = p.body[:200] + ("..." if len(p.body) > 200 else "")
        print(f"\n  Raw Body:\n    {preview}")


def print_analysis(findings: list[dict]) -> None:
    print("\n" + "=" * 55)
    print("  SECURITY ANALYSIS")
    print("=" * 55)

    if not findings:
        print("  No notable findings.")
        return

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    sorted_f = sorted(findings, key=lambda x: order.get(x["severity"], 9))

    for f in sorted_f:
        color = SEV_COLORS.get(f["severity"], "")
        print(f"\n  {color}[{f['severity']}]{RESET} {f['category']}")
        print(f"  Detail     : {f['detail']}")
        print(f"  Test ideas : {f['suggestion']}")

    high   = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    print(f"\n  Summary: {high} HIGH  |  {medium} MEDIUM  |  {len(findings)} total")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Burp Suite Request Parser & Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python burp_request_parser.py -f request.txt
  python burp_request_parser.py -f request.txt --analyze
  cat request.txt | python burp_request_parser.py --stdin --analyze
        """
    )
    parser.add_argument("-f", "--file",    help="Path to file containing the raw HTTP request")
    parser.add_argument("--stdin",         action="store_true", help="Read request from stdin")
    parser.add_argument("--analyze",       action="store_true", help="Run security analysis on the request")
    parser.add_argument("--output",        help="Save output to a file")
    args = parser.parse_args()

    # Read input
    if args.stdin:
        raw = sys.stdin.read()
    elif args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except FileNotFoundError:
            print(f"[ERROR] File not found: {args.file}")
            raise SystemExit(1)
    else:
        parser.print_help()
        raise SystemExit(0)

    if not raw.strip():
        print("[ERROR] Empty input.")
        raise SystemExit(1)

    # Parse
    req      = BurpRequestParser(raw)
    output   = []

    # Capture output
    import io
    old_stdout = sys.stdout
    sys.stdout = buffer = io.StringIO()

    print_parsed(req)
    if args.analyze:
        analyzer = SecurityAnalyzer(req)
        findings = analyzer.analyze()
        print_analysis(findings)

    print("\n[!] Only test on authorized targets.\n")

    sys.stdout = old_stdout
    result = buffer.getvalue()
    print(result)

    if args.output:
        with open(args.output, "w") as f:
            f.write(result)
        print(f"[+] Output saved to: {args.output}")


if __name__ == "__main__":
    main()
