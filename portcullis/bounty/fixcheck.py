"""Fix validation: replay a PoC against vulnerable and patched reference implementations.

A fix is accepted only if the PoC succeeds on the vulnerable build (so the PoC is real)
and fails on the patched build, and a benign input still works on the patched build."""
import ipaddress, html
from urllib.parse import urlparse


def ssrf_vuln(url): return urlparse(url).scheme in ("http", "https")


def ssrf_fixed(url):
    p = urlparse(url)
    if p.scheme != "https" or not p.hostname:
        return False
    try:
        ip = ipaddress.ip_address(p.hostname)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except ValueError:
        return p.hostname.lower() not in ("localhost", "metadata.google.internal") and not p.hostname.endswith(".internal")


def xss_vuln(s): return f"<div>{s}</div>"
def xss_fixed(s): return f"<div>{html.escape(s)}</div>"


def redirect_vuln(u): return u
def redirect_fixed(u):
    p = urlparse(u)
    return u if (u.startswith("/") and not u.startswith("//") and not p.netloc) else "/"


PAIRS = {
    "ssrf": dict(vuln=ssrf_vuln, fixed=ssrf_fixed, poc="http://169.254.169.254/latest/meta-data", benign="https://example.com/a",
                 exploited=lambda out: out is True, works=lambda out: out is True),
    "xss": dict(vuln=xss_vuln, fixed=xss_fixed, poc="<script>alert(1)</script>", benign="hello",
                exploited=lambda out: "<script>" in out, works=lambda out: "hello" in out),
    "redirect": dict(vuln=redirect_vuln, fixed=redirect_fixed, poc="//evil.example/x", benign="/dashboard",
                     exploited=lambda out: out.startswith("//") or "://" in out, works=lambda out: out == "/dashboard"),
}


def validate(cls):
    p = PAIRS[cls]
    poc_real = p["exploited"](p["vuln"](p["poc"]))
    poc_blocked = not p["exploited"](p["fixed"](p["poc"]))
    benign_ok = p["works"](p["fixed"](p["benign"]))
    return {"poc_reproduces": poc_real, "fix_blocks_poc": poc_blocked, "benign_still_works": benign_ok,
            "accepted": poc_real and poc_blocked and benign_ok}
