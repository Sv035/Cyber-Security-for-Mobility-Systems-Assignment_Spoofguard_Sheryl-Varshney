#!/usr/bin/env python3
"""SpoofGuard: explainable email spoofing detector."""
import re, sys, json
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

try:
    import dns.resolver
except ImportError:
    dns = None

TRUSTED = ["paypal.com", "google.com", "microsoft.com", "amazon.com", "apple.com"]
WEIGHTS = {"spf_fail": 2, "dkim_fail": 2, "dmarc_fail": 3, "replyto_mismatch": 2,
           "returnpath_mismatch": 1, "display_name_domain": 3, "lookalike": 4,
           "idn_domain": 2, "no_dmarc": 1}
T_HIGH, T_LOW = 6, 3

def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].strip("<> ").lower() if "@" in addr else ""

def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]

def lookalike_of(domain: str):
    for t in TRUSTED:
        if domain != t and levenshtein(domain, t) <= 2:
            return t
    return None

def auth_results(msg) -> dict:
    header = " ".join(str(h) for h in msg.get_all("Authentication-Results", []))
    out = {}
    for key in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{key}=(\w+)", header, re.I)
        out[key] = m.group(1).lower() if m else None
    return out

def dmarc_policy(domain: str):
    """Return the DMARC 'p=' value, or None if no record / lookup impossible."""
    if dns is None or not domain:
        return None
    try:
        for rdata in dns.resolver.resolve("_dmarc." + domain, "TXT", lifetime=5):
            txt = b"".join(rdata.strings).decode(errors="ignore")
            if txt.lower().startswith("v=dmarc1"):
                m = re.search(r"\bp=(\w+)", txt, re.I)
                return m.group(1).lower() if m else "none"
    except Exception:
        return None
    return None

def analyze(path: str, online: bool = True) -> dict:
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    name, from_addr = parseaddr(str(msg.get("From", "")))
    from_dom = domain_of(from_addr)
    reply_dom = domain_of(parseaddr(str(msg.get("Reply-To", "")))[1])
    rpath_dom = domain_of(parseaddr(str(msg.get("Return-Path", "")))[1])

    flags = {}
    auth = auth_results(msg)
    if auth["spf"] in ("fail", "softfail", "permerror"):
        flags["spf_fail"] = f"SPF result: {auth['spf']}"
    if auth["dkim"] in ("fail", "permerror"):
        flags["dkim_fail"] = f"DKIM result: {auth['dkim']}"
    if auth["dmarc"] == "fail":
        flags["dmarc_fail"] = "DMARC result: fail"

    if reply_dom and reply_dom != from_dom:
        flags["replyto_mismatch"] = f"Reply-To domain {reply_dom} != From domain {from_dom}"
    if rpath_dom and rpath_dom != from_dom:
        flags["returnpath_mismatch"] = f"Return-Path domain {rpath_dom} != From domain {from_dom}"

    shown = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", name or "")
    if shown and shown.group(1).lower() != from_dom:
        flags["display_name_domain"] = f"Display name shows {shown.group(0)}"

    look = lookalike_of(from_dom)
    if look:
        flags["lookalike"] = f"{from_dom} resembles trusted domain {look}"
    if "xn--" in from_dom:
        flags["idn_domain"] = f"Internationalised domain: {from_dom}"

    if online:
        pol = dmarc_policy(from_dom)
        if pol is None:
            flags["no_dmarc"] = "No DMARC record found (or lookup failed)"

    score = sum(WEIGHTS[k] for k in flags)
    verdict = ("LIKELY SPOOFED" if score >= T_HIGH else
               "SUSPICIOUS" if score >= T_LOW else "NO STRONG EVIDENCE")
    return {"from": from_addr, "score": score, "verdict": verdict,
            "reasons": list(flags.values())}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: spoofguard.py message.eml [--offline]")
    result = analyze(sys.argv[1], online="--offline" not in sys.argv)
    print(json.dumps(result, indent=2))
    sys.exit(1 if result["verdict"] != "NO STRONG EVIDENCE" else 0)
