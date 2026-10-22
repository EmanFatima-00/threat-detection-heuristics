"""
task2.py - Phishing Awareness Analyzer (CodeNova Cyber Security Internship, Task 2)

Analyses an email (.eml file) or a single URL for phishing indicators using
transparent, rule-based heuristics, then prints a risk score with an
educational explanation.

SAFETY
  * Works on synthetic / sanitised samples. It only READS local files.
  * It NEVER opens links, makes network requests, probes servers or collects
    credentials. URLs are only analysed as text.
  * Heuristics are not proof. FALSE POSITIVES AND FALSE NEGATIVES ARE POSSIBLE:
    a legitimate email can score high and a clever phishing email can score low.

Usage (Windows):
  python task2.py --create-samples        create synthetic test emails in .\\samples
  python task2.py --demo                  analyse every email in .\\samples
  python task2.py --email samples\\phish_paypal.eml
  python task2.py --url "http://paypa1-security.test/login"
  python task2.py --selftest              check the heuristics against the samples

Only the Python standard library is used (urllib, re, email, ipaddress).
"""

import argparse
import ipaddress
import os
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

DISCLAIMER = ("This is an educational heuristic tool. False positives (safe "
              "emails flagged) and false negatives (phishing missed) are "
              "possible. Never treat the score as proof; verify through an "
              "official channel instead of clicking links.")

# ---------------------------------------------------------------- knowledge
# Brand -> official registered domains (used to spot impersonation).
BRANDS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "google": {"google.com", "gmail.com"},
    "amazon": {"amazon.com"},
    "apple": {"apple.com", "icloud.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "meta.com"},
    "linkedin": {"linkedin.com"},
}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
                  "buff.ly", "cutt.ly"}
SUSPICIOUS_TLDS = {"zip", "top", "xyz", "click", "country", "gq", "tk", "work"}
MULTI_PART_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au",
                       "co.in", "com.pk", "co.jp", "com.br"}

KEYWORDS = {
    "urgency": ["urgent", "immediately", "within 24 hours", "act now",
                "final notice", "expires today", "last warning",
                "right away", "limited time"],
    "security warning": ["account suspended", "account will be closed",
                         "unusual activity", "suspicious activity",
                         "security alert", "unauthorized login",
                         "your account has been locked", "verify your account"],
    "credential request": ["verify your password", "confirm your password",
                           "enter your password", "login details",
                           "social security", "credit card number",
                           "update your payment", "confirm your identity",
                           "one-time code", "pin number"],
}
KEYWORD_POINTS = {"urgency": 5, "security warning": 6, "credential request": 10}
KEYWORD_CAPS = {"urgency": 15, "security warning": 18, "credential request": 25}
CATEGORY_CAPS = {"Header": 50, "Body": 40, "URL": 50}

URL_REGEX = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


# ------------------------------------------------------------------ helpers
def registered_domain(host):
    """Naive registered-domain finder (no external suffix list needed)."""
    host = (host or "").lower().strip(".")
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def levenshtein(a, b):
    """Edit distance between two short strings."""
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def look_alike_forms(label):
    """Undo common character swaps (paypa1 -> paypal, rn -> m, vv -> w)."""
    forms = {label}
    for swap in ({"0": "o", "1": "l", "3": "e", "5": "s"},
                 {"0": "o", "1": "i", "3": "e", "5": "s"}):
        forms.add("".join(swap.get(c, c) for c in label))
    forms |= {f.replace("rn", "m").replace("vv", "w") for f in list(forms)}
    return forms


def add(findings, category, points, indicator, explanation):
    findings.append({"category": category, "points": points,
                     "indicator": indicator, "explanation": explanation})


# ------------------------------------------------------------- URL analysis
def analyze_url(url, findings, anchor_text=None):
    """Add URL-based indicators to findings. Never contacts the URL."""
    raw = url.strip()
    parts = urlsplit(raw if "://" in raw else "http://" + raw)
    host = (parts.hostname or "").lower()
    if not host:
        return
    short = host if len(host) <= 40 else host[:37] + "..."
    reg = registered_domain(host)
    labels = host.split(".")
    seen = set()

    def flag(key, points, indicator, explanation):
        if (key, host) not in seen:
            seen.add((key, host))
            add(findings, "URL", points, f"{indicator}: {short}", explanation)

    if is_ip(host):
        flag("ip", 20, "IP address used instead of a domain name",
             "Legitimate services use domain names. Raw IP links hide who "
             "owns the destination.")
    if "@" in parts.netloc:
        flag("at", 15, "'@' symbol in the link",
             "Everything before '@' is ignored by browsers, so attackers use "
             "it to disguise the real destination.")
    if "xn--" in host:
        flag("puny", 15, "Punycode (internationalised) domain",
             "Look-alike Unicode characters can imitate well-known brands.")
    if reg in URL_SHORTENERS:
        flag("short", 10, "URL shortener",
             "Shorteners hide the final destination from the reader.")
    if parts.scheme == "http":
        flag("http", 5, "Unencrypted http link",
             "Login pages should always use https.")
    if labels[-1] in SUSPICIOUS_TLDS and not is_ip(host):
        flag("tld", 8, "Domain ends in a TLD often abused by attackers",
             "Some low-cost TLDs are over-represented in abuse reports.")
    if len(labels) >= 5 and not is_ip(host):
        flag("deep", 8, "Unusually many subdomains",
             "Long subdomain chains are used to push the real domain out of "
             "sight on small screens.")

    if not is_ip(host):
        label = reg.split(".")[0]
        subdomain_part = host[:-len(reg)] if host.endswith(reg) else ""
        for brand, official in BRANDS.items():
            if reg in official:
                continue
            if brand in subdomain_part:
                flag("sub-" + brand, 20,
                     f"Misleading subdomain mentions '{brand}'",
                     f"The real domain is '{reg}', not {brand}'s. Read a "
                     "link's domain from right to left.")
            elif label != brand and brand in label:
                flag("embed-" + brand, 18,
                     f"Brand name '{brand}' embedded in an unrelated domain",
                     f"'{reg}' is not an official {brand} domain.")
            elif any(tok != brand and (
                    brand in look_alike_forms(tok) or
                    (len(tok) >= 5 and levenshtein(tok, brand) == 1))
                    for tok in re.split(r"[-_]", label)):
                flag("typo-" + brand, 25,
                     f"Possible typosquatting of '{brand}'",
                     f"'{reg}' is visually very close to the real brand name "
                     "(swapped or altered characters).")

    if anchor_text:
        shown = URL_REGEX.search(anchor_text)
        if shown:
            shown_host = (urlsplit(shown.group(0)).hostname or "").lower()
            if registered_domain(shown_host) != reg:
                flag("anchor", 20, "Link text shows a different domain than "
                     "the real target",
                     f"The text says '{registered_domain(shown_host)}' but "
                     f"the link goes to '{reg}'.")
class LinkCollector(HTMLParser):
    """Collects (href, visible text) pairs from HTML email bodies."""

    def __init__(self):
        super().__init__()
        self.links, self._href, self._text = [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href, self._text = dict(attrs).get("href"), []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


# ----------------------------------------------------------- email analysis
def analyze_headers(msg, findings):
    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    from_dom = registered_domain(from_addr.split("@")[-1]) if "@" in from_addr else ""
    if not from_dom:
        add(findings, "Header", 15, "Missing or malformed From address",
            "Genuine mail always has a clear sender address.")

    for header, points in (("Reply-To", 15), ("Return-Path", 10)):
        _, addr = parseaddr(str(msg.get(header, "")))
        if "@" in addr:
            dom = registered_domain(addr.split("@")[-1])
            if from_dom and dom != from_dom:
                add(findings, "Header", points,
                    f"{header} domain differs from sender domain",
                    f"From uses '{from_dom}' but {header} uses '{dom}'. "
                    "Replies or bounces go somewhere unexpected.")

    lowered_name = from_name.lower()
    for brand, official in BRANDS.items():
        if brand in lowered_name and from_dom and from_dom not in official:
            add(findings, "Header", 20,
                f"Display name claims '{brand}' but domain is '{from_dom}'",
                "Attackers set a trusted display name; check the actual "
                "address behind it.")
            break

    auth = " ".join(str(v) for k, v in msg.items()
                    if k.lower() in ("authentication-results", "received-spf"))
    if not auth:
        add(findings, "Header", 5, "No SPF/DKIM/DMARC results in headers",
            "Authentication could not be verified from the supplied headers.")
    else:
        for mech, points in (("spf", 15), ("dkim", 15), ("dmarc", 10)):
            m = re.search(rf"{mech}\s*=\s*(\w+)", auth, re.IGNORECASE)
            if m and m.group(1).lower() in ("fail", "softfail", "none",
                                            "permerror", "temperror"):
                add(findings, "Header", points,
                    f"{mech.upper()} result: {m.group(1).lower()}",
                    f"The sending server did not pass {mech.upper()} "
                    "checks, so the sender may be forged.")


def extract_body(msg):
    """Return (plain_text, html_text) of an email."""
    plain, html = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        if ctype in ("text/plain", "text/html"):
            try:
                text = part.get_content()
            except Exception:
                text = ""
            (plain if ctype == "text/plain" else html).append(text)
    return "\n".join(plain), "\n".join(html)


def analyze_body(subject, plain, html, findings):
    html_text = re.sub(r"<[^>]+>", " ", html)
    text = f"{subject}\n{plain}\n{html_text}".lower()
    for group, phrases in KEYWORDS.items():
        hits = [p for p in phrases if p in text]
        if hits:
            points = min(KEYWORD_CAPS[group], KEYWORD_POINTS[group] * len(hits))
            add(findings, "Body", points,
                f"{group.title()} language ({len(hits)} match"
                f"{'es' if len(hits) > 1 else ''})",
                "Phrases found: " + ", ".join(f"'{h}'" for h in hits) +
                ". Phishing relies on pressure and fear to rush decisions.")


def analyze_email(path):
    with open(path, "rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)
    findings = []
    analyze_headers(msg, findings)
    plain, html = extract_body(msg)
    analyze_body(str(msg.get("Subject", "")), plain, html, findings)

    anchors = []
    collector = LinkCollector()
    collector.feed(html)
    anchors.extend(collector.links)
    anchored = {href for href, _ in anchors}
    for url in URL_REGEX.findall(plain + " " + html):
        url = url.rstrip(".,;")
        if url not in anchored:
            anchors.append((url, None))
    for href, text in anchors:
        if href.lower().startswith(("http://", "https://")):
            analyze_url(href, findings, anchor_text=text)
    return summarise(findings, {
        "Type": "Email", "File": os.path.basename(path),
        "From": str(msg.get("From", "(none)")),
        "Subject": str(msg.get("Subject", "(none)")),
        "Links found": str(len([a for a in anchors
                                if a[0].lower().startswith("http")]))})


def analyze_single_url(url):
    findings = []
    analyze_url(url, findings)
    return summarise(findings, {"Type": "URL", "Target": url})


def summarise(findings, meta):
    """Apply per-category caps and convert points to a 0-100 risk score."""
    totals = {}
    for f in findings:
        totals[f["category"]] = totals.get(f["category"], 0) + f["points"]
    score = min(100, sum(min(v, CATEGORY_CAPS[k]) for k, v in totals.items()))
    level = "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH"
    return {"meta": meta, "findings": findings, "score": score,
            "level": level, "totals": totals}


# ------------------------------------------------------------------- output
COLOUR = {"LOW": "\033[92m", "MEDIUM": "\033[93m", "HIGH": "\033[91m"}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"


def print_report(result):
    c = COLOUR[result["level"]]
    bar = "#" * (result["score"] // 5) + "-" * (20 - result["score"] // 5)
    print("\n" + "=" * 64)
    print(f"{BOLD}PHISHING ANALYSIS REPORT{RESET}")
    print("=" * 64)
    for k, v in result["meta"].items():
        print(f"{k:<12}: {v}")
    print("-" * 64)
    print(f"Risk score  : {c}{BOLD}{result['score']}/100  "
          f"[{result['level']} RISK]{RESET}")
    print(f"              [{c}{bar}{RESET}]")
    print("-" * 64)
    if not result["findings"]:
        print("No suspicious indicators were found by the heuristic rules.")
    for cat in ("Header", "Body", "URL"):
        items = [f for f in result["findings"] if f["category"] == cat]
        if not items:
            continue
        cap = CATEGORY_CAPS[cat]
        total = min(cap, result["totals"][cat])
        print(f"\n{BOLD}{cat} indicators{RESET} ({total}/{cap} pts)")
        for f in items:
            print(f"  [+{f['points']:>2}] {f['indicator']}")
            print(f"        {DIM}{f['explanation']}{RESET}")
    print("\n" + "-" * 64)
    print(f"{BOLD}Disclaimer:{RESET} {DISCLAIMER}")
    print("=" * 64)
    # ------------------------------------------------------------ sample corpus
SAMPLES = {
    "legit_newsletter.eml": """\
From: "Example News" <news@example.com>
To: student@example.org
Subject: Your weekly campus newsletter
Date: Mon, 12 Oct 2026 09:00:00 +0000
Message-ID: <1001@example.com>
Authentication-Results: mx.example.org; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain; charset=utf-8

Hello,

Here is this week's newsletter. Read the full stories on our website:
https://www.example.com/news/weekly

Regards,
The Example News team
""",
    "legit_meeting.eml": """\
From: Dana Lee <dana.lee@example.com>
To: team@example.com
Subject: Project meeting moved to Thursday
Date: Tue, 13 Oct 2026 10:15:00 +0000
Message-ID: <1002@example.com>
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain; charset=utf-8

Hi all,

The project meeting is now on Thursday at 2 PM. Agenda is in the shared
folder: https://docs.example.com/projects/agenda

Thanks,
Dana
""",
    "promo_false_positive.eml": """\
From: "Example Shop" <offers@example.com>
To: student@example.org
Subject: Limited time offer - act now!
Date: Wed, 14 Oct 2026 08:00:00 +0000
Message-ID: <1003@example.com>
Authentication-Results: mx.example.org; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain; charset=utf-8

Limited time offer! Act now - this sale expires today.
Browse the deals: https://shop.example.com/sale

This is a legitimate marketing email. It uses urgent wording, which shows
how heuristics can raise the score even for harmless mail.
""",
    "phish_paypal.eml": """\
From: "PayPal Support" <support@paypa1-security.test>
Reply-To: collect@mailbox.test
Return-Path: <bounce@mailbox.test>
To: victim@example.org
Subject: URGENT: Your account has been locked
Date: Thu, 15 Oct 2026 03:21:00 +0000
Message-ID: <2001@paypa1-security.test>
Authentication-Results: mx.example.org; spf=fail; dkim=none; dmarc=fail
Content-Type: text/plain; charset=utf-8

Security alert: we noticed unusual activity on your account.
Your account has been locked. Verify your password immediately or the
account will be closed within 24 hours.

Log in here: http://paypa1-security.test/login
Or use our secure server: http://192.0.2.10/verify
""",
    "phish_microsoft.eml": """\
From: "Microsoft Account Team" <no-reply@account-verify.test>
To: victim@example.org
Subject: Final notice - password expires today
Date: Fri, 16 Oct 2026 02:05:00 +0000
Message-ID: <2002@account-verify.test>
Authentication-Results: mx.example.org; spf=softfail; dkim=fail
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>
<p>Your password expires today. Confirm your password right away to avoid
suspicious activity flags on your account.</p>
<p><a href="http://microsoft.account-verify.test/signin">https://www.microsoft.com/account</a></p>
<p>Or <a href="http://bit.ly/3xAmPl3">click here</a> to update your payment details.</p>
</body></html>
""",
}


def create_samples(folder="samples"):
    os.makedirs(folder, exist_ok=True)
    for name, body in SAMPLES.items():
        with open(os.path.join(folder, name), "w", encoding="utf-8",
                  newline="\n") as fh:
            fh.write(body)
    print(f"Created {len(SAMPLES)} synthetic sample emails in '{folder}'.")
    print("They use reserved example/test domains; nothing is real.")


def analyze_folder(folder="samples"):
    if not os.path.isdir(folder):
        print(f"Folder '{folder}' not found. Run: python task2.py --create-samples")
        return {}
    results = {}
    for name in sorted(os.listdir(folder)):
        if name.lower().endswith(".eml"):
            results[name] = analyze_email(os.path.join(folder, name))
    return results


def selftest(folder="samples"):
    create_samples(folder)
    results = analyze_folder(folder)
    expected = {"legit_newsletter.eml": {"LOW"}, "legit_meeting.eml": {"LOW"},
                "promo_false_positive.eml": {"LOW", "MEDIUM"},
                "phish_paypal.eml": {"HIGH"}, "phish_microsoft.eml": {"HIGH"}}
    ok = True
    print("\nSELF-TEST")
    for name, allowed in expected.items():
        r = results[name]
        passed = r["level"] in allowed
        ok &= passed
        print(f"  {'PASS' if passed else 'FAIL'}  {name:<28} "
              f"score={r['score']:>3} level={r['level']} "
              f"(expected {'/'.join(sorted(allowed))})")
    print("\nAll checks passed." if ok else "\nSome checks FAILED.")
    return 0 if ok else 1


def main():
    p = argparse.ArgumentParser(description="Phishing Awareness Analyzer")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--create-samples", action="store_true")
    g.add_argument("--demo", action="store_true")
    g.add_argument("--email", metavar="FILE.eml")
    g.add_argument("--url", metavar="URL")
    g.add_argument("--selftest", action="store_true")
    args = p.parse_args()

    if os.name == "nt":
        os.system("")  # enable ANSI colours in Windows terminals
    try:
        if args.create_samples:
            create_samples()
        elif args.demo:
            for r in analyze_folder().values():
                print_report(r)
        elif args.email:
            print_report(analyze_email(args.email))
        elif args.url:
            print_report(analyze_single_url(args.url))
        elif args.selftest:
            return selftest()
    except FileNotFoundError as err:
        print(f"Error: file not found - {err.filename}")
        return 1
    except OSError as err:
        print(f"Error: could not read file - {err}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())