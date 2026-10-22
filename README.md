# Phishing Awareness Analyzer

A command-line tool that inspects an email (`.eml`) or a URL for phishing indicators, produces a **risk score with an explanation** and teaches the user why each indicator matters. Built for the CodeNova Cyber Security Internship (Task 2).

## Safety and scope

- Works on **synthetic or sanitised** samples only.
- Only **reads local files**. It never opens links, probes servers, makes network requests or collects credentials. URLs are analysed purely as text.
- The sample emails use reserved example/test domains and invented names.

## False-positive disclaimer

These are heuristic rules, not proof. **False positives and false negatives are possible**: a legitimate email using urgent wording can score higher than expected, and a careful attacker can score low. Always verify through an official channel instead of clicking links. The included `promo_false_positive.eml` sample demonstrates this on purpose, and the tool prints this disclaimer in every report.

## How the score works

Each indicator adds points. Points are capped per category so one category cannot dominate:

| Category | Cap |
|---|---|
| Header | 50 |
| Body | 40 |
| URL | 50 |

Total is limited to 100.

| Score | Level |
|---|---|
| 0-24 | LOW |
| 25-49 | MEDIUM |
| 50-100 | HIGH |

## Heuristic rules

### Header indicators

| Indicator | Points |
|---|---|
| Missing or malformed From address | 15 |
| Reply-To domain differs from From domain | 15 |
| Return-Path domain differs from From domain | 10 |
| Display name claims a known brand but the domain is not official | 20 |
| SPF fail/softfail/none | 15 |
| DKIM fail/none | 15 |
| DMARC fail/none | 10 |
| No authentication results present | 5 |

### Body indicators (keyword groups)

| Group | Points per phrase | Cap |
|---|---|---|
| Urgency ("immediately", "final notice") | 5 | 15 |
| Security warnings ("unusual activity", "account suspended") | 6 | 18 |
| Credential requests ("confirm your password") | 10 | 25 |

### URL indicators

| Indicator | Points |
|---|---|
| IP address instead of a domain | 20 |
| `@` symbol in the link | 15 |
| Punycode (`xn--`) domain | 15 |
| URL shortener | 10 |
| Plain `http` link | 5 |
| Frequently abused TLD (e.g. `.top`, `.xyz`) | 8 |
| Five or more domain labels | 8 |
| Brand name in a subdomain of an unrelated domain | 20 |
| Brand name embedded in an unrelated domain | 18 |
| Typosquatting (look-alike characters or one-character edit) | 25 |
| Link text shows a different domain than the real target | 20 |

## Requirements

- Python 3.8 or newer
- No external packages (standard library only: `email`, `re`, `urllib`, `ipaddress`)

## Usage

```
python task2.py --create-samples     create synthetic emails in .\samples
python task2.py --demo               analyse all sample emails
python task2.py --email samples\phish_paypal.eml
python task2.py --url "http://paypa1-security.test/login"
python task2.py --selftest           check scoring against the samples
```

## Synthetic test corpus

| File | Type |
|---|---|
| `legit_newsletter.eml` | legitimate |
| `legit_meeting.eml` | legitimate |
| `promo_false_positive.eml` | legitimate marketing email with urgent wording (false-positive demo) |
| `phish_paypal.eml` | synthetic phishing (typosquat domain, Reply-To mismatch, failed SPF/DKIM) |
| `phish_microsoft.eml` | synthetic phishing (HTML link mismatch, shortener, brand subdomain) |

## Project files

```
task2.py
samples/          created by --create-samples
README.md
```

## Screenshots

<img width="490" height="105" alt="WhatsApp Image 2026-10-22 at 4 28 52 AM" src="https://github.com/user-attachments/assets/c73e335a-2c2d-4a82-9251-34e55a402c42" />
<img width="614" height="194" alt="WhatsApp Image 2026-10-22 at 4 29 27 AM" src="https://github.com/user-attachments/assets/2f0ada28-b300-49c1-9f3c-2f0084071b27" />
<img width="987" height="194" alt="WhatsApp Image 2026-10-22 at 4 30 18 AM" src="https://github.com/user-attachments/assets/3aca48d5-1957-4f87-89b3-0ae4b74cd0e7" />




## Limitations

- Small brand list and a simplified domain parser (no full public-suffix list).
- Keyword matching is English only.
- Does not inspect attachments or follow redirects (by design: no network activity).
-
