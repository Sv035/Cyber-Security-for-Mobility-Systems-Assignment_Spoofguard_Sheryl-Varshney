# SpoofGuard

An explainable, open-source email spoofing detector written in Python. It analyses a raw
`.eml` message and reports a risk score with human-readable reasons.

## Signals checked
| Signal | Weight |
|---|---|
| SPF fail / softfail | 2 |
| DKIM fail | 2 |
| DMARC fail | 3 |
| Reply-To domain differs from From | 2 |
| Return-Path domain differs from From | 1 |
| Display name contains a different email domain | 3 |
| Lookalike of a trusted domain (edit distance <= 2) | 4 |
| Internationalised (`xn--`) domain | 2 |
| No DMARC record (online mode only) | 1 |

Verdict: score >= 6 -> **LIKELY SPOOFED**, 3-5 -> **SUSPICIOUS**, otherwise **NO STRONG EVIDENCE**.

## Installation
```bash
git clone https://github.com/Sv035/Cyber-Security-for-Mobility-Systems-Assignment_Spoofguard_Sheryl-Varshney.git
cd spoofguard
pip install -r requirements.txt
```

## Usage
```bash
python spoofguard.py samples/lookalike_domain.eml --offline   # no DNS lookups
python spoofguard.py samples/lookalike_domain.eml             # with DMARC DNS lookup
```
Exit code is `1` if the message is flagged, `0` otherwise (useful in CI pipelines).

## Run tests
```bash
pytest -q
```

## Project structure
```
spoofguard.py              main detector
samples/*.eml              sample messages (legitimate and spoofed)
tests/test_spoofguard.py   unit tests
.github/workflows/test.yml CI (GitHub Actions)
requirements.txt, LICENSE, .gitignore, README.md
```

## Limitations
- Trusts the `Authentication-Results` header added by the receiving mail server.
- Trusted-domain list is manual (edit `TRUSTED` in `spoofguard.py`).
- Mailing lists can trigger Reply-To / Return-Path mismatch warnings.
- Headers only; message bodies, links and attachments are not analysed.

## Disclaimer
Educational project. Do not rely on it as your only defence against phishing.
