# SpoofGuard

**SpoofGuard** is an explainable, open-source email spoofing detector written in Python.
It analyses a raw email message (`.eml` file) and returns a risk score, a verdict and a
human-readable list of reasons.

Email authentication standards (SPF, DKIM and DMARC) do not catch lookalike domains
(e.g. `paypa1.com`) or a trusted name placed in the display field. SpoofGuard combines
authentication results with identity-consistency and lookalike-domain checks to cover these gaps.

Author: Sheryl Varshney, Cyber Security for Mobility Systems, Thapar Institute of Engineering and Technology, Patiala.
This repository accompanies the article *"SpoofGuard: A Multi-Signal Email Spoofing Detector Combining Header
Authentication, Identity Consistency and Lookalike-Domain Analysis"*.

---

## Repository contents

```
.
├── spoofguard.py
├── evaluate.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
├── samples/
│   ├── legitimate.eml
│   ├── lookalike_domain.eml
│   ├── display_name_spoof.eml
│   └── failed_dmarc.eml
├── tests/
│   └── test_spoofguard.py
└── .github/
    └── workflows/
        └── test.yml
```

### Files

| File / folder | Purpose |
|---|---|
| `spoofguard.py` | The main program. Parses an `.eml` file, runs all checks (authentication results, Reply-To / Return-Path mismatch, display-name deception, lookalike domain, internationalised domain, DMARC record lookup), and prints a JSON report with score, verdict and reasons. |
| `evaluate.py` | Evaluation script. Runs the detector on the labelled sample emails and prints precision, recall, F1-score and mean processing time for an authentication-only baseline and for full SpoofGuard. These numbers are used in the article's results table. |
| `requirements.txt` | Python dependencies: `dnspython` (DMARC DNS lookups) and `pytest` (tests). Install with `pip install -r requirements.txt`. |
| `README.md` | This file: project description, usage and explanation of the repository. |
| `LICENSE` | MIT licence, allowing reuse of the code with attribution. |
| `.gitignore` | Tells Git to ignore temporary files (`__pycache__/`, `.pytest_cache/`, virtual environments, `.env`). |
| `samples/` | Four example emails used for testing and evaluation (see below). |
| `tests/test_spoofguard.py` | Automated unit tests (pytest). They check the edit-distance function and that each sample email receives the expected verdict. |
| `.github/workflows/test.yml` | GitHub Actions workflow. On every push or pull request it installs the dependencies and runs the tests automatically, so a green tick in the **Actions** tab means all tests pass. |

### Sample emails (`samples/`)

| File | Description | Expected verdict |
|---|---|---|
| `legitimate.eml` | Normal message from `google.com` that passes SPF, DKIM and DMARC. | NO STRONG EVIDENCE |
| `lookalike_domain.eml` | Sent from `paypa1.com` (digit 1 instead of letter l). Passes authentication for its own domain, but resembles `paypal.com` and has a different Reply-To domain. | LIKELY SPOOFED |
| `display_name_spoof.eml` | Display name shows `support@paypal.com` while the real sender is `mailer.example`; SPF soft-fails. | SUSPICIOUS |
| `failed_dmarc.eml` | Impersonates a CEO; SPF, DKIM and DMARC all fail. | LIKELY SPOOFED |

---

## How it works

Each triggered signal adds a weight to the risk score:

| Signal | Weight |
|---|---|
| SPF fail / softfail / permerror | 2 |
| DKIM fail / permerror | 2 |
| DMARC fail | 3 |
| Reply-To domain differs from From domain | 2 |
| Return-Path domain differs from From domain | 1 |
| Display name contains an email address from a different domain | 3 |
| Lookalike of a trusted domain (edit distance <= 2) | 4 |
| Internationalised (`xn--`) domain | 2 |
| No DMARC record found (online mode only) | 1 |

Verdict: score >= 6 -> **LIKELY SPOOFED**; score 3 to 5 -> **SUSPICIOUS**; otherwise **NO STRONG EVIDENCE**.

---

## Installation

```bash
git clone https://github.com/Sv035/Cyber-Security-for-Mobility-Systems-Assignment_Spoofguard_Sheryl-Varshney.git
cd Cyber-Security-for-Mobility-Systems-Assignment_Spoofguard_Sheryl-Varshney
pip install -r requirements.txt
```

Requires Python 3.10 or newer.

## Usage

Analyse a single email:

```bash
python spoofguard.py samples/lookalike_domain.eml --offline    # no DNS lookups
python spoofguard.py samples/lookalike_domain.eml              # also checks the DMARC record via DNS
```

Example output:

```json
{
  "from": "support@paypa1.com",
  "score": 6,
  "verdict": "LIKELY SPOOFED",
  "reasons": [
    "Reply-To domain secure-mail.example != From domain paypa1.com",
    "paypa1.com resembles trusted domain paypal.com"
  ]
}
```

The exit code is `1` if the message is flagged and `0` otherwise, so the tool can be used in scripts and pipelines.

To analyse your own email, save it as a raw `.eml` file (in most mail clients: "Download message" or "Show original")
and pass its path to `spoofguard.py`. The tool reads the `Authentication-Results` header added by your receiving mail server.

## Run the tests

```bash
pytest -q
```

## Run the evaluation

```bash
python evaluate.py
```

Results on the four sample emails:

| Method | Precision | Recall | F1 | Time (ms) |
|---|---|---|---|---|
| Authentication only | 1.00 | 0.67 | 0.80 | 0.37 |
| SpoofGuard (all signals) | 1.00 | 1.00 | 1.00 | 0.52 |

The authentication-only baseline misses the lookalike-domain email because it passes SPF, DKIM and DMARC.
The dataset is very small and was built to exercise each signal, so these numbers show the approach works
as designed, not how it performs on real-world email. Timings vary by machine.

To add your own test emails, put the `.eml` file in `samples/` and add it to the `LABELS` dictionary in
`evaluate.py` (`1` = spoofed, `0` = legitimate).

## Customisation

Edit these constants at the top of `spoofguard.py`:
- `TRUSTED`: the list of brand domains checked for lookalikes.
- `WEIGHTS`: the weight of each signal.
- `T_HIGH`, `T_LOW`: the score thresholds for the verdicts.

## Limitations

- Trusts the `Authentication-Results` header added by the receiving mail server; it does not verify SPF or DKIM itself.
- The trusted-domain list is manual.
- Legitimate mailing lists can trigger Reply-To / Return-Path mismatch warnings.
- Homoglyph attacks are only partly covered (via the `xn--` check).
- Only headers are analysed; message bodies, links and attachments are not.

## Disclaimer

Educational project. Do not rely on it as your only defence against phishing.

## Licence

MIT, see `LICENSE`.
