"""Compare authentication-only detection with full SpoofGuard on labelled samples."""
import os, time
from email import policy
from email.parser import BytesParser
from spoofguard import analyze, auth_results

SAMPLES = "samples"
# 1 = spoofed, 0 = legitimate (ground truth). Add your own files here.
LABELS = {
    "legitimate.eml": 0,
    "lookalike_domain.eml": 1,
    "display_name_spoof.eml": 1,
    "failed_dmarc.eml": 1,
}

def auth_only(path):
    with open(path, "rb") as f:
        a = auth_results(BytesParser(policy=policy.default).parse(f))
    return int(a["spf"] in ("fail", "softfail", "permerror")
               or a["dkim"] in ("fail", "permerror") or a["dmarc"] == "fail")

def full(path):
    return int(analyze(path, online=False)["verdict"] != "NO STRONG EVIDENCE")

def evaluate(name, detector):
    tp = fp = fn = 0
    start = time.perf_counter()
    for fname, truth in LABELS.items():
        pred = detector(os.path.join(SAMPLES, fname))
        tp += pred == 1 and truth == 1
        fp += pred == 1 and truth == 0
        fn += pred == 0 and truth == 1
    ms = (time.perf_counter() - start) * 1000 / len(LABELS)
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    print(f"{name:28s} P={p:.2f}  R={r:.2f}  F1={f1:.2f}  Time={ms:.2f} ms")

if __name__ == "__main__":
    evaluate("Authentication only", auth_only)
    evaluate("SpoofGuard (all signals)", full)
