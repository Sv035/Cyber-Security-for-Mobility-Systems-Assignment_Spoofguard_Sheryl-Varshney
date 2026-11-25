import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from spoofguard import analyze, levenshtein

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")

def run(name):
    return analyze(os.path.join(SAMPLES, name), online=False)

def test_levenshtein():
    assert levenshtein("paypal.com", "paypa1.com") == 1
    assert levenshtein("same", "same") == 0

def test_legitimate_message():
    assert run("legitimate.eml")["verdict"] == "NO STRONG EVIDENCE"

def test_lookalike_domain():
    r = run("lookalike_domain.eml")
    assert r["verdict"] == "LIKELY SPOOFED"
    assert any("resembles" in x for x in r["reasons"])

def test_display_name_spoof():
    r = run("display_name_spoof.eml")
    assert r["verdict"] == "SUSPICIOUS"
    assert any("Display name" in x for x in r["reasons"])

def test_failed_dmarc():
    r = run("failed_dmarc.eml")
    assert r["verdict"] == "LIKELY SPOOFED"
    assert r["score"] >= 6
