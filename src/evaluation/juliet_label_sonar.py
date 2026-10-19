"""
Download SonarQube VULNERABILITY issues for the Juliet subset, add CWE, label each by method
(bad / good / other, using results/juliet/methods.csv from juliet_label_semgrep.py) and score
SonarQube alone, per method and per test case.

Usage (project root, venv active, SonarQube running, SONAR_TOKEN in .env):
    python src/evaluation/juliet_label_sonar.py
    python src/evaluation/juliet_label_sonar.py --project juliet-subset
Writes results/juliet/sonar_labeled.csv
"""
import argparse
import csv
import os
import re
import sys
from collections import defaultdict

import requests
from dotenv import load_dotenv

load_dotenv()
HOST = os.environ.get("SONAR_HOST", "http://localhost:9000")
OUT = "results/juliet/sonar_labeled.csv"


def fetch_issues(project, token):
    issues, page = [], 1
    while True:
        r = requests.get(HOST + "/api/issues/search", auth=(token, ""),
                         params={"componentKeys": project, "types": "VULNERABILITY",
                                 "ps": 500, "p": page}, timeout=120)
        r.raise_for_status()
        data = r.json()
        issues += data["issues"]
        total = data["paging"]["total"]
        if page * 500 >= min(total, 10000):
            break
        page += 1
    if total > 10000:
        print("WARNING: %d issues exist but the API returns at most 10,000." % total)
    print("Downloaded %d of %d VULNERABILITY issues" % (len(issues), total))
    return issues


_rule_cache = {}


def cwe_of_rule(rule_key, token):
    if rule_key in _rule_cache:
        return _rule_cache[rule_key]
    cwe = ""
    r = requests.get(HOST + "/api/rules/show", auth=(token, ""), params={"key": rule_key}, timeout=60)
    if r.ok:
        blob = r.text
        m = re.search(r"cwe\.mitre\.org/data/definitions/(\d+)", blob) or re.search(r"cwe:(\d+)", blob)
        if m:
            cwe = "CWE-" + m.group(1)
    _rule_cache[rule_key] = cwe
    return cwe


def group(path):
    d, b = os.path.split(os.path.normpath(path))
    return (d, re.sub(r"[a-z]$", "", b[:-5]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", default="juliet-subset")
    args = ap.parse_args()
    token = os.environ.get("SONAR_TOKEN")
    if not token:
        sys.exit("SONAR_TOKEN not found in .env")
    methods = defaultdict(list)
    truth = []
    for r in csv.DictReader(open("results/juliet/methods.csv")):
        key = os.path.normpath(r["file"])
        methods[key].append((r["method"], int(r["start"]), int(r["end"]), r["kind"]))
        truth.append((key, r["method"], r["kind"]))
    n_bad = sum(1 for t in truth if t[2] == "bad")
    n_good = sum(1 for t in truth if t[2] == "good")

    out, flagged = [], set()
    for it in fetch_issues(args.project, token):
        comp = it["component"].split(":", 1)[-1]
        path = os.path.normpath(comp)
        line = it.get("line") or it.get("textRange", {}).get("startLine")
        if path not in methods or not line:
            continue
        label, mname = "other", ""
        for nm, s, e, k in methods[path]:
            if s <= line <= e:
                label, mname = k, nm
                break
        if label in ("bad", "good"):
            flagged.add((path, mname))
        cwe = cwe_of_rule(it["rule"], token)
        out.append({"tool": "SonarQube", "test_name": os.path.basename(path)[:-5], "file": comp, "line": line,
                    "cwe": cwe, "rule_id": it["rule"], "severity": it.get("severity", ""),
                    "message": it["message"].replace("\n", " "), "method": mname, "label": label})
    if not out:
        sys.exit("No issues matched Juliet files; check the project key and paths.")
    with open(OUT, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0].keys())); w.writeheader(); w.writerows(out)
    by = {k: sum(1 for o in out if o["label"] == k) for k in ("bad", "good", "other")}
    print("SonarQube findings kept: %d  (in bad: %d, in good: %d, outside: %d)" % (len(out), by["bad"], by["good"], by["other"]))

    def report(title, tp, fp, pos, neg):
        p = tp / (tp + fp) if tp + fp else float("nan"); rc = tp / pos
        f1 = 2 * p * rc / (p + rc) if p + rc else float("nan")
        print("%s  TP=%d FP=%d FN=%d TN=%d" % (title, tp, fp, pos - tp, neg - fp))
        print("Precision=%.2f%%  Recall=%.2f%%  F1=%.3f" % (100 * p, 100 * rc, f1))

    tp = sum(1 for k, m, kd in truth if kd == "bad" and (k, m) in flagged)
    fp = sum(1 for k, m, kd in truth if kd == "good" and (k, m) in flagged)
    report("PER METHOD:   ", tp, fp, n_bad, n_good)
    bad_g = {group(k) for k, m, kd in truth if kd == "bad"}
    good_g = {group(k) for k, m, kd in truth if kd == "good"}
    kinds = {(k, m): kd for k, m, kd in truth}
    fl_bad = {group(k) for k, m in flagged if kinds.get((k, m)) == "bad"}
    fl_good = {group(k) for k, m in flagged if kinds.get((k, m)) == "good"}
    report("PER TEST CASE:", len(fl_bad), len(fl_good), len(bad_g), len(good_g))


if __name__ == "__main__":
    main()
