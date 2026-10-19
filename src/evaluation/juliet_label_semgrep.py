"""
Label Semgrep findings on the Juliet Java subset and score Semgrep per method.

Ground truth (Juliet): a method whose name starts with 'bad' contains the flaw,
a method whose name starts with 'good' is safe. A finding is labelled by the method
that contains its line. Findings outside bad*/good* methods are labelled 'other'
and are not scored (like helper files in OWASP Benchmark).

Usage (project root, venv active):
    python src/evaluation/juliet_label_semgrep.py \
        data/raw_sarif/juliet_semgrep.sarif data/juliet_subset/testcases

Writes:
    results/juliet/methods.csv            every bad*/good* method found (ground truth)
    results/juliet/semgrep_labeled.csv    every Semgrep finding with its label
and prints precision / recall / F1 (per method) for Semgrep alone.
"""
import csv
import json
import os
import re
import sys

OUT_DIR = "results/juliet"


def strip_noise(src):
    """Blank out comments and string/char literals but keep every newline."""
    out, i, n = [], 0, len(src)
    while i < n:
        c, d = src[i], src[i + 1] if i + 1 < n else ""
        if c == "/" and d == "/":
            while i < n and src[i] != "\n":
                out.append(" "); i += 1
        elif c == "/" and d == "*":
            out.append("  "); i += 2
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                out.append("\n" if src[i] == "\n" else " "); i += 1
            out.append("  "); i += 2
        elif c in "\"'":
            q = c
            out.append(" "); i += 1
            while i < n and src[i] != q:
                if src[i] == "\\":
                    out.append(" "); i += 1
                out.append("\n" if i < n and src[i] == "\n" else " "); i += 1
            out.append(" "); i += 1
        else:
            out.append(c); i += 1
    return "".join(out)


HEADER = re.compile(r"(\w+)\s*\([^()]*\)\s*(?:throws[^{;]*)?$", re.S)


def find_methods(path):
    """Return list of (name, start_line, end_line) for methods directly inside the class."""
    with open(path, "r", errors="ignore") as f:
        text = strip_noise(f.read())
    methods, depth, buf, line = [], 0, [], 1
    cur = None
    for ch in text:
        if ch == "\n":
            line += 1
        if ch == "{":
            depth += 1
            if depth == 2:  # opening brace of a member of the top-level class
                m = HEADER.search("".join(buf).strip())
                cur = [m.group(1) if m else None, line, None]
            buf = []
        elif ch == "}":
            if depth == 2 and cur is not None:
                cur[2] = line
                if cur[0]:
                    methods.append(tuple(cur))
                cur = None
            depth -= 1
            buf = []
        elif ch == ";":
            buf = []
        else:
            buf.append(ch)
    return methods


def kind(name):
    n = name.lower()
    if n.startswith("bad"):
        return "bad"
    if n.startswith("good"):
        return "good"
    return "other"


def cwe_from_path(p):
    m = re.search(r"CWE(\d+)_", p)
    return "CWE-" + m.group(1) if m else ""


def main():
    sarif_path, root = sys.argv[1], sys.argv[2]
    os.makedirs(OUT_DIR, exist_ok=True)

    # 1. ground truth: every bad*/good* method in every test file
    method_index, rows = {}, []
    for dp, _, fns in os.walk(root):
        for fn in fns:
            if not fn.endswith(".java"):
                continue
            p = os.path.join(dp, fn)
            ms = [(nm, s, e, kind(nm)) for nm, s, e in find_methods(p)]
            method_index[os.path.normpath(p)] = ms
            for nm, s, e, k in ms:
                if k in ("bad", "good"):
                    rows.append({"file": p, "test_name": fn[:-5], "method": nm, "start": s, "end": e,
                                 "kind": k, "cwe_dir": cwe_from_path(p)})
    with open(OUT_DIR + "/methods.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    n_bad = sum(r["kind"] == "bad" for r in rows)
    n_good = sum(r["kind"] == "good" for r in rows)
    print("Ground truth methods: %d bad (vulnerable), %d good (safe)" % (n_bad, n_good))

    # 2. read Semgrep SARIF
    sarif = json.load(open(sarif_path))
    run = sarif["runs"][0]
    rules = {r["id"]: r for r in run["tool"]["driver"].get("rules", [])}
    out, flagged = [], set()
    for res in run.get("results", []):
        loc = res["locations"][0]["physicalLocation"]
        uri = loc["artifactLocation"]["uri"].replace("file://", "")
        line = loc["region"]["startLine"]
        norm = os.path.normpath(uri)
        if norm not in method_index:
            continue  # support classes etc.
        rid = res["ruleId"]
        rule = rules.get(rid, {})
        tags = rule.get("properties", {}).get("tags", [])
        cwe = next((("CWE-" + re.search(r"CWE-(\d+)", t).group(1)) for t in tags if re.search(r"CWE-(\d+)", t)), "")
        sev = rule.get("defaultConfiguration", {}).get("level", "")
        label, mname = "other", ""
        for nm, s, e, k in method_index[norm]:
            if s <= line <= e:
                label, mname = k, nm
                break
        if label in ("bad", "good"):
            flagged.add((norm, mname))
        out.append({"tool": "Semgrep", "test_name": os.path.basename(norm)[:-5], "file": uri, "line": line,
                    "cwe": cwe, "rule_id": rid, "severity": sev,
                    "message": res["message"]["text"].replace("\n", " "),
                    "method": mname, "label": label, "cwe_dir": cwe_from_path(uri),
                    "cwe_matches_dir": cwe == cwe_from_path(uri)})
    with open(OUT_DIR + "/semgrep_labeled.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0].keys())); w.writeheader(); w.writerows(out)

    # 3. scoring, per method (same idea as per test case on Benchmark)
    tp = sum(1 for r in rows if r["kind"] == "bad" and (os.path.normpath(r["file"]), r["method"]) in flagged)
    fp = sum(1 for r in rows if r["kind"] == "good" and (os.path.normpath(r["file"]), r["method"]) in flagged)
    fn_ = n_bad - tp
    tn = n_good - fp
    prec = tp / (tp + fp) if tp + fp else float("nan")
    rec = tp / n_bad if n_bad else float("nan")
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else float("nan")
    by = {k: sum(1 for o in out if o["label"] == k) for k in ("bad", "good", "other")}
    print("Semgrep findings kept: %d  (in bad: %d, in good: %d, outside bad/good: %d)" % (len(out), by["bad"], by["good"], by["other"]))
    print("Per-method scoring:  TP=%d  FP=%d  FN=%d  TN=%d" % (tp, fp, fn_, tn))
    print("Precision=%.2f%%  Recall=%.2f%%  F1=%.3f" % (100 * prec, 100 * rec, f1))
    # ---- per TEST CASE scoring: group split files (_51a, _51b, ...) into one test case ----
    def group(p):
        d, b = os.path.split(os.path.normpath(p))
        return (d, re.sub(r"[a-z]$", "", b[:-5]))

    bad_g = {group(r["file"]) for r in rows if r["kind"] == "bad"}
    good_g = {group(r["file"]) for r in rows if r["kind"] == "good"}
    fl_bad = {group(f) for f, m in flagged if any(r["file"] and os.path.normpath(r["file"]) == f and r["method"] == m and r["kind"] == "bad" for r in rows)}
    fl_good = {group(f) for f, m in flagged if any(os.path.normpath(r["file"]) == f and r["method"] == m and r["kind"] == "good" for r in rows)}
    tp2, fp2 = len(fl_bad), len(fl_good)
    fn2, tn2 = len(bad_g) - tp2, len(good_g) - fp2
    p2 = tp2 / (tp2 + fp2) if tp2 + fp2 else float("nan")
    r2 = tp2 / len(bad_g)
    f2 = 2 * p2 * r2 / (p2 + r2)
    print("PER TEST CASE: bad cases=%d good cases=%d  TP=%d FP=%d FN=%d TN=%d" % (len(bad_g), len(good_g), tp2, fp2, fn2, tn2))
    print("Precision=%.2f%%  Recall=%.2f%%  F1=%.3f" % (100 * p2, 100 * r2, f2))

if __name__ == "__main__":
    main()
