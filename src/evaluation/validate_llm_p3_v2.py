"""
Score one or more LLM verification result files on the P3 sample.

Usage (project root, venv active):
    python src/evaluation/validate_llm_p3_v2.py results/p3_llm_verified_v2.csv \
        results/p3_llm_verified_anchored_openai_gpt-4.1-mini.csv

With several files it also prints a table and checks that they cover the SAME findings.
Saves results/llm_validation_summary.csv.
"""
import sys
import os
import pandas as pd


def score(path):
    df = pd.read_csv(path)
    total = len(df)
    skipped_err = df[~df["llm_verdict"].isin(["TP", "FP"])]
    df = df[df["llm_verdict"].isin(["TP", "FP"])].copy()
    real = df["real_vulnerability"].astype(str).str.strip().str.lower().isin(["true", "1", "1.0", "yes"])
    kept = df["llm_verdict"] == "TP"
    n, n_real, n_kept = len(df), int(real.sum()), int(kept.sum())
    tp_kept = int((real & kept).sum())
    base_p = real.mean()
    filt_p = tp_kept / n_kept if n_kept else float("nan")
    recall = tp_kept / n_real if n_real else float("nan")
    f1 = 2 * filt_p * recall / (filt_p + recall) if (filt_p + recall) else float("nan")
    return {
        "file": os.path.basename(path),
        "rows_in_file": total,
        "unusable(error/skipped/unknown)": len(skipped_err),
        "n_scored": n,
        "real_vulns": n_real,
        "baseline_precision_%": round(100 * base_p, 1),
        "kept": n_kept,
        "filtered_precision_%": round(100 * filt_p, 1),
        "precision_gain_pp": round(100 * (filt_p - base_p), 1),
        "real_discarded": n_real - tp_kept,
        "recall_%": round(100 * recall, 1),
        "f1_filtered": round(f1, 3),
    }, set(df["test_name"])


def main():
    paths = sys.argv[1:]
    if not paths:
        print(__doc__)
        sys.exit(1)
    rows, sets = [], []
    for p in paths:
        r, s = score(p)
        rows.append(r)
        sets.append(s)
        print("\n=== " + r["file"] + " ===")
        for k, v in r.items():
            if k != "file":
                print("  " + k + ": " + str(v))
    if len(sets) > 1:
        common = set.intersection(*sets)
        print("\nFindings common to all files: " + str(len(common)))
        if any(len(s) != len(common) for s in sets):
            print("WARNING: files do not cover identical findings; compare only on the common set.")
    out = "results/llm_validation_summary.csv"
    pd.DataFrame(rows).to_csv(out, index=False)
    print("\nSaved " + out)


if __name__ == "__main__":
    main()
