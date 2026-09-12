import csv

INPUT_FILE = "results/p3_llm_verified.csv"
OUTPUT_FILE = "results/p3_llm_validation_summary.csv"


def validate():
    rows = list(csv.DictReader(open(INPUT_FILE)))

    # Baseline: rule-based P3 precision on THIS SAME 100-row sample
    # (not the full 1047 -- we need a fair, apples-to-apples comparison)
    baseline_tp = sum(1 for r in rows if r["real_vulnerability"] == "1")
    baseline_fp = sum(1 for r in rows if r["real_vulnerability"] == "0")
    baseline_total = baseline_tp + baseline_fp
    baseline_precision = baseline_tp / baseline_total if baseline_total else 0

    # LLM-filtered: only keep findings the LLM verdict says are TP
    llm_kept = [r for r in rows if r["llm_verdict"] == "TP"]
    llm_tp = sum(1 for r in llm_kept if r["real_vulnerability"] == "1")
    llm_fp = sum(1 for r in llm_kept if r["real_vulnerability"] == "0")
    llm_total = llm_tp + llm_fp
    llm_precision = llm_tp / llm_total if llm_total else 0

    # How many REAL vulnerabilities did the LLM wrongly discard as FP?
    real_vulns_in_sample = [r for r in rows if r["real_vulnerability"] == "1"]
    wrongly_discarded = sum(1 for r in real_vulns_in_sample if r["llm_verdict"] == "FP")
    recall_within_sample = (len(real_vulns_in_sample) - wrongly_discarded) / len(real_vulns_in_sample) if real_vulns_in_sample else 0

    print(f"Sample size: {len(rows)}")
    print(f"\n--- BEFORE (rule-based P3, this sample) ---")
    print(f"TP={baseline_tp} FP={baseline_fp} Precision={baseline_precision:.1%}")
    print(f"\n--- AFTER (LLM-filtered, kept only LLM-verdict=TP) ---")
    print(f"TP={llm_tp} FP={llm_fp} Precision={llm_precision:.1%}")
    print(f"Findings kept: {llm_total}/{len(rows)} ({llm_total/len(rows):.1%})")
    print(f"\nReal vulnerabilities wrongly discarded by LLM: {wrongly_discarded}/{len(real_vulns_in_sample)}")
    print(f"Recall within this sample after LLM filtering: {recall_within_sample:.1%}")

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["stage", "tp", "fp", "total", "precision"])
        writer.writerow(["rule_based_p3_baseline", baseline_tp, baseline_fp, baseline_total, round(baseline_precision, 4)])
        writer.writerow(["llm_filtered_p3", llm_tp, llm_fp, llm_total, round(llm_precision, 4)])

    print(f"\nSaved to {OUTPUT_FILE}")


if __name__ == "__main__":
    validate()
