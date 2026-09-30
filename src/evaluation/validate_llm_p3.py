import csv

BASELINE_FILE = "results/p3_llm_verified.csv"        # has ground truth + original anchored LLM verdict
BLIND_FILE = "results/p3_llm_verified_blind.csv"       # has ground truth + blind LLM verdict
OUTPUT_FILE = "results/p3_three_way_comparison.csv"


def load_verdicts(path, verdict_col="llm_verdict"):
    rows = list(csv.DictReader(open(path)))
    by_test = {r["test_name"]: r for r in rows}
    return by_test


def compute_metrics(rows, verdict_col):
    """Rule-based baseline (all rows, no LLM filtering) vs LLM-filtered (kept only TP verdicts)."""
    baseline_tp = sum(1 for r in rows if r["real_vulnerability"] == "1")
    baseline_fp = sum(1 for r in rows if r["real_vulnerability"] == "0")
    baseline_total = baseline_tp + baseline_fp
    baseline_precision = baseline_tp / baseline_total if baseline_total else 0

    kept = [r for r in rows if r[verdict_col] == "TP"]
    llm_tp = sum(1 for r in kept if r["real_vulnerability"] == "1")
    llm_fp = sum(1 for r in kept if r["real_vulnerability"] == "0")
    llm_total = llm_tp + llm_fp
    llm_precision = llm_tp / llm_total if llm_total else 0

    real_vulns = [r for r in rows if r["real_vulnerability"] == "1"]
    discarded = sum(1 for r in real_vulns if r[verdict_col] == "FP")
    recall = (len(real_vulns) - discarded) / len(real_vulns) if real_vulns else 0

    return {
        "baseline_precision": baseline_precision,
        "llm_precision": llm_precision,
        "llm_total_kept": llm_total,
        "sample_size": len(rows),
        "real_vulns_discarded": discarded,
        "total_real_vulns": len(real_vulns),
        "recall_after_filtering": recall
    }


if __name__ == "__main__":
    anchored = load_verdicts(BASELINE_FILE)
    blind = load_verdicts(BLIND_FILE)

    # Only compare rows present in BOTH files, excluding ERROR/SKIPPED rows from blind run
    common_tests = [t for t in anchored if t in blind and blind[t]["llm_verdict"] in ("TP", "FP")]

    anchored_rows = [anchored[t] for t in common_tests]
    blind_rows = [blind[t] for t in common_tests]

    anchored_metrics = compute_metrics(anchored_rows, "llm_verdict")
    blind_metrics = compute_metrics(blind_rows, "llm_verdict")

    print(f"Comparable sample size (excluding ERROR/SKIPPED): {len(common_tests)}\n")

    print("=== RULE-BASED BASELINE (no LLM) ===")
    print(f"Precision: {anchored_metrics['baseline_precision']:.1%}\n")

    print("=== ANCHORED PROMPT (LLM told the tool's claim) ===")
    print(f"Precision after filtering: {anchored_metrics['llm_precision']:.1%}")
    print(f"Findings kept: {anchored_metrics['llm_total_kept']}/{len(common_tests)}")
    print(f"Real vulns wrongly discarded: {anchored_metrics['real_vulns_discarded']}/{anchored_metrics['total_real_vulns']}")
    print(f"Recall after filtering: {anchored_metrics['recall_after_filtering']:.1%}\n")

    print("=== BLIND PROMPT (LLM given only raw code, no tool claim) ===")
    print(f"Precision after filtering: {blind_metrics['llm_precision']:.1%}")
    print(f"Findings kept: {blind_metrics['llm_total_kept']}/{len(common_tests)}")
    print(f"Real vulns wrongly discarded: {blind_metrics['real_vulns_discarded']}/{blind_metrics['total_real_vulns']}")
    print(f"Recall after filtering: {blind_metrics['recall_after_filtering']:.1%}")

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["approach", "precision", "findings_kept", "sample_size", "real_vulns_discarded", "total_real_vulns", "recall"])
        writer.writerow(["rule_based_baseline", round(anchored_metrics["baseline_precision"], 4), "-", len(common_tests), "-", "-", "-"])
        writer.writerow(["anchored_prompt", round(anchored_metrics["llm_precision"], 4), anchored_metrics["llm_total_kept"], len(common_tests), anchored_metrics["real_vulns_discarded"], anchored_metrics["total_real_vulns"], round(anchored_metrics["recall_after_filtering"], 4)])
        writer.writerow(["blind_prompt", round(blind_metrics["llm_precision"], 4), blind_metrics["llm_total_kept"], len(common_tests), blind_metrics["real_vulns_discarded"], blind_metrics["total_real_vulns"], round(blind_metrics["recall_after_filtering"], 4)])

    print(f"\nSaved to {OUTPUT_FILE}")
