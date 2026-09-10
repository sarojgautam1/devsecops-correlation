import csv
from collections import defaultdict

# Input files -- the per-tool scored results we already have
SCORED_FILES = [
    "results/semgrep_scored.csv",
    "results/sonar_scored.csv"
]

# Output -- a clean, reusable table of precision per CWE category
OUTPUT_FILE = "results/cwe_precision_table.csv"


def calculate_cwe_precision(files):
    """
    Reads all scored files together and calculates precision
    (TP / (TP + FP)) for each CWE category, combining both tools'
    results into one shared view of "how reliable is this CWE category."
    """
    stats = defaultdict(lambda: {"tp": 0, "fp": 0})

    for filename in files:
        with open(filename, "r") as f:
            for row in csv.DictReader(f):
                cwe = row["cwe"]
                if row["outcome"] == "true_positive":
                    stats[cwe]["tp"] += 1
                elif row["outcome"] == "false_positive":
                    stats[cwe]["fp"] += 1

    results = []
    for cwe, counts in stats.items():
        total = counts["tp"] + counts["fp"]
        if total == 0:
            continue
        precision = counts["tp"] / total
        results.append({
            "cwe": cwe,
            "true_positives": counts["tp"],
            "false_positives": counts["fp"],
            "total_flagged": total,
            "precision": round(precision, 4)
        })

    # Sort by how often this CWE appears (most common first)
    results.sort(key=lambda r: -r["total_flagged"])
    return results


def assign_confidence_tier(precision):
    """
    Converts a raw precision number into a human-readable trust tier.
    These thresholds are a starting point -- adjust based on what
    your actual data distribution looks like.
    """
    if precision >= 0.85:
        return "Tier A - High reliability"
    elif precision >= 0.65:
        return "Tier B - Standard reliability"
    else:
        return "Tier C - Low reliability, flag for manual review"


def save_results(results, path):
    fieldnames = ["cwe", "true_positives", "false_positives", "total_flagged", "precision", "tier"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            row["tier"] = assign_confidence_tier(row["precision"])
            writer.writerow(row)


def print_summary(results):
    print(f"{'CWE':<10}{'TP':<6}{'FP':<6}{'Precision':<12}{'Tier'}")
    print("-" * 65)
    for row in results:
        tier = assign_confidence_tier(row["precision"])
        precision_str = f"{row['precision']:.1%}"
        print(f"{row['cwe']:<10}{row['true_positives']:<6}{row['false_positives']:<6}{precision_str:<12}{tier}")

if __name__ == "__main__":
    print("Calculating precision per CWE category across all scored tools...\n")
    results = calculate_cwe_precision(SCORED_FILES)

    print_summary(results)

    save_results(results, OUTPUT_FILE)
    print(f"\nSaved to {OUTPUT_FILE}")
