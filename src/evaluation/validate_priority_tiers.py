import csv
from collections import defaultdict

GROUND_TRUTH_FILE = "data/benchmark/expectedresults-1.2.csv"
PRIORITIZED_FILE = "results/prioritized_findings.csv"
OUTPUT_FILE = "results/priority_tier_validation.csv"


def load_ground_truth(path):
    """Reads the answer key into a dict keyed by test_name."""
    ground_truth = {}
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            parts = line.split(",")
            test_name = parts[0].strip()
            ground_truth[test_name] = parts[2].strip().lower() == "true"
    return ground_truth


def validate_tiers(prioritized_path, ground_truth):
    """
    For every finding, checks its assigned priority (P1-P4) against
    whether it's actually a real vulnerability, per the ground truth.
    This proves (or disproves) whether higher-priority tiers really
    do contain more genuine vulnerabilities than lower-priority tiers.
    """
    rows = list(csv.DictReader(open(prioritized_path)))
    stats = defaultdict(lambda: {"tp": 0, "fp": 0})

    for row in rows:
        test_name = row.get("test_name", "")
        if test_name not in ground_truth:
            continue  # Dependency-check rows or ungraded findings -- skip

        # Extract just "P1", "P2", etc. from the full label
        priority_short = row["priority"].split(" - ")[0]

        if ground_truth[test_name]:
            stats[priority_short]["tp"] += 1
        else:
            stats[priority_short]["fp"] += 1

    results = []
    for priority in sorted(stats.keys()):
        s = stats[priority]
        total = s["tp"] + s["fp"]
        precision = s["tp"] / total if total > 0 else 0
        results.append({
            "priority": priority,
            "true_positives": s["tp"],
            "false_positives": s["fp"],
            "total": total,
            "precision": round(precision, 4)
        })

    return results


def save_and_print(results, path):
    fieldnames = ["priority", "true_positives", "false_positives", "total", "precision"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"{'Priority':<10}{'TP':<6}{'FP':<6}{'Total':<8}{'Precision'}")
    print("-" * 45)
    for r in results:
        precision_str = f"{r['precision']:.1%}"
        print(f"{r['priority']:<10}{r['true_positives']:<6}{r['false_positives']:<6}{r['total']:<8}{precision_str}")


if __name__ == "__main__":
    print("Loading ground truth...")
    ground_truth = load_ground_truth(GROUND_TRUTH_FILE)

    print("Validating priority tiers against ground truth...\n")
    results = validate_tiers(PRIORITIZED_FILE, ground_truth)

    save_and_print(results, OUTPUT_FILE)
    print(f"\nSaved to {OUTPUT_FILE}")
