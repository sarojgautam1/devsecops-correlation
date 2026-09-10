import csv

CORRELATED_FILE = "results/correlated_findings.csv"
CWE_PRECISION_FILE = "results/cwe_precision_table.csv"
OUTPUT_FILE = "results/prioritized_findings.csv"


def load_cwe_tiers(path):
    """Builds a lookup: CWE number -> tier label, from our precision analysis."""
    lookup = {}
    with open(path, "r") as f:
        for row in csv.DictReader(f):
            # Match against the "CWE-XX" format used in correlated_findings.csv
            lookup[f"CWE-{row['cwe']}"] = row["tier"]
    return lookup


def assign_priority(row, cwe_tiers):
    """
    Combines two signals into one final priority:
    1. How many tools agreed (cross-tool confidence)
    2. How reliable this CWE category has historically been (precision-based tier)
    """
    num_tools = row.get("num_tools_agreeing", "1")
    try:
        num_tools = int(num_tools)
    except ValueError:
        num_tools = 1  # Dependency-check rows use a different confidence format

    cwe = row.get("cwe", "")
    cwe_tier = cwe_tiers.get(cwe, "Unknown")

    # Decision logic: multi-tool agreement always boosts priority,
    # but a historically unreliable CWE still gets flagged for review
    if num_tools >= 2 and "Tier A" in cwe_tier:
        priority = "P1 - Critical (multi-tool + reliable category)"
    elif num_tools >= 2:
        priority = "P2 - High (multi-tool confirmed, verify category)"
    elif "Tier A" in cwe_tier:
        priority = "P2 - High (single-tool, but reliable category)"
    elif "Tier B" in cwe_tier:
        priority = "P3 - Medium (single-tool, standard reliability)"
    else:
        priority = "P4 - Low (single-tool, historically noisy category - manual review recommended)"

    return priority


def process(correlated_path, cwe_tiers, output_path):
    with open(correlated_path, "r") as f:
        rows = list(csv.DictReader(f))

    for row in rows:
        row["priority"] = assign_priority(row, cwe_tiers)

    fieldnames = list(rows[0].keys())
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return rows


if __name__ == "__main__":
    print("Loading CWE reliability tiers...")
    cwe_tiers = load_cwe_tiers(CWE_PRECISION_FILE)

    print("Assigning final priority to every correlated finding...")
    rows = process(CORRELATED_FILE, cwe_tiers, OUTPUT_FILE)

    from collections import Counter
    priority_counts = Counter(r["priority"] for r in rows)

    print("\n--- Final Priority Breakdown ---")
    for priority, count in sorted(priority_counts.items()):
        print(f"{priority}: {count}")

    print(f"\nSaved to {OUTPUT_FILE}")
