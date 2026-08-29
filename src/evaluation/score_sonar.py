import csv

# Your two input files
GROUND_TRUTH_FILE = "data/benchmark/expectedresults-1.2.csv"
FINDINGS_FILE = "results/sonar_filtered.csv"

# Where we'll save the final scored results
OUTPUT_FILE = "results/sonar_scored.csv"


def load_ground_truth(path):
    """Reads the answer key into a dictionary."""
    ground_truth = {}
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            parts = line.split(",")
            test_name = parts[0].strip()
            real_vuln = parts[2].strip().lower() == "true"
            cwe = parts[3].strip()
            ground_truth[test_name] = {"real_vuln": real_vuln, "cwe": cwe}
    return ground_truth


def load_flagged_tests(path):
    """Reads Sonar's filtered findings into a set of flagged test names."""
    flagged = set()
    with open(path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            flagged.add(row["test_name"])
    return flagged


def score_results(ground_truth, flagged_tests):
    """Sorts every test case into one of 4 buckets."""
    scored_rows = []

    for test_name, info in ground_truth.items():
        is_real = info["real_vuln"]
        was_flagged = test_name in flagged_tests

        if is_real and was_flagged:
            outcome = "true_positive"
        elif not is_real and was_flagged:
            outcome = "false_positive"
        elif is_real and not was_flagged:
            outcome = "false_negative"
        else:
            outcome = "true_negative"

        scored_rows.append({
            "test_name": test_name,
            "cwe": info["cwe"],
            "real_vulnerability": is_real,
            "flagged_by_sonar": was_flagged,
            "outcome": outcome
        })

    return scored_rows


def save_and_summarize(scored_rows, path):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["test_name", "cwe", "real_vulnerability", "flagged_by_sonar", "outcome"])
        writer.writeheader()
        writer.writerows(scored_rows)

    tp = sum(1 for r in scored_rows if r["outcome"] == "true_positive")
    fp = sum(1 for r in scored_rows if r["outcome"] == "false_positive")
    fn = sum(1 for r in scored_rows if r["outcome"] == "false_negative")
    tn = sum(1 for r in scored_rows if r["outcome"] == "true_negative")

    print("\n--- Plain English Summary (SonarQube) ---")
    print(f"Correct catches (true positives):     {tp}")
    print(f"False alarms (false positives):       {fp}")
    print(f"Missed vulnerabilities (false neg):   {fn}")
    print(f"Correctly stayed quiet (true neg):    {tn}")

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0

    print(f"\nPrecision (of what it flagged, % actually real): {precision:.2%}")
    print(f"Recall (of real vulnerabilities, % it caught):   {recall:.2%}")


if __name__ == "__main__":
    print("Loading ground truth answer key...")
    ground_truth = load_ground_truth(GROUND_TRUTH_FILE)

    print("Loading SonarQube's flagged test cases...")
    flagged_tests = load_flagged_tests(FINDINGS_FILE)

    print("Scoring every test case...")
    scored_rows = score_results(ground_truth, flagged_tests)

    save_and_summarize(scored_rows, OUTPUT_FILE)
    print(f"\nFull scored table saved to {OUTPUT_FILE}")
