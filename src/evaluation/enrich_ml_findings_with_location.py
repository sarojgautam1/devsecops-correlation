import csv

ML_FILE = "results/ml_prioritized_findings.csv"
CORRELATED_FILE = "results/correlated_findings.csv"
OUTPUT_FILE = "results/ml_prioritized_findings_with_location.csv"


def load_locations(path):
    """
    Builds a lookup: test_name -> (file, line)
    from correlated_findings.csv. If a test_name has multiple
    correlated findings, we just take the first one's location --
    good enough for LLM verification purposes, since we mainly
    need SOME representative code snippet for that test case.
    """
    locations = {}
    with open(path, "r") as f:
        for row in csv.DictReader(f):
            test_name = row.get("test_name", "")
            if not test_name or test_name in locations:
                continue
            locations[test_name] = {
                "file": row.get("file", ""),
                "line": row.get("line", "")
            }
    return locations


def enrich(ml_path, locations, output_path):
    rows = list(csv.DictReader(open(ml_path)))

    for row in rows:
        loc = locations.get(row["test_name"], {"file": "", "line": ""})
        row["file"] = loc["file"]
        row["line"] = loc["line"]

    fieldnames = list(rows[0].keys())
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    matched = sum(1 for r in rows if r["file"])
    print(f"{matched}/{len(rows)} rows matched to a file/line location.")
    print(f"Saved to {output_path}")


if __name__ == "__main__":
    print("Loading file/line locations from correlated_findings.csv...")
    locations = load_locations(CORRELATED_FILE)

    print("Enriching ML findings with location data...")
    enrich(ML_FILE, locations, OUTPUT_FILE)
