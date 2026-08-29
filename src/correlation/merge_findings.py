import csv

# Input files from all three tools
SEMGREP_FILE = "results/semgrep_filtered.csv"
SONAR_FILE = "results/sonar_filtered_with_cwe.csv"
DEPCHECK_FILE = "results/depcheck_summary.csv"

# Output: one unified table
OUTPUT_FILE = "results/merged_findings.csv"


def load_semgrep():
    """Reads Semgrep findings, tags each row with a common schema."""
    rows = []
    with open(SEMGREP_FILE, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({
                "tool": "semgrep",
                "test_name": row["test_name"],
                "file": row["file"],
                "line": row["line"],
                "cwe": row["cwe"],
                "rule_id": row["rule_id"],
                "severity": row["severity"],  # Semgrep output didn't include a clean severity field
                "message": row["message"]
            })
    return rows


def load_sonar():
    """Reads SonarQube findings, tags each row with a common schema."""
    rows = []
    with open(SONAR_FILE, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({
                "tool": "sonarqube",
                "test_name": row["test_name"],
                "file": row["file"],
                "line": row["line"],
                "cwe": row["cwe"],
                "rule_id": row["rule_id"],
                "severity": row["severity"],
                "message": row["message"]
            })
    return rows


def load_depcheck():
    """
    Reads Dependency-Check findings.
    NOTE: these don't map to a BenchmarkTestXXXXX test_name,
    since they're library-level, not source-code-level.
    We keep test_name empty on purpose -- this is intentional,
    not a bug -- and we'll handle SCA correlation separately
    from SAST correlation later, per our literature review's guidance.
    """
    rows = []
    with open(DEPCHECK_FILE, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({
                "tool": "dependency-check",
                "test_name": "",  # intentionally blank -- not a graded test case
                "file": row["file"],
                "line": "",  # library-level, not a specific line
                "cwe": "",
                "rule_id": row["cve_id"],
                "severity": row["severity"],
                "message": row["message"]
            })
    return rows


def save_merged(all_rows, path):
    with open(path, "w", newline="") as f:
        fieldnames = ["tool", "test_name", "file", "line", "cwe","rule_id", "severity", "message"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)


if __name__ == "__main__":
    print("Loading Semgrep findings...")
    semgrep_rows = load_semgrep()
    print(f"  {len(semgrep_rows)} rows")

    print("Loading SonarQube findings...")
    sonar_rows = load_sonar()
    print(f"  {len(sonar_rows)} rows")

    print("Loading Dependency-Check findings...")
    depcheck_rows = load_depcheck()
    print(f"  {len(depcheck_rows)} rows")

    all_rows = semgrep_rows + sonar_rows + depcheck_rows

    save_merged(all_rows, OUTPUT_FILE)
    print(f"\nTotal merged rows: {len(all_rows)}")
    print(f"Saved to {OUTPUT_FILE}")
