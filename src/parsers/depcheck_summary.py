import json
import csv

INPUT_FILE = "data/raw_sarif/depcheck_output/dependency-check-report.sarif"
OUTPUT_FILE = "results/depcheck_summary.csv"


def load_sarif(path):
    with open(path, "r") as f:
        return json.load(f)


def extract_findings(sarif_data):
    """
    Pulls out every CVE finding, regardless of which file it's in.
    Unlike Semgrep/Sonar, we don't filter by BenchmarkTestXXXXX
    because these are library-level issues, not test-case-level ones.
    """
    findings = []
    results = sarif_data["runs"][0]["results"]

    for finding in results:
        cve_id = finding.get("ruleId", "")
        message = finding.get("message", {}).get("text", "")
        severity = finding.get("level", "")

        # Pull the file path and the library name/version
        location = finding["locations"][0]
        file_path = location["physicalLocation"]["artifactLocation"]["uri"]

        library = ""
        if "logicalLocations" in location:
            library = location["logicalLocations"][0].get("fullyQualifiedName", "")

        findings.append({
            "cve_id": cve_id,
            "library": library,
            "file": file_path,
            "severity": severity,
            "message": message,
            "tool": "dependency-check"
        })

    return findings


def save_to_csv(findings, path):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["cve_id", "library", "file", "severity", "message", "tool"])
        writer.writeheader()
        writer.writerows(findings)


if __name__ == "__main__":
    print("Reading Dependency-Check output...")
    sarif_data = load_sarif(INPUT_FILE)

    print("Extracting all CVE findings...")
    findings = extract_findings(sarif_data)

    print(f"Found {len(findings)} known vulnerabilities in dependencies.")

    save_to_csv(findings, OUTPUT_FILE)
    print(f"Saved to {OUTPUT_FILE}")
