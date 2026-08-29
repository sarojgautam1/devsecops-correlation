import json
import re
import csv

# Where the raw Semgrep output lives
INPUT_FILE = "data/raw_sarif/semgrep_output.sarif"

# Where we'll save the cleaned-up, filtered results
OUTPUT_FILE = "results/semgrep_filtered.csv"

# This pattern matches file names like "BenchmarkTest00001.java"
TEST_FILE_PATTERN = re.compile(r"(BenchmarkTest\d+)\.java")


def load_sarif(path):
    """Simply opens the file and reads the JSON inside it."""
    with open(path, "r") as f:
        return json.load(f)


def build_rule_lookup(sarif_data):
    """
    Builds a dictionary: ruleId -> {severity, cwe}
    by reading the rules catalog once, instead of searching it
    repeatedly for every single finding (much faster).
    """
    rules = sarif_data["runs"][0]["tool"]["driver"]["rules"]
    lookup = {}

    for rule in rules:
        rule_id = rule["id"]
        severity = rule.get("defaultConfiguration", {}).get("level", "")

        # Try to extract a real CWE number from the tags list
        cwe = ""
        tags = rule.get("properties", {}).get("tags", [])
        for tag in tags:
            if tag.startswith("CWE-"):
                cwe = tag.split(":")[0].strip()  # e.g. "CWE-95"
                break

        lookup[rule_id] = {"severity": severity, "cwe": cwe}

    return lookup


def extract_findings(sarif_data):
    """
    Walks through every finding Semgrep produced.
    Keeps only the ones inside a real BenchmarkTestXXXXX.java file.
    Now also looks up severity and CWE from the rules catalog.
    """
    kept_findings = []

    rule_lookup = build_rule_lookup(sarif_data)
    results = sarif_data["runs"][0]["results"]

    for finding in results:
        uri = finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        match = TEST_FILE_PATTERN.search(uri)

        if not match:
            continue

        test_name = match.group(1)
        line = finding["locations"][0]["physicalLocation"]["region"]["startLine"]
        rule_id = finding["ruleId"]
        message = finding["message"]["text"]

        # Look up severity and CWE from the rules catalog we built above
        rule_info = rule_lookup.get(rule_id, {"severity": "", "cwe": ""})

        kept_findings.append({
            "test_name": test_name,
            "file": uri,
            "line": line,
            "rule_id": rule_id,
            "cwe": rule_info["cwe"],
            "severity": rule_info["severity"],
            "message": message,
            "tool": "semgrep"
        })

    return kept_findings

def save_to_csv(findings, path):
    """Saves our cleaned-up list into a simple CSV spreadsheet file."""
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["test_name", "file", "line", "rule_id", "cwe", "severity", "message", "tool"])
        writer.writeheader()
        writer.writerows(findings)


if __name__ == "__main__":
    print("Reading raw Semgrep output...")
    sarif_data = load_sarif(INPUT_FILE)

    print("Filtering down to gradeable BenchmarkTest files...")
    findings = extract_findings(sarif_data)

    print(f"Kept {len(findings)} findings out of the original 3154.")

    save_to_csv(findings, OUTPUT_FILE)
    print(f"Saved to {OUTPUT_FILE}")
