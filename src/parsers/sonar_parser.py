import requests
import re
import csv
import time
import os
# SonarQube connection details
SONAR_URL = "http://localhost:9000"
SONAR_TOKEN = os.environ.get("SONAR_TOKEN")
PROJECT_KEY = "owasp-benchmark"

# Where we'll save the cleaned-up, filtered results
OUTPUT_FILE = "results/sonar_filtered.csv"

# This pattern matches file names like "BenchmarkTest00001.java"
TEST_FILE_PATTERN = re.compile(r"(BenchmarkTest\d+)\.java")

PAGE_SIZE = 500  # SonarQube's max issues per request


def fetch_all_issues():
    """
    Loops through every page of results from SonarQube's API.
    Keeps going until we've collected every single issue.
    """
    all_issues = []
    page = 1

    while True:
        print(f"Fetching page {page}...")
        response = requests.get(
            f"{SONAR_URL}/api/issues/search",
            auth=(SONAR_TOKEN, ""),
            params={
                "componentKeys": PROJECT_KEY,
                "ps": PAGE_SIZE,
                "p": page
            }
        )
        data = response.json()

        issues = data.get("issues", [])
        all_issues.extend(issues)

        total = data.get("total", 0)

        # Stop once we've collected everything
        if len(all_issues) >= total or not issues:
            break

        page += 1
        time.sleep(0.2)  # small pause to be polite to the local server

    print(f"Fetched {len(all_issues)} total issues across {page} pages.")
    return all_issues


def filter_issues(issues):
    """
    Keeps only issues that are:
    1. Inside a real BenchmarkTestXXXXX.java file
    2. Actually security vulnerabilities (not code smells or generic bugs)
    """
    kept_findings = []

    for issue in issues:
        component = issue.get("component", "")

        # Check if the file matches "BenchmarkTestXXXXX.java"
        match = TEST_FILE_PATTERN.search(component)
        if not match:
            continue  # not a gradeable test file — skip it

        # Only keep actual vulnerabilities, not code smells / bugs
        if issue.get("type") != "VULNERABILITY":
            continue

        test_name = match.group(1)  # e.g. "BenchmarkTest00001"

        kept_findings.append({
            "test_name": test_name,
            "file": component,
            "line": issue.get("line", ""),
            "rule_id": issue.get("rule", ""),
            "severity": issue.get("severity", ""),
            "message": issue.get("message", ""),
            "tool": "sonarqube"
        })

    return kept_findings


def save_to_csv(findings, path):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["test_name", "file", "line", "rule_id", "severity", "message", "tool"])
        writer.writeheader()
        writer.writerows(findings)


if __name__ == "__main__":
    all_issues = fetch_all_issues()

    print("Filtering down to gradeable BenchmarkTest files with type=VULNERABILITY...")
    findings = filter_issues(all_issues)

    print(f"Kept {len(findings)} findings out of {len(all_issues)} total issues.")

    save_to_csv(findings, OUTPUT_FILE)
    print(f"Saved to {OUTPUT_FILE}")
