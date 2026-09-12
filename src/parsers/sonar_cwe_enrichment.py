import csv
import re
import requests
import time
import os
SONAR_URL = "http://localhost:9000"
SONAR_TOKEN = os.environ.get("SONAR_TOKEN")
INPUT_FILE = "results/sonar_filtered.csv"
OUTPUT_FILE = "results/sonar_filtered_with_cwe.csv"

# Matches links like "cwe.mitre.org/data/definitions/327"
CWE_PATTERN = re.compile(r"cwe\.mitre\.org/data/definitions/(\d+)")


def get_unique_rule_ids(path):
    """Reads the CSV and returns a set of every distinct rule_id used."""
    rule_ids = set()
    with open(path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rule_ids.add(row["rule_id"])
    return rule_ids


def fetch_cwe_for_rule(rule_id):
    """
    Calls SonarQube's API for one rule, searches its description
    text for the first CWE number mentioned, and returns it.
    """
    response = requests.get(
        f"{SONAR_URL}/api/rules/show",
        auth=(SONAR_TOKEN, ""),
        params={"key": rule_id}
    )

    if response.status_code != 200:
        return ""  # rule lookup failed, leave blank rather than crash

    data = response.json()
    sections = data.get("rule", {}).get("descriptionSections", [])

    # Search every description section's HTML content for a CWE link
    for section in sections:
        content = section.get("content", "")
        match = CWE_PATTERN.search(content)
        if match:
            return f"CWE-{match.group(1)}"

    return ""  # no CWE mentioned for this rule


def build_rule_cwe_lookup(rule_ids):
    """Builds rule_id -> CWE lookup by calling the API once per unique rule."""
    lookup = {}
    total = len(rule_ids)

    for i, rule_id in enumerate(rule_ids, start=1):
        print(f"Looking up {i}/{total}: {rule_id}")
        lookup[rule_id] = fetch_cwe_for_rule(rule_id)
        time.sleep(0.1)  # small pause to be polite to the local server

    return lookup


def enrich_and_save(input_path, output_path, lookup):
    """Reads the original CSV, adds a new 'cwe' column, saves the result."""
    with open(input_path, "r") as infile:
        reader = csv.DictReader(infile)
        rows = list(reader)
        fieldnames = reader.fieldnames + ["cwe"]

    for row in rows:
        row["cwe"] = lookup.get(row["rule_id"], "")

    with open(output_path, "w", newline="") as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    print("Finding unique rule IDs in your Sonar findings...")
    rule_ids = get_unique_rule_ids(INPUT_FILE)
    print(f"Found {len(rule_ids)} unique rules.\n")

    print("Fetching CWE info for each rule from SonarQube API...")
    lookup = build_rule_cwe_lookup(rule_ids)

    print("\nEnriching findings with CWE numbers...")
    enrich_and_save(INPUT_FILE, OUTPUT_FILE, lookup)

    matched = sum(1 for v in lookup.values() if v)
    print(f"\n{matched}/{len(lookup)} rules had a CWE number found.")
    print(f"Saved to {OUTPUT_FILE}")
