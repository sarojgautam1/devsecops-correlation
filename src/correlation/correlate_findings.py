import csv
from collections import defaultdict

INPUT_FILE = "results/merged_findings.csv"
OUTPUT_FILE = "results/correlated_findings.csv"

# How close two line numbers need to be to be considered "the same area"
LINE_PROXIMITY = 5


def load_merged_findings(path):
    with open(path, "r") as f:
        reader = csv.DictReader(f)
        return list(reader)


def split_by_category(rows):
    """
    Splits findings into two groups, since they need different matching logic:
    - sast_rows: have a test_name (Semgrep, SonarQube) -- source code findings
    - sca_rows: no test_name (Dependency-Check) -- library findings
    """
    sast_rows = [r for r in rows if r["test_name"]]
    sca_rows = [r for r in rows if not r["test_name"]]
    return sast_rows, sca_rows


def correlate_sast(sast_rows):
    """
    Groups SAST findings by test_name, then within each test_name,
    merges findings that share the same CWE and are on nearby lines --
    regardless of which tool reported them.
    """
    grouped_by_test = defaultdict(list)
    for row in sast_rows:
        grouped_by_test[row["test_name"]].append(row)

    correlated = []

    for test_name, findings in grouped_by_test.items():
        used = [False] * len(findings)

        for i, finding_a in enumerate(findings):
            if used[i]:
                continue  # already merged into an earlier group

            group = [finding_a]
            used[i] = True

            for j in range(i + 1, len(findings)):
                if used[j]:
                    continue

                finding_b = findings[j]

                same_cwe = (
                    finding_a["cwe"] == finding_b["cwe"]
                    and finding_a["cwe"] != ""
                )

                try:
                    line_a = int(finding_a["line"])
                    line_b = int(finding_b["line"])
                    close_lines = abs(line_a - line_b) <= LINE_PROXIMITY
                    exact_same_line = line_a == line_b
                except ValueError:
                    close_lines = False
                    exact_same_line = False

                # Rule 1: same CWE + nearby lines (our original rule)
                rule1_match = same_cwe and close_lines

                # Rule 2 (NEW): exact same line, even if CWE differs slightly --
                # different tools sometimes use closely related but different
                # CWE numbers for what is really the same underlying issue
                rule2_match = exact_same_line and not same_cwe

                if rule1_match or rule2_match:
                    group.append(finding_b)
                    used[j] = True
            # Build one correlated record from the group
            tools_involved = sorted(set(f["tool"] for f in group))
            cwes_in_group = set(f["cwe"] for f in group)
            if len(group) == 1:
                confidence = "single-tool"
            elif len(cwes_in_group) == 1:
                confidence = "high (same CWE)"
            else:
                confidence = "medium (same line, different CWE label)"

            correlated.append({
                "test_name": test_name,
                "cwe": finding_a["cwe"],
                "file": finding_a["file"],
                "line": finding_a["line"],
                "tools_involved": ";".join(tools_involved),
                "num_tools_agreeing": len(tools_involved),
                "confidence": confidence,
                "severities": ";".join(sorted(set(f["severity"] for f in group if f["severity"]))),
                "sample_message": finding_a["message"]
            })

    return correlated


def correlate_sca(sca_rows):
    """
    Groups Dependency-Check findings by CVE (rule_id), since the same CVE
    often appears across multiple files (e.g. bootstrap.js and bootstrap.min.js).
    """
    grouped_by_cve = defaultdict(list)
    for row in sca_rows:
        grouped_by_cve[row["rule_id"]].append(row)

    correlated = []

    for cve, findings in grouped_by_cve.items():
        files_involved = sorted(set(f["file"] for f in findings))

        correlated.append({
            "test_name": "",  # not applicable for SCA
            "cwe": cve,        # storing the CVE here for consistency
            "file": ";".join(files_involved),
            "line": "",
            "tools_involved": "dependency-check",
            "num_tools_agreeing": 1,
            "confidence": f"appears in {len(files_involved)} file(s)",
            "severities": findings[0]["severity"],
            "sample_message": findings[0]["message"]
        })

    return correlated


def save_correlated(rows, path):
    fieldnames = ["test_name", "cwe", "file", "line", "tools_involved",
                  "num_tools_agreeing", "confidence", "severities", "sample_message"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    print("Loading merged findings...")
    rows = load_merged_findings(INPUT_FILE)
    print(f"  {len(rows)} total rows")

    sast_rows, sca_rows = split_by_category(rows)
    print(f"  {len(sast_rows)} SAST rows (Semgrep + SonarQube)")
    print(f"  {len(sca_rows)} SCA rows (Dependency-Check)")

    print("\nCorrelating SAST findings (by test_name + CWE + line proximity)...")
    sast_correlated = correlate_sast(sast_rows)
    print(f"  {len(sast_rows)} raw findings -> {len(sast_correlated)} correlated findings")

    print("\nCorrelating SCA findings (by CVE across files)...")
    sca_correlated = correlate_sca(sca_rows)
    print(f"  {len(sca_rows)} raw findings -> {len(sca_correlated)} correlated findings")

    all_correlated = sast_correlated + sca_correlated
    save_correlated(all_correlated, OUTPUT_FILE)

    multi_tool_count = sum(1 for r in sast_correlated if r["num_tools_agreeing"] > 1)
    print(f"\n{multi_tool_count} findings were confirmed by more than one tool.")
    print(f"Saved to {OUTPUT_FILE}")
