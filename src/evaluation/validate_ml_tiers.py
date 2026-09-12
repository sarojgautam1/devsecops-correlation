import pandas as pd

INPUT_FILE = "results/ml_prioritized_findings.csv"
OUTPUT_FILE = "results/ml_tier_validation.csv"


def extract_tier_label(full_priority_string):
    """Pulls just 'P1', 'P2', etc. from the full descriptive label."""
    return full_priority_string.split(" - ")[0]


def validate(path):
    df = pd.read_csv(path)
    df["tier"] = df["ml_priority"].apply(extract_tier_label)

    results = []
    for tier in sorted(df["tier"].unique()):
        subset = df[df["tier"] == tier]
        tp = (subset["real_vulnerability"] == 1).sum()
        fp = (subset["real_vulnerability"] == 0).sum()
        total = tp + fp
        precision = tp / total if total > 0 else 0
        results.append({
            "tier": tier,
            "true_positives": tp,
            "false_positives": fp,
            "total": total,
            "precision": round(precision, 4)
        })

    return pd.DataFrame(results)


if __name__ == "__main__":
    result_df = validate(INPUT_FILE)
    result_df.to_csv(OUTPUT_FILE, index=False)
    print(result_df.to_string(index=False))
    print(f"\nSaved to {OUTPUT_FILE}")
