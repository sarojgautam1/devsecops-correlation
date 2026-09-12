import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

PLOTS_DIR = "results/plots"
os.makedirs(PLOTS_DIR, exist_ok=True)

plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
sns.set_theme(style="whitegrid")

GROUND_TRUTH_FILE = "data/benchmark/expectedresults-1.2.csv"


def load_ground_truth_counts(path):
    """Returns (total_real_positives, total_real_negatives) from the answer key."""
    pos, neg = 0, 0
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            parts = line.split(",")
            if parts[2].strip().lower() == "true":
                pos += 1
            else:
                neg += 1
    return pos, neg


def pct_to_float(s):
    """Converts a string like '69.45%' into 69.45 (float)."""
    return float(str(s).replace("%", ""))


def plot_performance_comparison(total_pos):
    ml_summary = pd.read_csv("results/ml_evaluation_summary.csv")
    heuristic = pd.read_csv("results/priority_tier_validation.csv")

    p1_row = heuristic[heuristic["priority"] == "P1"].iloc[0]
    p1_precision = p1_row["precision"] * 100
    p1_recall = (p1_row["true_positives"] / total_pos) * 100
    p1_f1 = 2 * p1_precision * p1_recall / (p1_precision + p1_recall) if (p1_precision + p1_recall) > 0 else 0

    rows = []
    for _, r in ml_summary.iterrows():
        rows.append({
            "Tool/Model": r["Model/Tool"],
            "Precision": pct_to_float(r["Precision"]),
            "Recall": pct_to_float(r["Recall"]),
            "F1-Score": float(r["F1-Score"]) * 100
        })

    rows.insert(2, {
        "Tool/Model": "Heuristic Engine (P1)",
        "Precision": p1_precision,
        "Recall": p1_recall,
        "F1-Score": p1_f1
    })

    df = pd.DataFrame(rows)
    df_melted = df.melt(id_vars='Tool/Model', var_name='Metric', value_name='Percentage')

    plt.figure(figsize=(13, 6))
    ax = sns.barplot(data=df_melted, x='Tool/Model', y='Percentage', hue='Metric',
                      palette=['#1f77b4', '#ff7f0e', '#2ca02c'])
    plt.title('DevSecOps Correlation Performance Comparison (%)', fontsize=14, fontweight='bold', pad=15)
    plt.ylabel('Percentage (%) / F1 Score x100', fontsize=12)
    plt.xlabel('Tool / Priority Model', fontsize=12)
    plt.ylim(0, 115)

    for p in ax.patches:
        height = p.get_height()
        if height > 0:
            ax.annotate(f'{height:.1f}%', (p.get_x() + p.get_width() / 2., height),
                        ha='center', va='bottom', fontsize=9, xytext=(0, 3), textcoords='offset points')

    plt.xticks(rotation=15, ha='right')
    plt.tight_layout()
    plt.savefig(f"{PLOTS_DIR}/01_performance_comparison.png", dpi=300)
    plt.close()
    print(f"Saved {PLOTS_DIR}/01_performance_comparison.png")


def build_confusion_matrix_from_scored(path):
    """Reads a score_*.py output CSV and builds a 2x2 confusion matrix."""
    df = pd.read_csv(path)
    tp = (df["outcome"] == "true_positive").sum()
    fp = (df["outcome"] == "false_positive").sum()
    fn = (df["outcome"] == "false_negative").sum()
    tn = (df["outcome"] == "true_negative").sum()
    return np.array([[tn, fp], [fn, tp]])


def build_confusion_matrix_from_ml(path, threshold=0.5):
    """
    Reconstructs the ML model's confusion matrix using ml_risk_score
    (which stores out-of-fold probabilities) at the same 0.5 threshold
    used during cross-validation, so this matches the reported CV metrics.
    """
    df = pd.read_csv(path)
    pred = (df["ml_risk_score"] >= threshold).astype(int)
    actual = df["real_vulnerability"].astype(int)

    tp = ((pred == 1) & (actual == 1)).sum()
    fp = ((pred == 1) & (actual == 0)).sum()
    fn = ((pred == 0) & (actual == 1)).sum()
    tn = ((pred == 0) & (actual == 0)).sum()
    return np.array([[tn, fp], [fn, tp]])


def plot_confusion_matrices():
    semgrep_cm = build_confusion_matrix_from_scored("results/semgrep_scored.csv")
    sonar_cm = build_confusion_matrix_from_scored("results/sonar_scored.csv")
    ml_cm = build_confusion_matrix_from_ml("results/ml_prioritized_findings.csv")

    fig, axes = plt.subplots(1, 3, figsize=(16, 5))

    cms = [
        (semgrep_cm, "Semgrep Alone", axes[0]),
        (sonar_cm, "SonarQube Alone", axes[1]),
        (ml_cm, "Hybrid ML Model (5-Fold CV, leak-free)", axes[2])
    ]

    for cm, title, ax in cms:
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax, cbar=False,
                    xticklabels=['Predicted FP', 'Predicted TP'],
                    yticklabels=['Actual FP', 'Actual TP'], annot_kws={"size": 11, "weight": "bold"})
        ax.set_title(title, fontsize=12, fontweight='bold')

    plt.suptitle('Confusion Matrix Comparison (True Positives vs False Positives)', fontsize=14, fontweight='bold', y=1.02)
    plt.tight_layout()
    plt.savefig(f"{PLOTS_DIR}/02_confusion_matrices.png", dpi=300)
    plt.close()
    print(f"Saved {PLOTS_DIR}/02_confusion_matrices.png")


FEATURE_DISPLAY_NAMES = {
    "num_tools_agreeing": "Cross-Tool Agreement (num_tools)",
    "flagged_by_semgrep": "Flagged by Semgrep",
    "flagged_by_sonar": "Flagged by SonarQube",
    "cwe_historical_precision": "CWE Historical Precision (fold-safe)",
}


def plot_feature_importance():
    df_feat = pd.read_csv("results/feature_importance.csv").head(10).copy()
    df_feat["display_name"] = df_feat["feature"].apply(
        lambda f: FEATURE_DISPLAY_NAMES.get(f, f.replace("tfidf_", 'TF-IDF Keyword "') + '"' if f.startswith("tfidf_")
                  else f.replace("cwe_", "CWE Category ") if f.startswith("cwe_")
                  else f)
    )
    df_feat = df_feat.sort_values("importance", ascending=True)

    plt.figure(figsize=(10, 6))
    bars = plt.barh(df_feat['display_name'], df_feat['importance'] * 100, color='#2b5c8f')
    plt.title('Top 10 Feature Importances in Hybrid ML Model (%) — Leak-Free', fontsize=13, fontweight='bold', pad=15)
    plt.xlabel('Importance Weight (%)', fontsize=12)

    for bar in bars:
        width = bar.get_width()
        plt.text(width + 0.3, bar.get_y() + bar.get_height()/2, f'{width:.1f}%', va='center', fontsize=10, fontweight='bold')

    plt.xlim(0, max(df_feat['importance'] * 100) + 5)
    plt.tight_layout()
    plt.savefig(f"{PLOTS_DIR}/03_feature_importance.png", dpi=300)
    plt.close()
    print(f"Saved {PLOTS_DIR}/03_feature_importance.png")


def plot_cwe_precision():
    cwe_df = pd.read_csv("results/cwe_precision_table.csv")
    cwe_df['precision_pct'] = cwe_df['precision'] * 100
    cwe_df = cwe_df.sort_values('precision_pct', ascending=False)

    plt.figure(figsize=(10, 6))
    colors = ['#2ca02c' if p >= 85 else '#ff7f0e' if p >= 65 else '#d62728' for p in cwe_df['precision_pct']]
    bars = plt.bar(cwe_df['cwe'].astype(str), cwe_df['precision_pct'], color=colors)

    plt.title('Scanner Precision by Vulnerability Category (CWE)', fontsize=14, fontweight='bold', pad=15)
    plt.ylabel('Precision (%)', fontsize=12)
    plt.xlabel('CWE Category', fontsize=12)
    plt.axhline(85, color='green', linestyle='--', label='Tier A (>=85%)')
    plt.axhline(65, color='orange', linestyle='--', label='Tier B (>=65%)')
    plt.ylim(0, 115)

    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + 2, f'{height:.1f}%', ha='center', va='bottom', fontsize=9, fontweight='bold')

    plt.legend(loc='upper right')
    plt.tight_layout()
    plt.savefig(f"{PLOTS_DIR}/04_cwe_precision_breakdown.png", dpi=300)
    plt.close()
    print(f"Saved {PLOTS_DIR}/04_cwe_precision_breakdown.png")


def plot_priority_distribution():
    df = pd.read_csv("results/ml_prioritized_findings.csv")
    df["tier"] = df["ml_priority"].apply(lambda s: s.split(" - ")[0])

    tier_order = ["P1", "P2", "P3", "P4"]
    tier_labels = {
        "P1": "P1 - Critical Risk",
        "P2": "P2 - High Risk",
        "P3": "P3 - Medium Risk",
        "P4": "P4 - Low / Suppressed"
    }
    counts_series = df["tier"].value_counts().reindex(tier_order).fillna(0)

    tiers = [tier_labels[t] for t in tier_order]
    counts = counts_series.values
    colors = ['#d62728', '#ff7f0e', '#1f77b4', '#7f7f7f']

    plt.figure(figsize=(8, 6))
    plt.pie(counts, labels=tiers, autopct='%1.1f%%', startangle=140, colors=colors,
            explode=(0.05, 0.05, 0, 0), textprops={'fontsize': 11, 'weight': 'bold'})
    plt.title(f'ML Risk Triage Distribution ({int(sum(counts))} OWASP Benchmark Cases) — Leak-Free', fontsize=13, fontweight='bold', pad=15)
    plt.tight_layout()
    plt.savefig(f"{PLOTS_DIR}/05_ml_priority_distribution.png", dpi=300)
    plt.close()
    print(f"Saved {PLOTS_DIR}/05_ml_priority_distribution.png")


if __name__ == '__main__':
    total_pos, total_neg = load_ground_truth_counts(GROUND_TRUTH_FILE)
    print(f"Ground truth: {total_pos} real vulnerabilities, {total_neg} safe test cases\n")

    plot_performance_comparison(total_pos)
    plot_confusion_matrices()
    plot_feature_importance()
    plot_cwe_precision()
    plot_priority_distribution()
    print("\nAll plots successfully generated from live result files (no hardcoded numbers).")
