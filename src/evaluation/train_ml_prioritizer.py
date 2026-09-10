import csv
import re
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

GROUND_TRUTH_FILE = "data/benchmark/expectedresults-1.2.csv"
CORRELATED_FILE = "results/correlated_findings.csv"
CWE_PRECISION_FILE = "results/cwe_precision_table.csv"
OUTPUT_ML_FINDINGS = "results/ml_prioritized_findings.csv"
OUTPUT_EVAL_SUMMARY = "results/ml_evaluation_summary.csv"


def load_ground_truth(path):
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


def load_cwe_precision(path):
    cwe_prec = {}
    with open(path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cwe_prec[f"CWE-{row['cwe']}"] = float(row["precision"])
    return cwe_prec


def load_correlated_findings(path):
    findings_by_test = {}
    with open(path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            test_name = row.get("test_name", "")
            if not test_name:
                continue
            findings_by_test[test_name] = row
    return findings_by_test


def build_dataset(ground_truth, findings, cwe_prec):
    rows = []
    for test_name, info in ground_truth.items():
        is_real = 1 if info["real_vuln"] else 0
        cwe_raw = f"CWE-{info['cwe']}"
        cwe_prec_val = cwe_prec.get(cwe_raw, 0.5)

        if test_name in findings:
            f = findings[test_name]
            num_tools = int(f.get("num_tools_agreeing", 1))
            tools = f.get("tools_involved", "")
            flagged_semgrep = 1 if "semgrep" in tools else 0
            flagged_sonar = 1 if "sonarqube" in tools else 0
            msg = f.get("sample_message", "")
        else:
            num_tools = 0
            flagged_semgrep = 0
            flagged_sonar = 0
            msg = ""

        rows.append({
            "test_name": test_name,
            "real_vulnerability": is_real,
            "cwe": cwe_raw,
            "num_tools_agreeing": num_tools,
            "flagged_by_semgrep": flagged_semgrep,
            "flagged_by_sonar": flagged_sonar,
            "cwe_historical_precision": cwe_prec_val,
            "message": msg
        })

    return pd.DataFrame(rows)


def train_and_evaluate_ml(df):
    vectorizer = TfidfVectorizer(max_features=25, stop_words="english")
    tfidf_matrix = vectorizer.fit_transform(df["message"]).toarray()
    tfidf_cols = [f"tfidf_{w}" for w in vectorizer.get_feature_names_out()]
    tfidf_df = pd.DataFrame(tfidf_matrix, columns=tfidf_cols)

    cwe_dummies = pd.get_dummies(df["cwe"], prefix="cwe", drop_first=True)

    X = pd.concat([
        df[["num_tools_agreeing", "flagged_by_semgrep", "flagged_by_sonar", "cwe_historical_precision"]],
        cwe_dummies,
        tfidf_df
    ], axis=1)
    
    y = df["real_vulnerability"].values

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    
    oof_probs = np.zeros(len(df))
    oof_preds = np.zeros(len(df))

    rf = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42)

    cv_precisions, cv_recalls, cv_f1s, cv_aucs = [], [], [], []

    for fold, (train_idx, val_idx) in enumerate(skf.split(X, y), 1):
        X_train, y_train = X.iloc[train_idx], y[train_idx]
        X_val, y_val = X.iloc[val_idx], y[val_idx]

        rf.fit(X_train, y_train)

        probs = rf.predict_proba(X_val)[:, 1]
        preds = (probs >= 0.5).astype(int)

        oof_probs[val_idx] = probs
        oof_preds[val_idx] = preds

        prec = precision_score(y_val, preds, zero_division=0)
        rec = recall_score(y_val, preds, zero_division=0)
        f1 = f1_score(y_val, preds, zero_division=0)
        auc = roc_auc_score(y_val, probs)

        cv_precisions.append(prec)
        cv_recalls.append(rec)
        cv_f1s.append(f1)
        cv_aucs.append(auc)

    print("\n--- 5-Fold Stratified Cross-Validation Results ---")
    print(f"Mean CV Precision : {np.mean(cv_precisions):.2%}")
    print(f"Mean CV Recall    : {np.mean(cv_recalls):.2%}")
    print(f"Mean CV F1-Score  : {np.mean(cv_f1s):.4f}")
    print(f"Mean CV ROC-AUC   : {np.mean(cv_aucs):.4f}")

    rf.fit(X, y)
    df["ml_risk_score"] = oof_probs

    def assign_ml_priority(score):
        if score >= 0.85:
            return "P1 - Critical (ML High-Confidence Vulnerability)"
        elif score >= 0.65:
            return "P2 - High (ML Probable Vulnerability)"
        elif score >= 0.45:
            return "P3 - Medium (ML Moderate / Needs Review)"
        else:
            return "P4 - Low (ML Suppressed / Likely False Alarm)"

    df["ml_priority"] = [assign_ml_priority(s) for s in df["ml_risk_score"]]

    importances = rf.feature_importances_
    feat_names = X.columns
    feat_imp = sorted(zip(feat_names, importances), key=lambda x: -x[1])

    print("\n--- Top 10 Feature Importances ---")
    for name, imp in feat_imp[:10]:
        print(f"{name:<35}: {imp:.4f}")

    return df, feat_imp, np.mean(cv_precisions), np.mean(cv_recalls), np.mean(cv_f1s), np.mean(cv_aucs)


def save_summary_table(df, mean_prec, mean_rec, mean_f1, mean_auc):
    ground_truth = df["real_vulnerability"]
    
    semgrep_preds = df["flagged_by_semgrep"]
    semgrep_prec = precision_score(ground_truth, semgrep_preds, zero_division=0)
    semgrep_rec = recall_score(ground_truth, semgrep_preds, zero_division=0)
    semgrep_f1 = f1_score(ground_truth, semgrep_preds, zero_division=0)
    
    sonar_preds = df["flagged_by_sonar"]
    sonar_prec = precision_score(ground_truth, sonar_preds, zero_division=0)
    sonar_rec = recall_score(ground_truth, sonar_preds, zero_division=0)
    sonar_f1 = f1_score(ground_truth, sonar_preds, zero_division=0)

    ml_flagged = (df["ml_risk_score"] >= 0.65).astype(int)
    ml_prec = precision_score(ground_truth, ml_flagged, zero_division=0)
    ml_rec = recall_score(ground_truth, ml_flagged, zero_division=0)
    ml_f1 = f1_score(ground_truth, ml_flagged, zero_division=0)

    summary_rows = [
        {"Model/Tool": "Semgrep Alone", "Precision": f"{semgrep_prec:.2%}", "Recall": f"{semgrep_rec:.2%}", "F1-Score": f"{semgrep_f1:.4f}", "ROC-AUC": "N/A"},
        {"Model/Tool": "SonarQube Alone", "Precision": f"{sonar_prec:.2%}", "Recall": f"{sonar_rec:.2%}", "F1-Score": f"{sonar_f1:.4f}", "ROC-AUC": "N/A"},
        {"Model/Tool": "Hybrid ML Prioritizer (5-Fold CV)", "Precision": f"{mean_prec:.2%}", "Recall": f"{mean_rec:.2%}", "F1-Score": f"{mean_f1:.4f}", "ROC-AUC": f"{mean_auc:.4f}"},
        {"Model/Tool": "Hybrid ML Prioritizer (P1+P2 Filtered)", "Precision": f"{ml_prec:.2%}", "Recall": f"{ml_rec:.2%}", "F1-Score": f"{ml_f1:.4f}", "ROC-AUC": f"{mean_auc:.4f}"}
    ]

    summary_df = pd.DataFrame(summary_rows)
    summary_df.to_csv(OUTPUT_EVAL_SUMMARY, index=False)
    print(f"\nSaved evaluation summary to {OUTPUT_EVAL_SUMMARY}")
    print("\n" + summary_df.to_string(index=False))


if __name__ == "__main__":
    print("Loading Ground Truth and Scanner Data...")
    ground_truth = load_ground_truth(GROUND_TRUTH_FILE)
    cwe_prec = load_cwe_precision(CWE_PRECISION_FILE)
    findings = load_correlated_findings(CORRELATED_FILE)

    print("Building Feature Matrix...")
    df = build_dataset(ground_truth, findings, cwe_prec)

    print("Training & Validating Hybrid ML Prioritization Model...")
    df, feat_imp, mean_prec, mean_rec, mean_f1, mean_auc = train_and_evaluate_ml(df)

    df.to_csv(OUTPUT_ML_FINDINGS, index=False)
    print(f"\nSaved ML prioritized findings to {OUTPUT_ML_FINDINGS}")

    save_summary_table(df, mean_prec, mean_rec, mean_f1, mean_auc)

    print("\n--- ML Priority Tier Distribution ---")
    print(df["ml_priority"].value_counts().to_string())
