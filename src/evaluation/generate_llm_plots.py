import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

PLOTS_DIR = "results/plots"
os.makedirs(PLOTS_DIR, exist_ok=True)

plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
sns.set_theme(style="whitegrid")

# Real, validated numbers from the two experimental scales.
# 'Blind (n=400)' is intentionally absent -- that run is still pending
# (the Gemini attempt was explicitly discarded to avoid a cross-model
# confound; a same-model Groq blind run at n=400 has not yet completed).
DATA = [
    {"approach": "Rule-Based\nBaseline",  "scale": "Pilot (n=91)",     "precision": 56.0, "recall": None},
    {"approach": "Rule-Based\nBaseline",  "scale": "Full-Scale (n=400)","precision": 56.5, "recall": None},
    {"approach": "Anchored\nPrompt",      "scale": "Pilot (n=91)",     "precision": 56.4, "recall": 86.3},
    {"approach": "Anchored\nPrompt",      "scale": "Full-Scale (n=400)","precision": 57.0, "recall": 90.3},
    {"approach": "Blind\nPrompt",         "scale": "Pilot (n=91)",     "precision": 57.7, "recall": 88.2},
]

df = pd.DataFrame(DATA)

fig, axes = plt.subplots(1, 2, figsize=(14, 6))

# --- Panel A: Precision stability across scale ---
sns.barplot(data=df, x="approach", y="precision", hue="scale", ax=axes[0],
            palette=["#8c9eb5", "#006994"])
axes[0].set_title("Precision: Pilot vs. Full-Scale Sample", fontsize=13, fontweight="bold")
axes[0].set_ylabel("Precision (%)")
axes[0].set_xlabel("")
axes[0].set_ylim(0, 75)
axes[0].axhline(56.0, color="#C0392B", linestyle="--", linewidth=1, label="Baseline reference (56.0%)")
for p in axes[0].patches:
    h = p.get_height()
    if h > 0:
        axes[0].annotate(f"{h:.1f}%", (p.get_x() + p.get_width()/2, h),
                          ha="center", va="bottom", fontsize=9, xytext=(0, 3), textcoords="offset points")
axes[0].legend(loc="upper left", fontsize=8)

# --- Panel B: Recall after filtering (only where LLM filtering was applied) ---
recall_df = df[df["recall"].notna()]
sns.barplot(data=recall_df, x="approach", y="recall", hue="scale", ax=axes[1],
            palette=["#8c9eb5", "#006994"])
axes[1].set_title("Recall After LLM Filtering: Pilot vs. Full-Scale", fontsize=13, fontweight="bold")
axes[1].set_ylabel("Recall (%)")
axes[1].set_xlabel("")
axes[1].set_ylim(0, 105)
for p in axes[1].patches:
    h = p.get_height()
    if h > 0:
        axes[1].annotate(f"{h:.1f}%", (p.get_x() + p.get_width()/2, h),
                          ha="center", va="bottom", fontsize=9, xytext=(0, 3), textcoords="offset points")
axes[1].legend(loc="lower left", fontsize=8)
axes[1].text(0.98, 0.02, "Blind (n=400) pending", transform=axes[1].transAxes,
             ha="right", fontsize=8, style="italic", color="gray")

plt.suptitle("LLM Verification on P3: Result Stability Across Sample Size", fontsize=15, fontweight="bold", y=1.03)
plt.tight_layout()
plt.savefig(f"{PLOTS_DIR}/06_llm_pilot_vs_fullscale.png", dpi=300, bbox_inches="tight")
plt.close()
print(f"Saved {PLOTS_DIR}/06_llm_pilot_vs_fullscale.png")
