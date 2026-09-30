from dotenv import load_dotenv
load_dotenv()
import csv
import os
import re
import time
import random
from groq import Groq

INPUT_FILE = "results/ml_prioritized_findings_with_location.csv"
OUTPUT_FILE = "results/p3_llm_verified_v2.csv"

TARGET_TIER = "P3"
SAMPLE_SIZE = 400
RANDOM_SEED = 123  # NEW seed, distinct from the pilot's seed=42 -- this is a fresh, larger sample, not an extension of the pilot

CLIENT = Groq(api_key=os.environ["GROQ_API_KEY"])
MODEL = "openai/gpt-oss-120b"

FIELDNAMES = ["test_name", "real_vulnerability", "cwe", "num_tools_agreeing",
              "flagged_by_semgrep", "flagged_by_sonar", "cwe_historical_precision",
              "message", "ml_risk_score", "ml_priority", "file", "line",
              "llm_verdict", "llm_reason"]


def get_code_snippet(file_path, line_number, context_lines=6):
    try:
        line_number = int(line_number)
    except (ValueError, TypeError):
        return ""
    if not file_path or not os.path.exists(file_path):
        return ""
    with open(file_path, "r", errors="ignore") as f:
        lines = f.readlines()
    start = max(0, line_number - context_lines - 1)
    end = min(len(lines), line_number + context_lines)
    return "".join(lines[start:end])


def build_prompt(finding, code_snippet):
    prompt = "You are reviewing a static analysis security finding to judge if it is a TRUE POSITIVE (a genuine vulnerability) or a FALSE POSITIVE (the code is actually safe).\n\n"
    prompt += "Claimed vulnerability category: " + str(finding.get("cwe", "unknown")) + "\n"
    prompt += "Tool's description: " + str(finding.get("message", "")) + "\n\n"
    prompt += "Source code (flagged line is roughly in the middle of this snippet):\n"
    prompt += "```\n" + code_snippet + "\n```\n\n"
    prompt += "Respond in EXACTLY this format, nothing else:\n"
    prompt += "VERDICT: TP or FP\n"
    prompt += "REASON: one sentence explanation\n"
    return prompt


def call_llm(prompt, retries=3, use_low_effort=True):
    for attempt in range(retries):
        try:
            kwargs = dict(
                model=MODEL,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1024,
                temperature=0
            )
            if use_low_effort:
                kwargs["reasoning_effort"] = "low"
            response = CLIENT.chat.completions.create(**kwargs)
            return response.choices[0].message.content, use_low_effort
        except Exception as e:
            err_str = str(e)
            if use_low_effort and ("reasoning_effort" in err_str or "unsupported" in err_str.lower()):
                print("  reasoning_effort not supported by this model, retrying without it...")
                use_low_effort = False
                continue
            print("  Retry " + str(attempt + 1) + "/" + str(retries) + " after error: " + err_str)
            time.sleep(2)
    return "VERDICT: ERROR\nREASON: API call failed after retries", use_low_effort


def parse_verdict(response_text):
    verdict_match = re.search(r"VERDICT:\s*(TP|FP|ERROR)", response_text, re.IGNORECASE)
    reason_match = re.search(r"REASON:\s*(.+)", response_text)
    verdict = verdict_match.group(1).upper() if verdict_match else "UNKNOWN"
    reason = reason_match.group(1).strip() if reason_match else ""
    return verdict, reason


def load_already_done(path):
    """Returns set of test_names already processed, so we can resume without repeating work."""
    done = set()
    if os.path.exists(path):
        with open(path, "r") as f:
            for row in csv.DictReader(f):
                done.add(row["test_name"])
    return done


def append_row(path, row):
    file_exists = os.path.exists(path)
    with open(path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


def process():
    all_rows = list(csv.DictReader(open(INPUT_FILE)))
    target_rows = [r for r in all_rows if r["ml_priority"].startswith(TARGET_TIER)]

    random.seed(RANDOM_SEED)
    target_rows = random.sample(target_rows, min(SAMPLE_SIZE, len(target_rows)))

    already_done = load_already_done(OUTPUT_FILE)
    remaining = [r for r in target_rows if r["test_name"] not in already_done]

    print(f"Target sample: {len(target_rows)}. Already done: {len(already_done)}. Remaining: {len(remaining)}.\n")

    use_low_effort = True
    for i, row in enumerate(remaining, start=1):
        print(f"[{i}/{len(remaining)}] {row.get('test_name')}")

        code_snippet = get_code_snippet(row.get("file", ""), row.get("line", ""))
        out_row = {k: row.get(k, "") for k in FIELDNAMES if k in row}

        if not code_snippet:
            out_row["llm_verdict"] = "SKIPPED"
            out_row["llm_reason"] = "Could not read source file"
            append_row(OUTPUT_FILE, out_row)
            continue

        prompt = build_prompt(row, code_snippet)
        response_text, use_low_effort = call_llm(prompt, use_low_effort=use_low_effort)
        verdict, reason = parse_verdict(response_text)

        out_row["llm_verdict"] = verdict
        out_row["llm_reason"] = reason
        append_row(OUTPUT_FILE, out_row)

        time.sleep(0.3)

    print(f"\nDone (or paused by rate limit). Results saved incrementally to {OUTPUT_FILE}")
    print("Re-run this same script anytime -- it will automatically skip completed rows and continue.")


if __name__ == "__main__":
    process()
