from dotenv import load_dotenv
load_dotenv()
import csv
import os
import re
import time
import random
from groq import Groq

INPUT_FILE = "results/ml_prioritized_findings_with_location.csv"
OUTPUT_FILE = "results/p3_llm_verified_blind.csv"

TARGET_TIER = "P3"
SAMPLE_SIZE = 100

CLIENT = Groq(api_key=os.environ["GROQ_API_KEY"])
MODEL = "openai/gpt-oss-120b"


def get_code_snippet(file_path, line_number, context_lines=8):
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


def build_blind_prompt(code_snippet):
    prompt = "You are an independent security code reviewer. Analyze the following Java code snippet for ANY genuine, exploitable security vulnerability. Do not assume a vulnerability exists -- form your own judgment purely from the code.\n\n"
    prompt += "Code:\n```java\n" + code_snippet + "\n```\n\n"
    prompt += "Respond in EXACTLY this format, nothing else:\n"
    prompt += "VERDICT: VULNERABLE or SAFE\n"
    prompt += "CWE: the CWE number if vulnerable, or NONE if safe\n"
    prompt += "REASON: one sentence explanation\n"
    return prompt


def call_llm(prompt, retries=3):
    for attempt in range(retries):
        try:
            response = CLIENT.chat.completions.create(
                model=MODEL,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1024,
                temperature=0
            )
            return response.choices[0].message.content
        except Exception as e:
            print("  Retry " + str(attempt + 1) + "/" + str(retries) + " after error: " + str(e))
            time.sleep(2)
    return "VERDICT: ERROR\nCWE: NONE\nREASON: API call failed after retries"


def parse_blind_verdict(response_text):
    verdict_match = re.search(r"VERDICT:\s*(VULNERABLE|SAFE|ERROR)", response_text, re.IGNORECASE)
    cwe_match = re.search(r"CWE:\s*([\w-]+)", response_text, re.IGNORECASE)
    reason_match = re.search(r"REASON:\s*(.+)", response_text)

    verdict = verdict_match.group(1).upper() if verdict_match else "UNKNOWN"
    cwe = cwe_match.group(1).upper() if cwe_match else ""
    reason = reason_match.group(1).strip() if reason_match else ""
    return verdict, cwe, reason


def process():
    all_rows = list(csv.DictReader(open(INPUT_FILE)))
    target_rows = [r for r in all_rows if r["ml_priority"].startswith(TARGET_TIER)]

    if SAMPLE_SIZE:
        random.seed(42)  # SAME seed as before -- gets the SAME 100 rows for a fair comparison
        target_rows = random.sample(target_rows, min(SAMPLE_SIZE, len(target_rows)))

    print("Verifying " + str(len(target_rows)) + " findings via Groq (BLIND mode -- no tool claim shown)...\n")

    for i, row in enumerate(target_rows, start=1):
        print("[" + str(i) + "/" + str(len(target_rows)) + "] " + str(row.get("test_name")))

        code_snippet = get_code_snippet(row.get("file", ""), row.get("line", ""))

        if not code_snippet:
            row["llm_verdict"] = "SKIPPED"
            row["llm_cwe"] = ""
            row["llm_reason"] = "Could not read source file"
            continue

        prompt = build_blind_prompt(code_snippet)
        response_text = call_llm(prompt)
        verdict, cwe, reason = parse_blind_verdict(response_text)

        # Convert VULNERABLE/SAFE into the same TP/FP language as before, for comparison
        row["llm_verdict"] = "TP" if verdict == "VULNERABLE" else "FP" if verdict == "SAFE" else verdict
        row["llm_cwe"] = cwe
        row["llm_reason"] = reason

        time.sleep(0.3)

    fieldnames = list(target_rows[0].keys()) if target_rows else []
    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(target_rows)

    print("\nSaved to " + OUTPUT_FILE)


if __name__ == "__main__":
    process()
