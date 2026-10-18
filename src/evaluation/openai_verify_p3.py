"""
OpenAI LLM verification of the ML-tier P3 findings (anchored or blind prompt).

Usage (from project root, venv active):
    python src/evaluation/openai_verify_p3.py --mode anchored
    python src/evaluation/openai_verify_p3.py --mode blind
    python src/evaluation/openai_verify_p3.py --mode blind --model gpt-4.1-mini

Same design as the Groq runs: tier P3, 400 findings, seed 123 (identical sample),
checkpointed (re-run to resume), temperature 0 where the model allows it.
Needs OPENAI_API_KEY in .env   ->   pip install openai
"""
from dotenv import load_dotenv
load_dotenv()
import argparse
import csv
import os
import re
import time
import random
from openai import OpenAI

INPUT_FILE = "results/ml_prioritized_findings_with_location.csv"
TARGET_TIER = "P3"
SAMPLE_SIZE = 400
RANDOM_SEED = 123  # same as the Groq runs -> identical 400 findings

FIELDNAMES = ["test_name", "real_vulnerability", "cwe", "num_tools_agreeing",
              "flagged_by_semgrep", "flagged_by_sonar", "cwe_historical_precision",
              "message", "ml_risk_score", "ml_priority", "file", "line",
              "llm_verdict", "llm_cwe", "llm_reason"]


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


def build_anchored_prompt(finding, code_snippet):
    p = "You are reviewing a static analysis security finding to judge if it is a TRUE POSITIVE (a genuine vulnerability) or a FALSE POSITIVE (the code is actually safe).\n\n"
    p += "Claimed vulnerability category: " + str(finding.get("cwe", "unknown")) + "\n"
    p += "Tool's description: " + str(finding.get("message", "")) + "\n\n"
    p += "Source code (flagged line is roughly in the middle of this snippet):\n"
    p += "```\n" + code_snippet + "\n```\n\n"
    p += "Respond in EXACTLY this format, nothing else:\n"
    p += "VERDICT: TP or FP\n"
    p += "REASON: one sentence explanation\n"
    return p


def build_blind_prompt(code_snippet):
    p = "You are an independent security code reviewer. Analyze the following Java code snippet for ANY genuine, exploitable security vulnerability. Do not assume a vulnerability exists -- form your own judgment purely from the code.\n\n"
    p += "Code:\n```java\n" + code_snippet + "\n```\n\n"
    p += "Respond in EXACTLY this format, nothing else:\n"
    p += "VERDICT: VULNERABLE or SAFE\n"
    p += "CWE: the CWE number if vulnerable, or NONE if safe\n"
    p += "REASON: one sentence explanation\n"
    return p


def is_reasoning_model(model):
    m = model.lower()
    return m.startswith(("o1", "o3", "o4", "gpt-5"))


def call_llm(client, model, prompt, retries=4):
    for attempt in range(retries):
        try:
            kwargs = dict(model=model, messages=[{"role": "user", "content": prompt}])
            if is_reasoning_model(model):
                # reasoning models: no temperature, token cap covers hidden reasoning
                kwargs["max_completion_tokens"] = 1500
                kwargs["reasoning_effort"] = "low"
            else:
                kwargs["max_tokens"] = 200
                kwargs["temperature"] = 0
                kwargs["seed"] = 42
            r = client.chat.completions.create(**kwargs)
            return r.choices[0].message.content or ""
        except Exception as e:
            print("  Retry " + str(attempt + 1) + "/" + str(retries) + " after error: " + str(e)[:200])
            time.sleep(2 * (attempt + 1))
    return "VERDICT: ERROR\nREASON: API call failed after retries"


def parse_anchored(text):
    v = re.search(r"VERDICT:\s*(TP|FP|ERROR)", text, re.IGNORECASE)
    r = re.search(r"REASON:\s*(.+)", text)
    return (v.group(1).upper() if v else "UNKNOWN"), "", (r.group(1).strip() if r else "")


def parse_blind(text):
    v = re.search(r"VERDICT:\s*(VULNERABLE|SAFE|ERROR)", text, re.IGNORECASE)
    c = re.search(r"CWE:\s*([\w-]+)", text, re.IGNORECASE)
    r = re.search(r"REASON:\s*(.+)", text)
    verdict = v.group(1).upper() if v else "UNKNOWN"
    verdict = {"VULNERABLE": "TP", "SAFE": "FP"}.get(verdict, verdict)
    return verdict, (c.group(1).upper() if c else ""), (r.group(1).strip() if r else "")


def load_done(path):
    if not os.path.exists(path):
        return set()
    with open(path) as f:
        return {row["test_name"] for row in csv.DictReader(f)}


def append_row(path, row):
    exists = os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDNAMES)
        if not exists:
            w.writeheader()
        w.writerow(row)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["anchored", "blind"], required=True)
    ap.add_argument("--model", default="gpt-4.1-mini")
    args = ap.parse_args()

    out_file = "results/p3_llm_verified_" + args.mode + "_openai_" + args.model.replace("/", "-") + ".csv"
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

    rows = list(csv.DictReader(open(INPUT_FILE)))
    rows = [r for r in rows if r["ml_priority"].startswith(TARGET_TIER)]
    random.seed(RANDOM_SEED)
    rows = random.sample(rows, min(SAMPLE_SIZE, len(rows)))

    done = load_done(out_file)
    remaining = [r for r in rows if r["test_name"] not in done]
    print("Mode: " + args.mode + " | model: " + args.model)
    print("Sample: " + str(len(rows)) + ". Done: " + str(len(done)) + ". Remaining: " + str(len(remaining)) + "\n")

    for i, row in enumerate(remaining, start=1):
        print("[" + str(i) + "/" + str(len(remaining)) + "] " + row["test_name"])
        out = {k: row.get(k, "") for k in FIELDNAMES if k in row}
        snippet = get_code_snippet(row.get("file", ""), row.get("line", ""))
        if not snippet:
            out.update(llm_verdict="SKIPPED", llm_cwe="", llm_reason="Could not read source file")
            append_row(out_file, out)
            continue
        if args.mode == "anchored":
            text = call_llm(client, args.model, build_anchored_prompt(row, snippet))
            v, c, reason = parse_anchored(text)
        else:
            text = call_llm(client, args.model, build_blind_prompt(snippet))
            v, c, reason = parse_blind(text)
        out.update(llm_verdict=v, llm_cwe=c, llm_reason=reason)
        append_row(out_file, out)
        time.sleep(0.2)

    print("\nDone. Results in " + out_file + " (re-run the same command to resume if interrupted)")


if __name__ == "__main__":
    main()