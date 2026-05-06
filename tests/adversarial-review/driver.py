#!/usr/bin/env python3
"""
Adversarial review harness for llm-secure-patterns skills.

For each skill: bundles SKILL.md + referenced templates, sends to Claude,
GPT, and Gemini with an adversarial reviewer prompt, then runs a triage
pass with Claude to produce structured findings.

Usage:
    python driver.py                    # all skills
    python driver.py secure-external-ingestion  # one skill
    python driver.py --skip-triage      # reviewers only
"""

import argparse
import os
import re
import sys
from datetime import date
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
SKILLS_DIR = ROOT / "skills"
TEMPLATES_DIR = ROOT / "templates" / "python"
HARNESS_DIR = Path(__file__).resolve().parent
PROMPTS_DIR = HARNESS_DIR / "prompts"
RESULTS_DIR = HARNESS_DIR / "results"

# Skills to review (excludes report/ which is a command, not a security skill)
SKILLS = [
    "secure-external-ingestion",
    "llm-endpoint-hardening",
    "output-validation",
    "system-prompt-design",
    "agent-action-surface",
]

# Model selection — Opus reviewer is overkill; Sonnet is the sweet spot.
CLAUDE_MODEL = "claude-sonnet-4-6"
CLAUDE_TRIAGE_MODEL = "claude-opus-4-6"  # triage benefits from stronger judgment
OPENAI_MODEL = "gpt-4o"
GEMINI_MODEL = "gemini-2.5-pro"

MAX_OUTPUT_TOKENS = 2000


def load_skill_payload(skill_name: str) -> str:
    """Bundle SKILL.md + any referenced python templates + any sibling
    recommendations/*.md files into one string for reviewer critique."""
    skill_path = SKILLS_DIR / skill_name / "SKILL.md"
    if not skill_path.exists():
        raise FileNotFoundError(f"Missing {skill_path}")
    skill_md = skill_path.read_text()

    parts = [f"=== skills/{skill_name}/SKILL.md ===\n{skill_md}"]

    # Find referenced templates by filename mention
    for tmpl in TEMPLATES_DIR.glob("*.py"):
        if tmpl.name in skill_md:
            parts.append(f"\n=== templates/python/{tmpl.name} ===\n{tmpl.read_text()}")

    # Include sibling recommendations/*.md files when SKILL.md references them.
    # These carry the substance of skills like /report that assemble output from
    # per-decision advisory/scaffold files; reviewers need them to give useful
    # critique on the assembled document.
    recs_dir = SKILLS_DIR / skill_name / "recommendations"
    if recs_dir.is_dir():
        for rec in sorted(recs_dir.glob("*.md")):
            parts.append(
                f"\n=== skills/{skill_name}/recommendations/{rec.name} ===\n"
                f"{rec.read_text()}"
            )

    return "\n".join(parts)


def call_claude(payload: str, model: str) -> str:
    from anthropic import Anthropic
    client = Anthropic()
    prompt = (PROMPTS_DIR / "reviewer.txt").read_text().replace("{payload}", payload)
    msg = client.messages.create(
        model=model,
        max_tokens=MAX_OUTPUT_TOKENS,
        messages=[{"role": "user", "content": prompt}],
    )
    return msg.content[0].text


def call_openai(payload: str) -> str:
    from openai import OpenAI
    client = OpenAI()
    prompt = (PROMPTS_DIR / "reviewer.txt").read_text().replace("{payload}", payload)
    resp = client.chat.completions.create(
        model=OPENAI_MODEL,
        max_tokens=MAX_OUTPUT_TOKENS,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content


def call_gemini(payload: str) -> str:
    from google import genai
    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    prompt = (PROMPTS_DIR / "reviewer.txt").read_text().replace("{payload}", payload)
    # Gemini 2.5 Pro is a thinking model — thinking tokens count against
    # max_output_tokens and are spent before visible output. Give it a much
    # larger budget so thinking + the actual review both fit.
    resp = client.models.generate_content(
        model=GEMINI_MODEL,
        contents=prompt,
        config={"max_output_tokens": 16000},
    )
    return resp.text


REVIEWERS = [
    ("claude", lambda p: call_claude(p, CLAUDE_MODEL)),
    ("gpt", call_openai),
    ("gemini", call_gemini),
]


def run_triage(skill_name: str, reviews: dict[str, str]) -> str:
    blob = "\n\n".join(f"### Reviewer: {name}\n\n{text}" for name, text in reviews.items())
    prompt = (PROMPTS_DIR / "triage.txt").read_text()
    prompt = prompt.replace("{skill_name}", skill_name).replace("{reviews}", blob)
    from anthropic import Anthropic
    client = Anthropic()
    msg = client.messages.create(
        model=CLAUDE_TRIAGE_MODEL,
        max_tokens=8000,
        messages=[{"role": "user", "content": prompt}],
    )
    if not msg.content:
        return f"ERROR: Triage returned empty response (stop_reason: {msg.stop_reason})"
    return msg.content[0].text


def review_skill(skill_name: str, out_dir: Path, skip_triage: bool) -> dict:
    print(f"\n=== {skill_name} ===")
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = load_skill_payload(skill_name)

    reviews = {}
    for name, fn in REVIEWERS:
        target = out_dir / f"{name}.md"
        if target.exists():
            print(f"  [skip] {name} (cached: {target.name})")
            reviews[name] = target.read_text()
            continue
        print(f"  [run]  {name}...", end=" ", flush=True)
        try:
            text = fn(payload)
            target.write_text(text)
            reviews[name] = text
            print("ok")
        except Exception as e:
            print(f"FAIL: {e}")
            reviews[name] = f"ERROR: {e}"

    summary = {"fix_now": 0, "v1_0_1": 0, "wont_fix": 0, "rejected": 0}

    if not skip_triage and any(not v.startswith("ERROR") for v in reviews.values()):
        triage_path = out_dir / "findings.md"
        if triage_path.exists():
            print(f"  [skip] triage (cached)")
            text = triage_path.read_text()
        else:
            print(f"  [run]  triage...", end=" ", flush=True)
            try:
                text = run_triage(skill_name, reviews)
                triage_path.write_text(text)
                print("ok")
            except Exception as e:
                print(f"FAIL: {e}")
                text = ""
        # Quick count for summary table
        for line in text.splitlines():
            if line.startswith("## Fix Now"):
                section = "fix_now"
            elif line.startswith("## v1.0.1"):
                section = "v1_0_1"
            elif line.startswith("## Won't Fix"):
                section = "wont_fix"
            elif line.startswith("## Rejected"):
                section = "rejected"
            elif line.startswith("## "):
                section = None
            elif line.lstrip().startswith("- ") and section:
                summary[section] += 1

    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("skill", nargs="?", help="Single skill to review")
    parser.add_argument("--skip-triage", action="store_true")
    parser.add_argument("--date", default=date.today().isoformat(),
                        help="Output subdir (default: today)")
    args = parser.parse_args()

    load_dotenv(ROOT / ".env")
    for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"):
        if not os.environ.get(key):
            sys.exit(f"Missing {key} in .env")

    targets = [args.skill] if args.skill else SKILLS
    for s in targets:
        if s not in SKILLS:
            sys.exit(f"Unknown skill: {s}. Valid: {', '.join(SKILLS)}")

    run_dir = RESULTS_DIR / args.date
    print(f"Output: {run_dir}")

    summaries = {}
    for skill in targets:
        summaries[skill] = review_skill(skill, run_dir / skill, args.skip_triage)

    # Print summary table
    print("\n" + "=" * 70)
    print(f"{'Skill':<32} {'fix-now':>9} {'v1.0.1':>9} {'wont-fix':>10} {'rej':>5}")
    print("-" * 70)
    total_fix = 0
    for skill, s in summaries.items():
        print(f"{skill:<32} {s['fix_now']:>9} {s['v1_0_1']:>9} {s['wont_fix']:>10} {s['rejected']:>5}")
        total_fix += s["fix_now"]
    print("-" * 70)
    print(f"Total fix-now items: {total_fix}")
    print(f"\nResults: {run_dir}")
    if total_fix > 0:
        print("Review findings.md files before submission.")


if __name__ == "__main__":
    main()
