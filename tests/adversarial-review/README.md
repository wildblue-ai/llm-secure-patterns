# Adversarial Review Harness

Repeatable cross-model security review for the `llm-secure-patterns` skills. Sends each SKILL.md (plus referenced templates) to Claude, GPT, and Gemini with an adversarial reviewer prompt, then runs a Claude triage pass that dedupes findings and sorts them into **fix-now / v1.0.1 / wont-fix** buckets.

Use this before any marketplace submission, and after any non-trivial skill change.

## What it does

For each skill:

1. Bundles `skills/<skill>/SKILL.md` + any `templates/python/*.py` files referenced by name into a single payload.
2. Sends the payload to three reviewers in parallel families:
   - **Claude Sonnet 4.6** (`claude-sonnet-4-6`)
   - **GPT-4o** (`gpt-4o`)
   - **Gemini 2.5 Pro** (`gemini-2.5-pro`)
   with an adversarial prompt asking them to attack the guidance (missing threats, false confidence, language drift, code issues, scope overclaims).
3. Saves each raw response to `results/<date>/<skill>/{claude,gpt,gemini}.md`.
4. Runs a **triage pass** with **Claude Opus 4.6** that reads all three reviews together, deduplicates findings, rejects hallucinations, and produces `findings.md` with three buckets:
   - **Fix Now** — blocking submission
   - **v1.0.1** — valid but non-blocking
   - **Won't Fix** — out of scope (document in `SCOPE.md` instead)
5. Prints a summary table at the end with item counts per bucket per skill.

## Prerequisites

- Python 3.9+
- A `.env` file at the **project root** containing:
  ```
  ANTHROPIC_API_KEY=sk-ant-...
  OPENAI_API_KEY=sk-...
  GEMINI_API_KEY=...
  ```
- `.env` is gitignored — never commit it.

## Running it

From the project root:

```bash
cd tests/adversarial-review

# Smoke-test one skill first (~$0.05, ~1-2 min)
./run.sh secure-external-ingestion

# Full sweep — all 5 skills (~$0.30, ~5-10 min)
./run.sh

# Reviewers only, skip the triage pass
./run.sh --skip-triage

# Pin a specific output date (default: today)
./run.sh --date 2026-04-07
```

Valid skill names:

- `secure-external-ingestion`
- `llm-endpoint-hardening`
- `output-validation`
- `system-prompt-design`
- `agent-action-surface`

## First-run setup

The first invocation of `run.sh` creates a local `.venv/` and installs dependencies (`anthropic`, `openai`, `google-generativeai`, `python-dotenv`). This takes ~30 seconds and only happens once. Subsequent runs reuse the venv.

## Reading the output

Results land in `results/<date>/<skill>/`:

```
results/2026-04-07/secure-external-ingestion/
├── claude.md      # raw Claude Sonnet review
├── gpt.md         # raw GPT-4o review
├── gemini.md      # raw Gemini 2.5 Pro review
└── findings.md    # triaged: fix-now / v1.0.1 / wont-fix / rejected
```

**Start with `findings.md`** — it's the curated, deduped list. Drop into the raw `*.md` files only when you want to see a reviewer's full reasoning for a specific finding.

The terminal summary table looks like:

```
Skill                            fix-now    v1.0.1   wont-fix   rej
----------------------------------------------------------------------
secure-external-ingestion              2         3          1     2
llm-endpoint-hardening                 0         4          0     1
...
Total fix-now items: 2
```

Any non-zero **fix-now** count is a submission blocker.

## Caching and re-runs

Each reviewer response and the triage are cached by file existence. Re-running the harness will **skip** any step whose output file already exists. This means:

- A failed run is cheap to resume — just run `./run.sh <skill>` again, and only the failed reviewers re-query.
- To force a re-query of one reviewer, delete that file:
  ```bash
  rm results/2026-04-07/secure-external-ingestion/gpt.md
  ./run.sh secure-external-ingestion
  ```
- To force a fresh triage after editing reviews:
  ```bash
  rm results/2026-04-07/secure-external-ingestion/findings.md
  ./run.sh secure-external-ingestion
  ```
- To start completely over for a skill:
  ```bash
  rm -rf results/2026-04-07/secure-external-ingestion
  ./run.sh secure-external-ingestion
  ```

## Cost estimate

Per full run of all 5 skills, with the default model mix (Sonnet + GPT-4o + Gemini 2.5 Pro reviewers, Opus triage):

| Component | Cost per run |
|---|---|
| Claude Sonnet reviewers (5) | ~$0.20 |
| GPT-4o reviewers (5) | ~$0.15 |
| Gemini 2.5 Pro reviewers (5) | ~$0.05 |
| Opus triage (5) | ~$0.20 |
| **Total** | **~$0.30–0.60** |

Pricing changes — check current rates if cost matters. Even 10 full runs is well under $10.

## Workflow: how to use this before submission

1. **Run the full sweep:** `./run.sh`
2. **Review every `findings.md`** — open all 5.
3. **Triage Fix Now items** — for each, decide:
   - Real issue → fix the SKILL.md or template, commit
   - Hallucination triage missed → note it, ignore
   - Out of scope → move to `SCOPE.md` and re-categorize
4. **Re-run the harness** after fixes (`rm -rf` the affected skill dirs first to force re-review).
5. **When fix-now count is 0 across all skills**, you're clear to submit.
6. **Save the final run** — copy `results/<date>/` somewhere outside `tests/adversarial-review/results/` (which is gitignored) if you want to attach evidence to the marketplace submission notes.

## Customizing

All knobs live at the top of `driver.py`:

```python
CLAUDE_MODEL = "claude-sonnet-4-6"
CLAUDE_TRIAGE_MODEL = "claude-opus-4-6"
OPENAI_MODEL = "gpt-4o"
GEMINI_MODEL = "gemini-2.5-pro"
MAX_OUTPUT_TOKENS = 2000
SKILLS = [...]
```

To make reviews more thorough, swap `CLAUDE_MODEL` to `claude-opus-4-6` (costs ~5x more). To add a new skill, add its directory name to `SKILLS`.

Prompts are in `prompts/reviewer.txt` and `prompts/triage.txt` — edit them directly to change reviewer focus or output format. They use simple `{payload}` / `{reviews}` / `{skill_name}` placeholders.

## Troubleshooting

**`Missing ANTHROPIC_API_KEY in .env`** — `.env` is missing, in the wrong location, or the key name is wrong. It must live at the project root (one level above `tests/`), not inside `tests/adversarial-review/`.

**One reviewer fails, others succeed** — the failing reviewer's file contains `ERROR: ...`. The triage will still run on whatever responses succeeded. Delete the error file and re-run to retry just that reviewer.

**Triage produces empty buckets** — usually means reviewers all returned mild/no findings, which is a good sign. Spot-check one raw `*.md` to confirm the reviewer actually engaged with the content.

**Rate limits** — reviewers run sequentially, not concurrently, so rate limits are unlikely. If you hit one, wait a minute and re-run; cached responses make resumption free.

**Wildly different findings across reviewers** — expected and desirable. Different model families have different blind spots; that's the entire point of cross-model review. Trust the triage to dedupe and prioritize.

## Files

```
tests/adversarial-review/
├── README.md            # this file
├── run.sh               # shell wrapper, manages venv, calls driver
├── driver.py            # orchestrator
├── requirements.txt     # python deps
├── prompts/
│   ├── reviewer.txt     # adversarial attack prompt
│   └── triage.txt       # dedupe + prioritize prompt
├── .venv/               # gitignored, created on first run
└── results/             # gitignored, all run outputs
    └── <date>/
        └── <skill>/
            ├── claude.md
            ├── gpt.md
            ├── gemini.md
            └── findings.md
```
