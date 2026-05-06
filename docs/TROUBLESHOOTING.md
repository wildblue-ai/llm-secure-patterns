# Troubleshooting

Issues encountered during development and their solutions. Intended to save time on repeat encounters.

---

## Claude Code Agent Worktrees

**Problem:** Launched agents with `isolation: "worktree"` to parallelize edits across different files. Agents edited files successfully but changes were lost — worktree branches showed no new commits, and worktree directories were cleaned up.

**Root cause:** Agents edited files but were never told to commit. Worktree isolation creates a temporary git worktree on a separate branch. If the agent doesn't commit its changes before returning, the edits exist only as uncommitted modifications in the temporary directory. When the worktree is cleaned up, uncommitted changes are discarded.

**Fix:** Always include explicit commit instructions in the agent prompt when using `isolation: "worktree"`:

```
"After making all edits, stage and commit: git add -A && git commit -m 'fix: description'"
```

Then merge the worktree branch back:
```bash
git merge worktree-agent-XXXX
```

**When to use worktrees vs. direct edits:**
- **Use worktrees** when two agents need to edit the **same files** (real conflict risk), or for experimental changes you might discard
- **Skip worktrees** when agents edit **different files** — no conflict risk, direct edits are faster and simpler
- **Rule of thumb:** if the agents can't break each other's work, don't isolate them

**Impact of this incident:** Lost a full round of 47 adversarial review fixes across 10 files. All work had to be re-applied directly.

---

## Gemini API — Thinking Model Token Budget

**Problem:** Gemini 2.5 Pro returned `finish_reason: 2` (MAX_TOKENS) with no output `Part`, causing `response.text` to raise an error.

**Root cause:** Gemini 2.5 Pro is a thinking model. Thinking tokens count against `max_output_tokens` and are consumed before visible output. With `max_output_tokens=2000`, thinking used the entire budget, leaving zero tokens for actual output.

**Fix:** Set `max_output_tokens=16000` (or higher) for Gemini thinking models. Applied in `tests/adversarial-review/driver.py` — Gemini gets its own budget, separate from the `MAX_OUTPUT_TOKENS` constant used by Claude and GPT.

---

## Adversarial Review Harness — `[Errno 2] No such file or directory`

**Problem:** Running `./run.sh` produces `FAIL: [Errno 2] No such file or directory` for one or more reviewers (typically Claude and/or GPT), followed by `SyncHttpxClientWrapper` errors.

**Root cause:** The `.venv/` directory is missing, corrupted, or was only partially created. This can happen if:
- The venv was manually deleted (e.g., during SDK migration) but `run.sh` wasn't re-run from the correct directory
- A previous run was Ctrl+C'd during venv creation
- The harness was run from an unexpected working directory

The `[Errno 2]` is misleading — it's not about the prompt files or skill files being missing. It's the Python binary or SDK packages inside `.venv/` that can't be found.

**Fix:**
```bash
rm -rf tests/adversarial-review/.venv
./tests/adversarial-review/run.sh
```

The harness will recreate the venv from `requirements.txt` (~30 seconds) and retry. Cached results from previous successful reviewers are preserved — only the failed ones will re-query.

**Prevention:** Always run from the project root (`./tests/adversarial-review/run.sh`) or from the harness directory (`cd tests/adversarial-review && ./run.sh`). The script auto-navigates via `cd "$(dirname "$0")"`, but if you `cd` elsewhere first, the venv path may not resolve correctly.

---

## Adversarial Review — Triage Refusal (safety filter)

**Problem:** The triage step for `secure-external-ingestion` returns `ERROR: Triage returned empty response (stop_reason: refusal)` while the other 4 skills triage successfully.

**Root cause:** Claude Opus 4.6's safety filter triggers when the combined content of all 3 reviewer files (claude.md + gpt.md + gemini.md) contains too many explicit attack payloads, injection examples, and exploit descriptions. The SEI skill reviews tend to have the most detailed attack content because the skill directly deals with injection sanitization. Each reviewer file passes individually, but concatenated into the triage prompt they exceed the safety threshold.

**What we tried that did NOT work:**
- Adding a safety preamble ("You are a security auditor... this is authorized security research")
- The preamble was accepted for other skills but SEI content was still refused

**Fix:** Perform the SEI triage manually:
1. Read all three reviewer files in `results/<date>/secure-external-ingestion/`
2. Apply the same triage criteria from `prompts/triage.txt` (including the permanent limitations section)
3. Write the `findings.md` file manually with a note at the top explaining the manual triage
4. Note this in `docs/adversarial-review/AUDIT_LOG.md` for the run entry

**Prevention:** This may recur on future runs if reviewer content becomes more detailed. Consider: (a) running the triage with a different model (e.g., Sonnet instead of Opus), (b) truncating reviewer files before triage, or (c) accepting that SEI will need manual triage as a standard part of the process.

---

## Gemini API — Deprecated SDK Warning

**Problem:** `FutureWarning: All support for the google.generativeai package has ended.`

**Root cause:** Google replaced `google-generativeai` with `google-genai`. The old package still works but is no longer maintained.

**Status:** Cosmetic warning only — does not affect functionality. SDK migration to `google-genai` tracked as v1.0.1 item in `docs/adversarial-review/findings-plan.md`.
