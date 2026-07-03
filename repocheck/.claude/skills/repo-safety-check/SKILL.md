---
name: repo-safety-check
description: Use when the user wants to check whether a git repository (GitHub, GitLab, or any other host) is safe to clone or install before downloading or running anything from it. Runs the repocheck CLI, which analyzes the repository inside an isolated, disposable VM, and reports a SAFE/SUSPICIOUS/MALICIOUS verdict.
---

# Repo Safety Check

## When to use

The user asks something like "verifica se esse repositório é seguro", "posso confiar nesse repo?", "audita esse pacote antes de eu instalar", or pastes a git URL and asks whether it's safe. Always use this skill instead of inspecting the repository yourself or cloning it directly — the entire point of this tool is that untrusted code is only ever cloned and executed inside a disposable, isolated VM, never on the host.

## Prerequisites

- The `repocheck` CLI must be installed and on `PATH` (or invoked via its venv, e.g. `repocheck/.venv/bin/repocheck`).
- Multipass must be installed for the analysis stage (static scanners + dynamic step) to actually run. If it isn't, `repocheck` still runs the reputation pre-check and reports `SUSPICIOUS` with an explicit warning — never treat that as "safe."

## Steps

1. Extract the repository URL from the user's request. If it's ambiguous or missing, ask for it directly.
2. Run the CLI in JSON mode:
   ```bash
   repocheck <url> --json
   ```
3. Parse the JSON output. Key fields:
   - `verdict`: `"SAFE"` | `"SUSPICIOUS"` | `"MALICIOUS"`.
   - `reasons`: the rule-based reasons behind the verdict.
   - `precheck`: reputation signals (`age_days`, `stars`, `forks`, `possible_typosquat`, `typosquat_match`, `reachable`).
   - `analysis`: `null` if Multipass wasn't available; otherwise an object with `secrets`, `malicious_patterns`, `git_findings` (each finding has `rule`, `file`, `line`, `snippet` — `snippet` is always empty for `secrets` findings by design, to avoid ever persisting a raw secret value) and the dynamic-step fields (`dynamic_attempted`, `dynamic_command`, `dynamic_timed_out`, `network_connect_attempts`).
   - `multipass_warning`: non-null if the analysis stage could not run at all.
4. If `verdict` is `"SUSPICIOUS"` or `"MALICIOUS"` and `analysis` is not `null`, read the `snippet` field of every entry in `malicious_patterns` and `git_findings` — this is the only source of the flagged content, since the VM that cloned the repository has already been destroyed by the time the CLI returns. Use your own judgment on top of the rule-based verdict: is this snippet clearly malicious (e.g. a base64-decoded downloader, a git submodule using the `ext::` transport), or could it plausibly be a legitimate, if unusual, pattern (e.g. a build script whose comment happens to mention "curl | bash" as something it explicitly avoids)? State your own read explicitly and separately from the rule-based reasons — the rules can have false positives, and your assessment of the actual snippet is what adds value beyond them.
5. Present the result conversationally: lead with the verdict, then the rule-based reasons, then your own read of any flagged snippets (if applicable), then a clear recommendation — safe to proceed, proceed with caution and review specific findings, or do not clone.
6. If `multipass_warning` is present, tell the user explicitly that only the reputation pre-check ran — the deeper analysis wasn't possible in this environment. Offer to help install Multipass if they want the full analysis.

## What NOT to do

- Never clone or read the target repository yourself outside of `repocheck` — that defeats the entire point of the isolated VM.
- Never upgrade a `SUSPICIOUS`/`MALICIOUS` verdict to "safe" based on your own judgment alone when a scanner could not run (`"scanner_not_executed"`) — say so explicitly instead of compensating for the gap.
- Never treat `analysis: null` as "no problems found" — it means "not checked," which is a materially different and more cautious message to give the user.
