# Repo Safety Check — Design

**English** | [Português (Brasil)](design.pt-BR.md)

## Problem

Before cloning and installing a repository of unknown origin (GitHub, GitLab, or any git host), we want to verify whether it contains malicious code. Some malicious repositories execute code at the very moment of clone/install (git hooks, build scripts like `postinstall`/`setup.py`, malicious submodules, or crafted `.gitattributes` filters), so the check itself needs to happen in an environment fully isolated from the user's machine — never cloning or executing anything from the target repository directly on the host.

## v1 Goal

Given a repository URL, produce a verdict (SAFE / SUSPICIOUS / MALICIOUS) with a detailed report, without ever exposing the user's machine to the repository's untrusted content.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────────┐
│  Claude Code     │     │   repocheck CLI   │     │   Ephemeral VM (Multipass)│
│  skill           │────▶│   (Python, host)  │────▶│   - clone (network on)  │
│  /repo-check url │     │   orchestrator    │     │   - cuts network        │
└─────────────────┘     └──────────────────┘     │   - static scanners     │
        ▲                        │                 │   - generic dynamic    │
        │                        │                 │     step (sandbox)     │
        │                        ▼                 │   - telemetry capture  │
        │              ┌──────────────────┐        └─────────────────────────┘
        │              │  Platform API    │                    │
        │              │  precheck        │                    ▼
        │              │  (GitHub/GitLab) │        JSON with raw findings
        │              └──────────────────┘        (scanners + telemetry)
        │                                                       │
        │                                                       ▼
        │                                          Claude reads the findings +
        └──────────────────────────────────────────  flagged files and judges
                                                       intent (LLM review)
                                                                 │
                                                                 ▼
                                                   Final verdict + report
```

## Key decisions

- **Interface:** standalone Python CLI (`repocheck <url>`) + a Claude Code skill that invokes the same core, allowing both direct terminal/CI use and conversational use.
- **Analysis type:** static (never executes anything from the repository) **and** sandboxed dynamic (actually runs clone/build/install, but inside a disposable VM).
- **Isolation:** disposable local VM via **Multipass** (not Lima) — Multipass is genuinely cross-platform (Hyper-V on Windows, QEMU/KVM on Linux, Virtualization.framework on macOS) with the same CLI interface, guaranteeing real Windows/Linux/macOS support already in v1.
- **Detection engine:** a combination of established security scanners (secret detection, a language-agnostic vulnerable-dependency scanner — e.g. OSV-Scanner —, malicious-pattern rules, git-specific checks) **with** LLM review. The LLM review is done by the Claude Code session itself reading the JSON findings and flagged snippets — not a separate API call inside the Python tool. When the CLI runs outside Claude Code (`--json`), this stage is unavailable and the report makes that explicit.
- **Ecosystem scope:** generic — the focus is the git repository as a whole (hooks, submodules, `.gitattributes`/filters, Makefiles, shell scripts), not a specific package manager. Language-agnostic dependency scanners are used when known manifests exist.
- **VM network policy:** network is allowed only during the initial clone; it is then cut by an internal firewall rule before any build/install step. Network attempts after the cutoff are logged as a strong signal of malicious behavior.
- **Report:** verdict up top (SAFE/SUSPICIOUS/MALICIOUS) + detailed sections with scanner findings, VM telemetry (processes, file access outside the repo, blocked network attempts), and the LLM's analysis of the flagged snippets.

## Components

1. **`repocheck` (Python CLI, host)** — the orchestrator. Commands: `repocheck <url>` (full pipeline) and `repocheck <url> --json` (no LLM stage, for CI or when invoked by the skill).
2. **API precheck (host)** — identifies the platform from the URL and queries the public API (repo age, stars/forks, author/org verification, typosquatting signals in the name). Purely metadata, never touches the code. Unknown platforms skip this stage without error.
3. **Analysis script (inside the Multipass VM)** — copied into the VM before it boots (never downloaded from the target). Runs: clone → network cutoff → static scanners → generic dynamic step (attempts whatever build/install steps the repo declares) → telemetry capture → writes structured JSON.
4. **VM lifecycle (host)** — creates a fresh instance for every analysis (never reused), copies out the JSON, and **always** destroys the VM at the end — including on timeout/error/crash.
5. **LLM review (Claude Code session)** — reads the JSON + flagged snippets, decides what to investigate further, produces a judgment of intent.
6. **Claude Code skill** — exposes this as a natural-language command, calls `repocheck --json`, and presents the verdict conversationally.

## Data flow

1. Input: repository URL (directly, or via natural language in the skill).
2. API precheck (host, seconds) — flags reputation before spending time on the VM, but doesn't skip the full analysis by default.
3. Provisioning of a fresh Multipass VM, from a fixed base image.
4. Repository clone (network on), followed by a network cutoff inside the VM.
5. Static scanners run over the files without executing anything.
6. Dynamic step: declared build/install steps are attempted, with every process execution, file access outside the repo, and blocked network attempt being captured.
7. The only artifact leaving the VM: the JSON of findings + telemetry (never the repository's source code).
8. The VM is destroyed — always, even on an error path.
9. LLM review (if available, in the Claude Code session).
10. Final report: verdict + evidence organized by section.

## Error handling and edge cases

- **Timeout in the dynamic step:** the VM is destroyed all the same; the report records "incomplete dynamic analysis" as a SUSPICIOUS item (never becomes SAFE by default without confirmation).
- **Multipass/hypervisor unavailable:** `repocheck` refuses to run the dynamic step and clearly warns that only the (weaker) static analysis is available — never silently falls back to cloning on the host.
- **Private repo (requires authentication):** credentials/tokens are passed only into the ephemeral VM, are never saved after it's destroyed, and the host's default git credentials are never used without explicit confirmation.
- **Unknown/self-hosted platform:** the API precheck is skipped; the static/dynamic pipeline inside the VM keeps working normally (platform-agnostic).
- **External scanner fails/not installed:** the corresponding item is marked "not executed," never "clean" — this avoids a false sense of security.
- **Very large repo:** configurable size/timeout limit; if exceeded, abort with a warning.
- **Failure to destroy the VM:** retries; if it persists, explicitly warns for manual checking (never fakes success without confirming).

## Testing strategy

- **Unit tests (host, fast, no VM):** URL/platform parsing, API precheck logic (mocked), findings JSON parsing, verdict composition logic from simulated findings.
- **Integration tests (real Multipass, slower):** against controlled test cases:
  - clean repo → SAFE;
  - repo with a hardcoded secret → caught by the secrets scanner;
  - repo with a known vulnerable dependency → caught by the dependency scanner;
  - repo with a `postinstall` that attempts a network connection → shows up in telemetry even with the network cut;
  - repo with a simulated malicious submodule/`.gitattributes` → caught by the git-specific checks;
  - **samples of real, publicly documented attacks** (e.g. known cases of malicious npm/PyPI packages that have since been removed, via databases like OSV/security reports) — kept and handled only inside the ephemeral VM, never on the host, to validate that the pipeline catches real attacks and not just our own artificial simulations.
- **VM lifecycle test:** ensure the VM is always destroyed even when forcing a timeout/error mid-analysis.
- **Manual skill test:** end-to-end flow via Claude Code, checking that the conversational verdict matches the raw JSON.

## Out of scope for v1

- Scanners/heuristics specific to a package manager (npm/pip) beyond what the agnostic scanners already cover.
- Caching/allowlisting of repositories already analyzed as safe.
- Abstraction over multiple VM backends — Multipass only for now.
