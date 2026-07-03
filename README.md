# repocheck

**English** | [Português (Brasil)](README.pt-BR.md)

> Analyze a git repository for malicious content **before** you clone or install it — never touching your machine with untrusted code.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## The problem

Some malicious repositories execute code the moment you clone or install them: git hooks, build scripts (`postinstall`, `setup.py`), malicious git submodules, or crafted `.gitattributes` filters. By the time you notice something is wrong, the damage is already done — on your machine.

`repocheck` never clones or executes anything from the target repository on your host. All of that happens inside a disposable, network-isolated virtual machine that is destroyed after every analysis.

## How it works

```
┌──────────────────┐     ┌────────────────────┐     ┌───────────────────────────┐
│  Claude Code      │     │   repocheck CLI     │     │   Disposable VM (Multipass)│
│  skill (optional) │────▶│   (Python, host)    │────▶│   - clone (network on)     │
└──────────────────┘     └────────────────────┘     │   - static scanners        │
                                    │                  │   - network cutoff         │
                                    ▼                  │   - dynamic build attempt  │
                          ┌────────────────────┐        │   - telemetry capture      │
                          │  Reputation         │        └───────────────────────────┘
                          │  precheck via API   │                    │
                          │  (GitHub/GitLab)    │                    ▼
                          └────────────────────┘        JSON findings + verdict
```

1. **Reputation precheck** — queries the GitHub/GitLab public API for repo age, stars, forks, and typosquatting signals. Pure metadata, no code is touched.
2. **Disposable VM** — a brand-new [Multipass](https://multipass.run/) VM is created for every analysis and is **always destroyed** afterward, even on error or timeout.
3. **Static scanners** (run inside the VM, after cloning, network still on) — never execute anything, only read files:
   - Secret detection (via [`detect-secrets`](https://github.com/Yelp/detect-secrets))
   - Malicious pattern matching (`curl | bash`, obfuscated `eval`, encoded PowerShell, etc.)
   - Git-specific checks (`ext::` submodule transports, custom `.gitattributes` filters, nested `.git` directories, RTLO/homoglyph filenames)
4. **Network cutoff** — the VM's network is cut (`iptables`) right before any build/install step, and never before — static analysis never needs network access to be safe.
5. **Dynamic step** — if an `npm`/`pip` build system is detected, it's attempted with the network already cut, wrapped in `strace` to capture any connection attempt (a strong signal of malicious intent, since nothing should be phoning home with no network).
6. **Verdict** — a deterministic, rules-based engine combines every signal above into `SAFE` / `SUSPICIOUS` / `MALICIOUS`, always with explicit reasons. A scanner failure or missing analysis **never** silently resolves to `SAFE`.
7. **Claude Code skill (optional)** — ask conversationally ("is this repo safe to install?") and Claude will run the CLI, read the verdict and the already-flagged snippets, and add its own judgment on top of the rules — without ever touching the target repository itself (the VM is already gone by the time the CLI returns).

## Tech stack

| Layer | Technology |
|---|---|
| CLI / orchestration | Python 3.11+, [Click](https://click.palletsprojects.com/) |
| Reputation precheck | GitHub/GitLab REST APIs via [`requests`](https://requests.readthedocs.io/) |
| Isolation | [Multipass](https://multipass.run/) (disposable Ubuntu 24.04 VMs — works on macOS, Linux, and Windows) |
| Secrets scanning | [`detect-secrets`](https://github.com/Yelp/detect-secrets) |
| Network telemetry | `iptables` (cutoff) + `strace` (connection-attempt capture) |
| Tests | `pytest`, `responses` (HTTP mocking), real end-to-end tests against a live Multipass VM |
| Conversational usage | A [Claude Code](https://claude.com/claude-code) skill (`repocheck/.claude/skills/repo-safety-check/SKILL.md`) |

## Requirements

- Python 3.11+
- [Multipass](https://multipass.run/) — for the deep analysis stage (static + dynamic). Without it, `repocheck` still runs the reputation precheck and reports `SUSPICIOUS` with an explicit warning; it never silently claims a repo is safe.

```bash
# macOS
brew install multipass

# Linux / Windows: see https://multipass.run/install
```

## Installation

```bash
git clone <this-repo-url>
cd repocheck
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Usage

```bash
# Human-readable report
.venv/bin/repocheck https://github.com/<owner>/<repo>

# Machine-readable JSON (used by the Claude Code skill)
.venv/bin/repocheck https://github.com/<owner>/<repo> --json
```

Example output:

```
Checking repository reputation...
Launching disposable analysis VM (this can take a minute)...
Installing analysis tools inside the VM (git, npm, detect-secrets)...
Cloning the repository inside the isolated VM...
Running static and dynamic analysis (network is cut before any build step)...
Collecting results and destroying the VM...
VERDICT: SAFE

Reasons:
  - no relevant findings

Precheck:
  Platform: github
  Reachable: yes
  Age (days): 5636
  Stars: 3659
  Forks: 6128

Static analysis:
  Clone succeeded: yes
  Secrets found: 0
  Malicious patterns: 0
  Git findings: 0

Dynamic step:
  Attempted: no
```

### Using it conversationally (Claude Code)

Inside a [Claude Code](https://claude.com/claude-code) session in this project, just ask in natural language:

> "Is this repository safe to clone? https://github.com/\<owner\>/\<repo\>"

Claude will run the CLI, read the verdict and the already-flagged snippets from the JSON output, and add its own judgment on top of the rules-based verdict — see `repocheck/.claude/skills/repo-safety-check/SKILL.md` for the full instructions it follows.

## Running the tests

```bash
cd repocheck
PATH="$PWD/.venv/bin:$PATH" .venv/bin/pytest -v
```

Two tests require a real Multipass VM and are skipped automatically if it isn't installed. With Multipass installed, the full suite (113 tests) runs end-to-end, including a real analysis pipeline run against a public repository.

## What's out of scope for v1

- Scanners beyond secrets/malicious-patterns/git-checks (e.g. semgrep, YARA, OSV-Scanner).
- Build ecosystems beyond npm/pip in the dynamic step.
- Caching/allowlisting of previously-analyzed repositories.
- VM backends other than Multipass.

## Design rationale

For the original design discussion (why a disposable VM, why Multipass over Lima, testing strategy, edge cases) see [`docs/design.md`](docs/design.md) (in Portuguese).

## Contributing

Pull requests are welcome! All contributions are reviewed before merging. Please open an issue first for significant changes so we can discuss the approach.

## License

[Apache License 2.0](LICENSE).
