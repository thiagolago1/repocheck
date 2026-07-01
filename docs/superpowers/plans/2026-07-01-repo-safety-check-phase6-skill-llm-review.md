# Repo Safety Check — Fase 6: Skill do Claude Code + Revisão por LLM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expor o pipeline completo (Fases 1-5) como uma skill do Claude Code em linguagem natural, que roda `repocheck <url> --json`, lê os achados já sinalizados (incluindo os trechos/snippets que os scanners da Fase 3 embutiram no JSON), e usa o próprio julgamento do Claude para avaliar intenção — complementando o veredito baseado em regras sem nunca precisar tocar o repositório-alvo de novo (a VM que o clonou já foi destruída).

**Architecture:** Esta fase não adiciona nenhum código Python novo — o CLI já expõe tudo que a skill precisa via `--json` (Fase 5). O único artefato novo é um arquivo `SKILL.md` no formato de skill do Claude Code, colocado em `repocheck/.claude/skills/repo-safety-check/SKILL.md`, para que fique associado ao projeto `repocheck` especificamente (e não ao repositório `agentes` como um todo, que pode vir a hospedar outros projetos no futuro).

**Tech Stack:** Markdown (formato de skill do Claude Code) — nenhuma dependência nova.

## Global Constraints

- A skill nunca clona ou lê o repositório-alvo por conta própria — só consome o JSON que `repocheck --json` já produziu.
- A skill nunca promove um veredito SUSPEITO/MALICIOSO para "seguro" só com base no próprio julgamento, quando um scanner não pôde ser executado (achado `"scanner_not_executed"`) ou quando `analysis` é `null` — nesses casos, deixa isso explícito para o usuário em vez de tentar compensar com julgamento próprio.
- A skill trata `analysis: null` sempre como "não verificado", nunca como "sem problemas".

---

## Task 1: Escrever a skill

**Files:**
- Create: `repocheck/.claude/skills/repo-safety-check/SKILL.md`

**Interfaces:**
- Consumes: a saída JSON de `repocheck <url> --json` (Fase 5): chaves `verdict`, `reasons`, `precheck`, `analysis` (ou `null`), `multipass_warning`.
- Produces: nenhuma interface de código — a skill é o artefato final consumido diretamente pelo Claude Code.

- [ ] **Step 1: Criar o diretório da skill e o arquivo `SKILL.md`**

```bash
mkdir -p repocheck/.claude/skills/repo-safety-check
```

Criar `repocheck/.claude/skills/repo-safety-check/SKILL.md`:

```markdown
---
name: repo-safety-check
description: Use when the user wants to check whether a git repository (GitHub, GitLab, or any other host) is safe to clone or install before downloading or running anything from it. Runs the repocheck CLI, which analyzes the repository inside an isolated, disposable VM, and reports a SEGURO/SUSPEITO/MALICIOSO verdict.
---

# Repo Safety Check

## When to use

The user asks something like "verifica se esse repositório é seguro", "posso confiar nesse repo?", "audita esse pacote antes de eu instalar", or pastes a git URL and asks whether it's safe. Always use this skill instead of inspecting the repository yourself or cloning it directly — the entire point of this tool is that untrusted code is only ever cloned and executed inside a disposable, isolated VM, never on the host.

## Prerequisites

- The `repocheck` CLI must be installed and on `PATH` (or invoked via its venv, e.g. `repocheck/.venv/bin/repocheck`).
- Multipass must be installed for the analysis stage (static scanners + dynamic step) to actually run. If it isn't, `repocheck` still runs the reputation pre-check and reports `SUSPEITO` with an explicit warning — never treat that as "safe."

## Steps

1. Extract the repository URL from the user's request. If it's ambiguous or missing, ask for it directly.
2. Run the CLI in JSON mode:
   ```bash
   repocheck <url> --json
   ```
3. Parse the JSON output. Key fields:
   - `verdict`: `"SEGURO"` | `"SUSPEITO"` | `"MALICIOSO"`.
   - `reasons`: the rule-based reasons behind the verdict.
   - `precheck`: reputation signals (`age_days`, `stars`, `forks`, `possible_typosquat`, `typosquat_match`, `reachable`).
   - `analysis`: `null` if Multipass wasn't available; otherwise an object with `secrets`, `malicious_patterns`, `git_findings` (each finding has `rule`, `file`, `line`, `snippet` — `snippet` is always empty for `secrets` findings by design, to avoid ever persisting a raw secret value) and the dynamic-step fields (`dynamic_attempted`, `dynamic_command`, `dynamic_timed_out`, `network_connect_attempts`).
   - `multipass_warning`: non-null if the analysis stage could not run at all.
4. If `verdict` is `"SUSPEITO"` or `"MALICIOSO"` and `analysis` is not `null`, read the `snippet` field of every entry in `malicious_patterns` and `git_findings` — this is the only source of the flagged content, since the VM that cloned the repository has already been destroyed by the time the CLI returns. Use your own judgment on top of the rule-based verdict: is this snippet clearly malicious (e.g. a base64-decoded downloader, a git submodule using the `ext::` transport), or could it plausibly be a legitimate, if unusual, pattern (e.g. a build script whose comment happens to mention "curl | bash" as something it explicitly avoids)? State your own read explicitly and separately from the rule-based reasons — the rules can have false positives, and your assessment of the actual snippet is what adds value beyond them.
5. Present the result conversationally: lead with the verdict, then the rule-based reasons, then your own read of any flagged snippets (if applicable), then a clear recommendation — safe to proceed, proceed with caution and review specific findings, or do not clone.
6. If `multipass_warning` is present, tell the user explicitly that only the reputation pre-check ran — the deeper analysis wasn't possible in this environment. Offer to help install Multipass if they want the full analysis.

## What NOT to do

- Never clone or read the target repository yourself outside of `repocheck` — that defeats the entire point of the isolated VM.
- Never upgrade a `SUSPEITO`/`MALICIOSO` verdict to "safe" based on your own judgment alone when a scanner could not run (`"scanner_not_executed"`) — say so explicitly instead of compensating for the gap.
- Never treat `analysis: null` as "no problems found" — it means "not checked," which is a materially different and more cautious message to give the user.
```

- [ ] **Step 2: Commit**

```bash
git add repocheck/.claude/skills/repo-safety-check/SKILL.md
git commit -m "docs(repocheck): add Claude Code skill for conversational repo safety checks"
```

---

## Task 2: Verificação manual de ponta a ponta

**Files:**
- Verification: manual (esta fase não introduz código Python novo, então não há suíte automatizada nova — a verificação é o próprio fluxo conversacional via Claude Code, conforme a estratégia de testes original do projeto: "teste manual da skill, fluxo ponta a ponta via Claude Code").

**Interfaces:**
- Consumes: a skill da Task 1, o CLI completo (Fases 1-5, já testado automaticamente em cada fase anterior).
- Produces: nada de novo — este task só confirma que a skill funciona como pretendido.

- [ ] **Step 1: Rodar a suíte automatizada completa uma última vez, para garantir uma baseline limpa antes da verificação manual**

```bash
cd repocheck && .venv/bin/pytest -v
```

Expected: todos os testes das Fases 1-5 passam (o teste de integração real pula se o Multipass não estiver instalado neste ambiente).

- [ ] **Step 2: Verificar manualmente o caso "Multipass indisponível" (o caso atual desta máquina)**

Numa sessão do Claude Code, dentro do diretório `repocheck/`, peça em linguagem natural: *"verifica se esse repositório é seguro: https://github.com/octocat/Hello-World"*.

Expected: o Claude invoca a skill, roda `repocheck --json`, e — como o Multipass não está instalado nesta máquina — apresenta um veredito `SUSPEITO` com aviso explícito de que a análise mais profunda não pôde ser executada, sem nunca alegar "seguro".

- [ ] **Step 3: (Se o Multipass estiver instalado num ambiente de teste) Verificar o caso de pipeline completo**

Repetir o mesmo pedido em um ambiente com Multipass instalado.

Expected: o Claude invoca a skill, o pipeline completo roda (precheck + análise estática/dinâmica dentro da VM), e o veredito final é `SEGURO` para esse repositório de demonstração (sem achados). Confirmar que a resposta conversacional inclui o veredito, os motivos, e — caso houvesse achados suspeitos/maliciosos — a leitura do Claude sobre os snippets sinalizados.

- [ ] **Step 4: Confirmar que a skill nunca tenta reler o repositório-alvo**

Revisar a transcrição da sessão das Steps 2-3 e confirmar que nenhuma chamada de ferramenta (Bash, Read, etc.) tentou clonar ou acessar o repositório-alvo fora da chamada a `repocheck --json` — toda a informação usada pela resposta conversacional deve vir exclusivamente do JSON retornado.

---

## Escopo do projeto — o que fica fora da v1 (todas as fases)

- Scanners/heurísticas específicos por gerenciador de pacotes além do que os scanners agnósticos já cobrem (Fase 3/4).
- Cache/allowlist de repositórios já analisados como seguros.
- Abstração de múltiplos backends de VM — só Multipass.
- Captura de acesso a arquivo fora do diretório do repositório durante a etapa dinâmica (Fase 4 só rastreia tentativas de conexão de rede via `strace`).
- Ecossistemas de build além de npm/pip na etapa dinâmica (Fase 4).
- Testes de integração com amostras reais de malware documentado publicamente (mencionados no spec original como parte da estratégia de testes) — ficam como extensão futura da suíte de integração das Fases 3/4, mantidas e manuseadas só dentro da VM efêmera, nunca no host.
