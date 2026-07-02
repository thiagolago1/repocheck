# Repo Safety Check — Fase 5: Montagem do Relatório/Veredito Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Combinar o `PrecheckResult` (Fase 1) e o `AnalysisReport` (Fases 3+4) numa lógica de veredito baseada em regras (SEGURO/SUSPEITO/MALICIOSO com motivos explícitos), renderizar isso como relatório legível, e ligar tudo isso no CLI, que agora roda o pipeline completo: pré-check → análise (se o Multipass estiver disponível) → veredito → relatório.

**Architecture:** `repocheck/src/repocheck/verdict.py` contém a lógica pura de composição de veredito (`compute_verdict`), testável com combinações sintéticas de achados sem precisar de rede/VM. `repocheck/src/repocheck/report.py` renderiza esse resultado como texto. `repocheck/src/repocheck/cli.py` é reescrito para orquestrar as três etapas (precheck, análise, veredito) e tratar a ausência do Multipass de forma explícita (nunca "SEGURO" silencioso).

**Tech Stack:** Mesmo das fases anteriores — Python stdlib (`dataclasses`, `enum`) + Click (já usado no CLI).

## Global Constraints

- Falha de um scanner (achado `"scanner_not_executed"`) nunca resulta em veredito SEGURO — no mínimo SUSPEITO.
- Ausência de análise (Multipass indisponível, `analysis is None`) nunca resulta em veredito SEGURO — sempre SUSPEITO, com aviso explícito ao usuário.
- MALICIOSO tem prioridade sobre SUSPEITO: se qualquer achado malicioso existir, o veredito é MALICIOSO mesmo que também existam sinais apenas suspeitos — nunca "dilui" um achado grave por causa de sinais mistos.
- O relatório sempre lista os motivos por trás do veredito — nunca um veredito sem justificativa (`reasons` nunca vazio).
- Se a etapa dinâmica rodou (`dynamic_attempted=True`) mas o corte de rede não foi confirmado (`network_cutoff_applied is False`), isso é pelo menos SUSPEITO — o build/install pode ter rodado com acesso à rede, o que enfraquece qualquer achado "limpo" da etapa dinâmica (sugestão incorporada da revisão final da Fase 4).

---

## Task 1: Lógica de composição de veredito (`compute_verdict`)

**Files:**
- Create: `repocheck/src/repocheck/verdict.py`
- Test: `repocheck/tests/test_verdict.py`

**Interfaces:**
- Consumes: `repocheck.precheck.PrecheckResult`, `repocheck.platform.RepoLocation` (Fase 1); `repocheck.analysis.AnalysisReport` (Fases 3+4).
- Produces: `repocheck.verdict.Verdict` (enum: `SAFE = "SEGURO"`, `SUSPICIOUS = "SUSPEITO"`, `MALICIOUS = "MALICIOSO"`), `repocheck.verdict.VerdictResult` (dataclass: `verdict: Verdict`, `reasons: list[str]`), `repocheck.verdict.compute_verdict(precheck: PrecheckResult, analysis: AnalysisReport | None) -> VerdictResult`.

- [ ] **Step 1: Escrever os testes de composição de veredito (devem falhar)**

Criar `repocheck/tests/test_verdict.py`:

```python
from repocheck.analysis import AnalysisReport
from repocheck.platform import RepoLocation
from repocheck.precheck import PrecheckResult
from repocheck.verdict import Verdict, compute_verdict


def _make_precheck(**overrides) -> PrecheckResult:
    defaults = dict(
        location=RepoLocation(
            platform="github",
            owner="acme",
            repo="widget",
            url="https://github.com/acme/widget",
        ),
        reachable=True,
        age_days=1000,
        stars=500,
        forks=20,
        owner_type="Organization",
        possible_typosquat=False,
        typosquat_match=None,
        error=None,
    )
    defaults.update(overrides)
    return PrecheckResult(**defaults)


def _make_analysis(**overrides) -> AnalysisReport:
    defaults = dict(
        clone_succeeded=True,
        malicious_patterns=[],
        git_findings=[],
        secrets=[],
        dynamic_attempted=False,
        dynamic_command=None,
        dynamic_exit_code=None,
        dynamic_timed_out=False,
        network_cutoff_applied=None,
        network_connect_attempts=[],
        error=None,
    )
    defaults.update(overrides)
    return AnalysisReport(**defaults)


def test_clean_repo_is_safe():
    result = compute_verdict(_make_precheck(), _make_analysis())
    assert result.verdict == Verdict.SAFE
    assert result.reasons


def test_secrets_found_is_malicious():
    analysis = _make_analysis(
        secrets=[{"rule": "secret_aws_key", "file": "config.py", "line": 1, "snippet": ""}]
    )
    result = compute_verdict(_make_precheck(), analysis)
    assert result.verdict == Verdict.MALICIOUS
    assert any("segredo" in reason for reason in result.reasons)


def test_malicious_pattern_found_is_malicious():
    analysis = _make_analysis(
        malicious_patterns=[
            {"rule": "curl_pipe_shell", "file": "install.sh", "line": 2, "snippet": "curl x | bash"}
        ]
    )
    result = compute_verdict(_make_precheck(), analysis)
    assert result.verdict == Verdict.MALICIOUS


def test_gitmodules_ext_transport_is_malicious():
    analysis = _make_analysis(
        git_findings=[
            {"rule": "gitmodules_ext_transport", "file": ".gitmodules", "line": 3, "snippet": "url = ext::sh -c x"}
        ]
    )
    result = compute_verdict(_make_precheck(), analysis)
    assert result.verdict == Verdict.MALICIOUS


def test_network_connect_attempts_after_cutoff_is_malicious():
    analysis = _make_analysis(network_connect_attempts=["connect(3, ...)"])
    result = compute_verdict(_make_precheck(), analysis)
    assert result.verdict == Verdict.MALICIOUS


def test_other_git_finding_is_suspicious_not_malicious():
    analysis = _make_analysis(
        git_findings=[{"rule": "nested_git_path", "file": "vendor/.git", "line": 0, "snippet": ""}]
    )
    result = compute_verdict(_make_precheck(), analysis)
    assert result.verdict == Verdict.SUSPICIOUS


def test_typosquat_candidate_is_suspicious():
    precheck = _make_precheck(possible_typosquat=True, typosquat_match="react")
    result = compute_verdict(precheck, _make_analysis())
    assert result.verdict == Verdict.SUSPICIOUS
    assert any("typosquat" in reason for reason in result.reasons)


def test_young_and_unpopular_repo_is_suspicious():
    precheck = _make_precheck(age_days=2, stars=0)
    result = compute_verdict(precheck, _make_analysis())
    assert result.verdict == Verdict.SUSPICIOUS


def test_dynamic_timeout_is_suspicious():
    analysis = _make_analysis(dynamic_attempted=True, dynamic_timed_out=True)
    result = compute_verdict(_make_precheck(), analysis)
    assert result.verdict == Verdict.SUSPICIOUS


def test_dynamic_step_without_confirmed_network_cutoff_is_suspicious():
    analysis = _make_analysis(
        dynamic_attempted=True, network_cutoff_applied=False
    )
    result = compute_verdict(_make_precheck(), analysis)
    assert result.verdict == Verdict.SUSPICIOUS
    assert any("corte de rede" in reason for reason in result.reasons)


def test_dynamic_not_attempted_with_no_cutoff_info_is_safe():
    analysis = _make_analysis(dynamic_attempted=False, network_cutoff_applied=None)
    result = compute_verdict(_make_precheck(), analysis)
    assert result.verdict == Verdict.SAFE


def test_scanner_not_executed_is_suspicious_not_safe():
    analysis = _make_analysis(
        secrets=[
            {"rule": "scanner_not_executed", "file": "", "line": 0, "snippet": "detect-secrets unavailable"}
        ]
    )
    result = compute_verdict(_make_precheck(), analysis)
    assert result.verdict == Verdict.SUSPICIOUS


def test_analysis_error_is_suspicious():
    analysis = _make_analysis(clone_succeeded=False, error="clone failed: repository not found")
    result = compute_verdict(_make_precheck(), analysis)
    assert result.verdict == Verdict.SUSPICIOUS


def test_analysis_none_is_suspicious():
    result = compute_verdict(_make_precheck(), None)
    assert result.verdict == Verdict.SUSPICIOUS
    assert any("Multipass" in reason for reason in result.reasons)


def test_malicious_takes_priority_over_suspicious_signals():
    analysis = _make_analysis(
        secrets=[{"rule": "secret_aws_key", "file": "x", "line": 1, "snippet": ""}],
        git_findings=[{"rule": "nested_git_path", "file": "vendor/.git", "line": 0, "snippet": ""}],
    )
    precheck = _make_precheck(possible_typosquat=True, typosquat_match="react")
    result = compute_verdict(precheck, analysis)
    assert result.verdict == Verdict.MALICIOUS
    assert len(result.reasons) >= 2
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

```bash
cd repocheck && .venv/bin/pytest tests/test_verdict.py -v
```

Expected: FAIL com `ModuleNotFoundError: No module named 'repocheck.verdict'`.

- [ ] **Step 3: Implementar `compute_verdict`**

Criar `repocheck/src/repocheck/verdict.py`:

```python
from dataclasses import dataclass, field
from enum import Enum

from repocheck.analysis import AnalysisReport
from repocheck.precheck import PrecheckResult

_YOUNG_REPO_AGE_DAYS = 7
_LOW_STAR_THRESHOLD = 5


class Verdict(Enum):
    SAFE = "SEGURO"
    SUSPICIOUS = "SUSPEITO"
    MALICIOUS = "MALICIOSO"


@dataclass
class VerdictResult:
    verdict: Verdict
    reasons: list[str] = field(default_factory=list)


def compute_verdict(
    precheck: PrecheckResult, analysis: AnalysisReport | None
) -> VerdictResult:
    if analysis is None:
        return VerdictResult(
            verdict=Verdict.SUSPICIOUS,
            reasons=[
                "análise dinâmica/estática não pôde ser executada (Multipass indisponível)"
            ],
        )

    malicious_reasons: list[str] = []
    suspicious_reasons: list[str] = []

    if analysis.error is not None:
        suspicious_reasons.append(f"análise incompleta: {analysis.error}")

    real_secrets = [f for f in analysis.secrets if f["rule"] != "scanner_not_executed"]
    if real_secrets:
        malicious_reasons.append(
            f"{len(real_secrets)} segredo(s) encontrado(s) no código"
        )

    scanner_gaps = [f for f in analysis.secrets if f["rule"] == "scanner_not_executed"]
    if scanner_gaps:
        suspicious_reasons.append("scanner de secrets não pôde ser executado")

    if analysis.malicious_patterns:
        malicious_reasons.append(
            f"{len(analysis.malicious_patterns)} padrão(ões) malicioso(s) encontrado(s)"
        )

    ext_transport_findings = [
        f for f in analysis.git_findings if f["rule"] == "gitmodules_ext_transport"
    ]
    if ext_transport_findings:
        malicious_reasons.append(
            "submódulo git usando transporte 'ext::' (execução arbitrária de comando)"
        )

    other_git_findings = [
        f for f in analysis.git_findings if f["rule"] != "gitmodules_ext_transport"
    ]
    if other_git_findings:
        suspicious_reasons.append(
            f"{len(other_git_findings)} achado(s) suspeito(s) específico(s) de git"
        )

    if analysis.network_connect_attempts:
        malicious_reasons.append(
            f"{len(analysis.network_connect_attempts)} tentativa(s) de conexão de "
            "rede após o corte de rede"
        )

    if analysis.dynamic_timed_out:
        suspicious_reasons.append("etapa dinâmica não terminou dentro do timeout")

    if analysis.dynamic_attempted and analysis.network_cutoff_applied is False:
        suspicious_reasons.append(
            "a etapa dinâmica rodou sem corte de rede confirmado (iptables falhou "
            "dentro da VM) — o build/install pode ter tido acesso à rede"
        )

    if precheck.possible_typosquat:
        suspicious_reasons.append(
            f"nome suspeito de typosquatting (parecido com '{precheck.typosquat_match}')"
        )

    if (
        precheck.reachable
        and precheck.age_days is not None
        and precheck.age_days < _YOUNG_REPO_AGE_DAYS
        and precheck.stars is not None
        and precheck.stars < _LOW_STAR_THRESHOLD
    ):
        suspicious_reasons.append(
            f"repositório muito novo ({precheck.age_days} dia(s)) e pouco popular "
            f"({precheck.stars} estrela(s))"
        )

    if malicious_reasons:
        return VerdictResult(
            verdict=Verdict.MALICIOUS, reasons=malicious_reasons + suspicious_reasons
        )
    if suspicious_reasons:
        return VerdictResult(verdict=Verdict.SUSPICIOUS, reasons=suspicious_reasons)
    return VerdictResult(verdict=Verdict.SAFE, reasons=["nenhum achado relevante"])
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

```bash
cd repocheck && .venv/bin/pytest tests/test_verdict.py -v
```

Expected: 15 passed.

- [ ] **Step 5: Commit**

```bash
git add repocheck/src/repocheck/verdict.py repocheck/tests/test_verdict.py
git commit -m "feat(repocheck): add rules-based verdict composition from precheck and analysis findings"
```

---

## Task 2: Renderização do relatório

**Files:**
- Create: `repocheck/src/repocheck/report.py`
- Test: `repocheck/tests/test_report.py`

**Interfaces:**
- Consumes: `repocheck.precheck.PrecheckResult`, `repocheck.platform.RepoLocation` (Fase 1); `repocheck.analysis.AnalysisReport` (Fases 3+4); `repocheck.verdict.Verdict`, `repocheck.verdict.VerdictResult` (Task 1).
- Produces: `repocheck.report.render_report(precheck: PrecheckResult, analysis: AnalysisReport | None, verdict_result: VerdictResult) -> str`.

- [ ] **Step 1: Escrever os testes de renderização (devem falhar)**

Criar `repocheck/tests/test_report.py`:

```python
from repocheck.analysis import AnalysisReport
from repocheck.platform import RepoLocation
from repocheck.precheck import PrecheckResult
from repocheck.report import render_report
from repocheck.verdict import Verdict, VerdictResult


def _make_precheck(**overrides) -> PrecheckResult:
    defaults = dict(
        location=RepoLocation(
            platform="github",
            owner="acme",
            repo="widget",
            url="https://github.com/acme/widget",
        ),
        reachable=True,
        age_days=1000,
        stars=500,
        forks=20,
        owner_type="Organization",
        possible_typosquat=False,
        typosquat_match=None,
    )
    defaults.update(overrides)
    return PrecheckResult(**defaults)


def test_render_report_includes_verdict_and_reasons():
    precheck = _make_precheck()
    analysis = AnalysisReport(clone_succeeded=True)
    verdict_result = VerdictResult(verdict=Verdict.SAFE, reasons=["nenhum achado relevante"])

    output = render_report(precheck, analysis, verdict_result)

    assert "VEREDITO: SEGURO" in output
    assert "nenhum achado relevante" in output


def test_render_report_includes_precheck_summary():
    precheck = _make_precheck(stars=1234, forks=56)
    analysis = AnalysisReport(clone_succeeded=True)
    verdict_result = VerdictResult(verdict=Verdict.SAFE, reasons=["ok"])

    output = render_report(precheck, analysis, verdict_result)

    assert "github" in output
    assert "1234" in output
    assert "56" in output


def test_render_report_includes_dynamic_step_summary_when_attempted():
    precheck = _make_precheck()
    analysis = AnalysisReport(
        clone_succeeded=True,
        dynamic_attempted=True,
        dynamic_command=["npm", "install"],
        dynamic_timed_out=False,
        network_connect_attempts=["connect(3, ...)"],
    )
    verdict_result = VerdictResult(verdict=Verdict.MALICIOUS, reasons=["1 tentativa(s) de conexão de rede"])

    output = render_report(precheck, analysis, verdict_result)

    assert "npm install" in output
    assert "Tentativas de rede após corte: 1" in output


def test_render_report_handles_missing_analysis():
    precheck = _make_precheck()
    verdict_result = VerdictResult(
        verdict=Verdict.SUSPICIOUS,
        reasons=["análise dinâmica/estática não pôde ser executada (Multipass indisponível)"],
    )

    output = render_report(precheck, None, verdict_result)

    assert "VEREDITO: SUSPEITO" in output
    assert "não executada" in output
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

```bash
cd repocheck && .venv/bin/pytest tests/test_report.py -v
```

Expected: FAIL com `ModuleNotFoundError: No module named 'repocheck.report'`.

- [ ] **Step 3: Implementar `render_report`**

Criar `repocheck/src/repocheck/report.py`:

```python
from repocheck.analysis import AnalysisReport
from repocheck.precheck import PrecheckResult
from repocheck.verdict import VerdictResult


def render_report(
    precheck: PrecheckResult,
    analysis: AnalysisReport | None,
    verdict_result: VerdictResult,
) -> str:
    lines = [f"VEREDITO: {verdict_result.verdict.value}", "", "Motivos:"]
    for reason in verdict_result.reasons:
        lines.append(f"  - {reason}")

    lines.append("")
    lines.append("Pré-check:")
    lines.append(f"  Plataforma: {precheck.location.platform}")
    lines.append(f"  Alcançável: {'sim' if precheck.reachable else 'não'}")
    if precheck.reachable:
        lines.append(f"  Idade (dias): {precheck.age_days}")
        lines.append(f"  Estrelas: {precheck.stars}")
        lines.append(f"  Forks: {precheck.forks}")

    if analysis is None:
        lines.append("")
        lines.append("Análise (estática/dinâmica): não executada (Multipass indisponível)")
        return "\n".join(lines)

    lines.append("")
    lines.append("Análise estática:")
    lines.append(f"  Clone bem-sucedido: {'sim' if analysis.clone_succeeded else 'não'}")
    lines.append(f"  Secrets encontrados: {len(analysis.secrets)}")
    lines.append(f"  Padrões maliciosos: {len(analysis.malicious_patterns)}")
    lines.append(f"  Achados de git: {len(analysis.git_findings)}")

    lines.append("")
    lines.append("Etapa dinâmica:")
    lines.append(f"  Tentada: {'sim' if analysis.dynamic_attempted else 'não'}")
    if analysis.dynamic_attempted:
        lines.append(f"  Comando: {' '.join(analysis.dynamic_command or [])}")
        lines.append(f"  Timeout: {'sim' if analysis.dynamic_timed_out else 'não'}")
        lines.append(
            f"  Tentativas de rede após corte: {len(analysis.network_connect_attempts)}"
        )

    return "\n".join(lines)
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

```bash
cd repocheck && .venv/bin/pytest tests/test_report.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add repocheck/src/repocheck/report.py repocheck/tests/test_report.py
git commit -m "feat(repocheck): render the combined precheck/analysis/verdict report"
```

---

## Task 3: Ligar tudo no CLI (pipeline completo)

**Files:**
- Modify: `repocheck/src/repocheck/cli.py`
- Modify: `repocheck/tests/test_cli.py`

**Interfaces:**
- Consumes: `repocheck.precheck.run_precheck` (Fase 1); `repocheck.analysis.run_analysis` (Fases 3+4); `repocheck.vm.MultipassNotAvailable` (Fase 2); `repocheck.verdict.compute_verdict` (Task 1); `repocheck.report.render_report` (Task 2).
- Produces: comando `repocheck <url>` rodando o pipeline completo (precheck → análise → veredito → relatório), com `--json` emitindo tudo isso como JSON estruturado.

- [ ] **Step 1: Escrever os testes do CLI completo (devem falhar)**

Substituir o conteúdo inteiro de `repocheck/tests/test_cli.py` por:

```python
import json
from unittest.mock import patch

from click.testing import CliRunner

from repocheck.analysis import AnalysisReport
from repocheck.cli import main
from repocheck.platform import RepoLocation
from repocheck.precheck import PrecheckResult
from repocheck.vm import MultipassNotAvailable


def _fake_precheck() -> PrecheckResult:
    return PrecheckResult(
        location=RepoLocation(
            platform="github",
            owner="acme",
            repo="widget",
            url="https://github.com/acme/widget",
        ),
        reachable=True,
        age_days=500,
        stars=1000,
        forks=50,
        owner_type="Organization",
        possible_typosquat=False,
        typosquat_match=None,
    )


def _fake_clean_analysis() -> AnalysisReport:
    return AnalysisReport(clone_succeeded=True)


def test_cli_reports_safe_verdict_for_clean_repo():
    runner = CliRunner()
    with patch("repocheck.cli.run_precheck", return_value=_fake_precheck()):
        with patch("repocheck.cli.run_analysis", return_value=_fake_clean_analysis()):
            result = runner.invoke(main, ["https://github.com/acme/widget"])

    assert result.exit_code == 0
    assert "VEREDITO: SEGURO" in result.output


def test_cli_reports_malicious_verdict_when_secrets_found():
    runner = CliRunner()
    malicious_analysis = AnalysisReport(
        clone_succeeded=True,
        secrets=[{"rule": "secret_aws_key", "file": "config.py", "line": 1, "snippet": ""}],
    )
    with patch("repocheck.cli.run_precheck", return_value=_fake_precheck()):
        with patch("repocheck.cli.run_analysis", return_value=malicious_analysis):
            result = runner.invoke(main, ["https://github.com/acme/widget"])

    assert result.exit_code == 0
    assert "VEREDITO: MALICIOSO" in result.output


def test_cli_json_output_includes_verdict_and_reports():
    runner = CliRunner()
    with patch("repocheck.cli.run_precheck", return_value=_fake_precheck()):
        with patch("repocheck.cli.run_analysis", return_value=_fake_clean_analysis()):
            result = runner.invoke(main, ["https://github.com/acme/widget", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["verdict"] == "SEGURO"
    assert payload["precheck"]["location"]["platform"] == "github"
    assert payload["analysis"]["clone_succeeded"] is True


def test_cli_handles_multipass_unavailable_gracefully():
    runner = CliRunner()
    with patch("repocheck.cli.run_precheck", return_value=_fake_precheck()):
        with patch(
            "repocheck.cli.run_analysis",
            side_effect=MultipassNotAvailable("multipass CLI not found"),
        ):
            result = runner.invoke(main, ["https://github.com/acme/widget"])

    assert result.exit_code == 0
    assert "AVISO" in result.output
    assert "VEREDITO: SUSPEITO" in result.output


def test_cli_json_output_includes_multipass_warning():
    runner = CliRunner()
    with patch("repocheck.cli.run_precheck", return_value=_fake_precheck()):
        with patch(
            "repocheck.cli.run_analysis",
            side_effect=MultipassNotAvailable("multipass CLI not found"),
        ):
            result = runner.invoke(main, ["https://github.com/acme/widget", "--json"])

    payload = json.loads(result.output)
    assert payload["analysis"] is None
    assert payload["multipass_warning"] == "multipass CLI not found"
    assert payload["verdict"] == "SUSPEITO"
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

```bash
cd repocheck && .venv/bin/pytest tests/test_cli.py -v
```

Expected: FAIL — `repocheck.cli` ainda não expõe `run_analysis`, e a saída ainda é o formato antigo da Fase 1 (sem "VEREDITO:").

- [ ] **Step 3: Reescrever o CLI**

Substituir o conteúdo inteiro de `repocheck/src/repocheck/cli.py` por:

```python
import json
from dataclasses import asdict

import click

from repocheck.analysis import run_analysis
from repocheck.precheck import run_precheck
from repocheck.report import render_report
from repocheck.verdict import compute_verdict
from repocheck.vm import MultipassNotAvailable


@click.command()
@click.argument("url")
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Output raw JSON instead of a human-readable report.",
)
def main(url: str, as_json: bool) -> None:
    precheck = run_precheck(url)

    analysis = None
    multipass_warning = None
    try:
        analysis = run_analysis(url)
    except MultipassNotAvailable as exc:
        multipass_warning = str(exc)

    verdict_result = compute_verdict(precheck, analysis)

    if as_json:
        payload = {
            "verdict": verdict_result.verdict.value,
            "reasons": verdict_result.reasons,
            "precheck": asdict(precheck),
            "analysis": asdict(analysis) if analysis is not None else None,
            "multipass_warning": multipass_warning,
        }
        click.echo(json.dumps(payload, indent=2, default=str))
        return

    if multipass_warning is not None:
        click.echo(f"AVISO: {multipass_warning}")
        click.echo("")

    click.echo(render_report(precheck, analysis, verdict_result))


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

```bash
cd repocheck && .venv/bin/pytest tests/test_cli.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Rodar a suíte completa do projeto**

```bash
cd repocheck && .venv/bin/pytest -v
```

Expected: todos os testes das Fases 1-5 passam (sem regressões); o teste de integração real da Fase 3/4 pula se o Multipass não estiver instalado.

- [ ] **Step 6: Testar manualmente o CLI de ponta a ponta (se o Multipass estiver instalado) ou confirmar o aviso gracioso (se não estiver)**

```bash
cd repocheck && .venv/bin/repocheck https://github.com/octocat/Hello-World
```

Expected: se o Multipass não estiver instalado neste ambiente, a saída mostra `AVISO: multipass CLI not found or not working...` seguido de `VEREDITO: SUSPEITO`. Se estiver instalado, roda o pipeline completo e mostra `VEREDITO: SEGURO` (repositório de demonstração oficial do GitHub, sem achados).

- [ ] **Step 7: Commit**

```bash
git add repocheck/src/repocheck/cli.py repocheck/tests/test_cli.py
git commit -m "feat(repocheck): wire precheck, analysis, and verdict into the full CLI pipeline"
```

---

## Escopo desta fase — o que fica para depois

- A revisão por LLM (Claude lendo os achados sinalizados e julgando intenção) fica para a Fase 6 — esta fase só produz o veredito baseado em regras determinísticas e o relatório para consumo direto (terminal ou JSON).
- A skill do Claude Code que expõe isso em linguagem natural também fica para a Fase 6.
- Refinamentos na lógica de veredito (ex: pesos diferentes por severidade, mais sinais de reputação) ficam como ajuste futuro — as regras desta fase são deliberadamente simples e auditáveis, cobrindo os sinais que já existem nas fases anteriores.
