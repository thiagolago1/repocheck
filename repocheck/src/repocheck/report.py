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
