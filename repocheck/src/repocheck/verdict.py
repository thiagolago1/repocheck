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
