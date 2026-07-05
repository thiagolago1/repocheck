from dataclasses import dataclass, field
from enum import Enum

from repocheck.analysis import AnalysisReport
from repocheck.precheck import PrecheckResult

_YOUNG_REPO_AGE_DAYS = 7
_LOW_STAR_THRESHOLD = 5


class Verdict(Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


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
                "static/dynamic analysis could not be executed (Multipass unavailable)"
            ],
        )

    malicious_reasons: list[str] = []
    suspicious_reasons: list[str] = []

    if analysis.error is not None:
        suspicious_reasons.append(f"incomplete analysis: {analysis.error}")

    real_secrets = [f for f in analysis.secrets if f["rule"] != "scanner_not_executed"]
    if real_secrets:
        malicious_reasons.append(
            f"{len(real_secrets)} secret(s) found in the code"
        )

    scanner_gaps = [f for f in analysis.secrets if f["rule"] == "scanner_not_executed"]
    if scanner_gaps:
        suspicious_reasons.append("the secrets scanner could not be executed")

    if analysis.malicious_patterns:
        malicious_reasons.append(
            f"{len(analysis.malicious_patterns)} malicious pattern(s) found"
        )

    ext_transport_findings = [
        f for f in analysis.git_findings if f["rule"] == "gitmodules_ext_transport"
    ]
    if ext_transport_findings:
        malicious_reasons.append(
            "git submodule using the 'ext::' transport (arbitrary command execution)"
        )

    other_git_findings = [
        f for f in analysis.git_findings if f["rule"] != "gitmodules_ext_transport"
    ]
    if other_git_findings:
        suspicious_reasons.append(
            f"{len(other_git_findings)} git-specific finding(s)"
        )

    if analysis.network_connect_attempts:
        # The dynamic step cuts the network then runs the package manager,
        # whose job is to fetch declared dependencies — so every normal
        # project with dependencies produces attempts here. Surface it, but
        # don't call it malicious on its own (that would flag essentially
        # every npm/pip project). MALICIOUS is reserved for the signals
        # below that genuinely imply intent.
        suspicious_reasons.append(
            f"{len(analysis.network_connect_attempts)} network connection attempt(s) "
            "after the network cutoff"
        )

    if analysis.dynamic_timed_out:
        suspicious_reasons.append("the dynamic step did not finish within the timeout")

    if analysis.dynamic_attempted and analysis.network_cutoff_applied is False:
        suspicious_reasons.append(
            "the dynamic step ran without a confirmed network cutoff (iptables "
            "failed inside the VM) — the build/install may have had network access"
        )

    if precheck.possible_typosquat:
        suspicious_reasons.append(
            f"suspicious name, resembling a typosquat of '{precheck.typosquat_match}'"
        )

    if (
        precheck.reachable
        and precheck.age_days is not None
        and precheck.age_days < _YOUNG_REPO_AGE_DAYS
        and precheck.stars is not None
        and precheck.stars < _LOW_STAR_THRESHOLD
    ):
        suspicious_reasons.append(
            f"very young repository ({precheck.age_days} day(s) old) with low "
            f"popularity ({precheck.stars} star(s))"
        )

    if malicious_reasons:
        return VerdictResult(
            verdict=Verdict.MALICIOUS, reasons=malicious_reasons + suspicious_reasons
        )
    if suspicious_reasons:
        return VerdictResult(verdict=Verdict.SUSPICIOUS, reasons=suspicious_reasons)
    return VerdictResult(verdict=Verdict.SAFE, reasons=["no relevant findings"])
