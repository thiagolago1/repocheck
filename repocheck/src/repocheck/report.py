from repocheck.analysis import AnalysisReport
from repocheck.precheck import PrecheckResult
from repocheck.verdict import Verdict, VerdictResult

_VERDICT_EMOJI = {
    Verdict.SAFE: "✅",
    Verdict.SUSPICIOUS: "⚠️",
    Verdict.MALICIOUS: "🚨",
}


def render_report(
    precheck: PrecheckResult,
    analysis: AnalysisReport | None,
    verdict_result: VerdictResult,
) -> str:
    emoji = _VERDICT_EMOJI[verdict_result.verdict]
    lines = [f"{emoji} VERDICT: {verdict_result.verdict.value}", "", "Reasons:"]
    for reason in verdict_result.reasons:
        lines.append(f"  - {reason}")

    lines.append("")
    lines.append("Precheck:")
    lines.append(f"  Platform: {precheck.location.platform}")
    lines.append(f"  Reachable: {'yes' if precheck.reachable else 'no'}")
    if precheck.reachable:
        lines.append(f"  Age (days): {precheck.age_days}")
        lines.append(f"  Stars: {precheck.stars}")
        lines.append(f"  Forks: {precheck.forks}")

    if analysis is None:
        lines.append("")
        lines.append("Analysis (static/dynamic): not executed (Multipass unavailable)")
        return "\n".join(lines)

    real_secrets = [f for f in analysis.secrets if f["rule"] != "scanner_not_executed"]
    secrets_scanner_failed = len(real_secrets) != len(analysis.secrets)

    lines.append("")
    lines.append("Static analysis:")
    lines.append(f"  Clone succeeded: {'yes' if analysis.clone_succeeded else 'no'}")
    secrets_line = f"  Secrets found: {len(real_secrets)}"
    if secrets_scanner_failed:
        secrets_line += " (scanner could not run — not confirmed clean)"
    lines.append(secrets_line)
    lines.append(f"  Malicious patterns: {len(analysis.malicious_patterns)}")
    lines.append(f"  Git findings: {len(analysis.git_findings)}")

    lines.append("")
    lines.append("Dynamic step:")
    lines.append(f"  Attempted: {'yes' if analysis.dynamic_attempted else 'no'}")
    if analysis.dynamic_attempted:
        lines.append(f"  Command: {' '.join(analysis.dynamic_command or [])}")
        lines.append(f"  Timed out: {'yes' if analysis.dynamic_timed_out else 'no'}")
        lines.append(
            f"  Network attempts after cutoff: {len(analysis.network_connect_attempts)}"
        )

    return "\n".join(lines)
