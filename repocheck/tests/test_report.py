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
    verdict_result = VerdictResult(verdict=Verdict.SAFE, reasons=["no relevant findings"])

    output = render_report(precheck, analysis, verdict_result)

    assert "VERDICT: SAFE" in output
    assert "no relevant findings" in output


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
    verdict_result = VerdictResult(verdict=Verdict.MALICIOUS, reasons=["1 network connection attempt(s)"])

    output = render_report(precheck, analysis, verdict_result)

    assert "npm install" in output
    assert "Network attempts after cutoff: 1" in output


def test_render_report_does_not_count_scanner_not_executed_as_a_secret():
    precheck = _make_precheck()
    analysis = AnalysisReport(
        clone_succeeded=True,
        secrets=[
            {
                "rule": "scanner_not_executed",
                "file": "",
                "line": 0,
                "snippet": "detect-secrets unavailable",
            }
        ],
    )
    verdict_result = VerdictResult(
        verdict=Verdict.SUSPICIOUS, reasons=["the secrets scanner could not be executed"]
    )

    output = render_report(precheck, analysis, verdict_result)

    assert "Secrets found: 0" in output
    assert "scanner could not run" in output


def test_render_report_handles_missing_analysis():
    precheck = _make_precheck()
    verdict_result = VerdictResult(
        verdict=Verdict.SUSPICIOUS,
        reasons=["static/dynamic analysis could not be executed (Multipass unavailable)"],
    )

    output = render_report(precheck, None, verdict_result)

    assert "VERDICT: SUSPICIOUS" in output
    assert "not executed" in output
