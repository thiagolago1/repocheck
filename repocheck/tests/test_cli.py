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
    assert "VERDICT: SAFE" in result.output


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
    assert "VERDICT: MALICIOUS" in result.output


def test_cli_json_output_includes_verdict_and_reports():
    runner = CliRunner()
    with patch("repocheck.cli.run_precheck", return_value=_fake_precheck()):
        with patch("repocheck.cli.run_analysis", return_value=_fake_clean_analysis()):
            result = runner.invoke(main, ["https://github.com/acme/widget", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["verdict"] == "SAFE"
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
    assert "WARNING" in result.output
    assert "VERDICT: SUSPICIOUS" in result.output


def test_cli_json_output_includes_multipass_warning():
    runner = CliRunner()
    with patch("repocheck.cli.run_precheck", return_value=_fake_precheck()):
        with patch(
            "repocheck.cli.run_analysis",
            side_effect=MultipassNotAvailable("multipass CLI not found"),
        ):
            result = runner.invoke(main, ["https://github.com/acme/widget", "--json"])

    payload = json.loads(result.stdout)
    assert payload["analysis"] is None
    assert payload["multipass_warning"] == "multipass CLI not found"
    assert payload["verdict"] == "SUSPICIOUS"
