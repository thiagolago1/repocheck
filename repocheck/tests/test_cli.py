import json
from unittest.mock import patch

from click.testing import CliRunner

from repocheck.cli import main
from repocheck.platform import RepoLocation
from repocheck.precheck import PrecheckResult


def _fake_result() -> PrecheckResult:
    return PrecheckResult(
        location=RepoLocation(
            platform="github", owner="anthropics", repo="claude-code",
            url="https://github.com/anthropics/claude-code",
        ),
        reachable=True,
        age_days=500,
        stars=1000,
        forks=50,
        owner_type="Organization",
        possible_typosquat=False,
        typosquat_match=None,
        raw={"stargazers_count": 1000},
    )


def test_cli_human_readable_output():
    runner = CliRunner()
    with patch("repocheck.cli.run_precheck", return_value=_fake_result()):
        result = runner.invoke(main, ["https://github.com/anthropics/claude-code"])

    assert result.exit_code == 0
    assert "Platform: github" in result.output
    assert "Stars: 1000" in result.output


def test_cli_json_output():
    runner = CliRunner()
    with patch("repocheck.cli.run_precheck", return_value=_fake_result()):
        result = runner.invoke(
            main, ["https://github.com/anthropics/claude-code", "--json"]
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["location"]["platform"] == "github"
    assert payload["stars"] == 1000


def test_cli_warns_on_typosquat():
    typosquat_result = _fake_result()
    typosquat_result.possible_typosquat = True
    typosquat_result.typosquat_match = "react"

    runner = CliRunner()
    with patch("repocheck.cli.run_precheck", return_value=typosquat_result):
        result = runner.invoke(main, ["https://github.com/someone/reacct"])

    assert "WARNING" in result.output
    assert "react" in result.output
