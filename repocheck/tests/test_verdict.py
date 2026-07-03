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
    assert any("secret" in reason for reason in result.reasons)


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
    assert any("network cutoff" in reason for reason in result.reasons)


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
