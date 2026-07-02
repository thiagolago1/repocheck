import pytest

from repocheck.analysis import run_static_analysis
from repocheck.vm import check_multipass_available

pytestmark = pytest.mark.skipif(
    not check_multipass_available(),
    reason="multipass CLI not installed/available in this environment",
)


def test_static_analysis_full_pipeline_against_real_public_repo():
    report = run_static_analysis(
        "https://github.com/octocat/Hello-World", timeout=300.0
    )

    assert report.clone_succeeded is True
    assert report.error is None
    assert isinstance(report.malicious_patterns, list)
    assert isinstance(report.git_findings, list)
    assert isinstance(report.secrets, list)
