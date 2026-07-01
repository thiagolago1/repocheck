import responses

from repocheck.precheck import run_precheck


@responses.activate
def test_precheck_github_reachable_repo():
    responses.add(
        responses.GET,
        "https://api.github.com/repos/anthropics/claude-code",
        json={
            "created_at": "2020-01-01T00:00:00Z",
            "stargazers_count": 500,
            "forks_count": 20,
            "owner": {"type": "Organization"},
        },
        status=200,
    )

    result = run_precheck("https://github.com/anthropics/claude-code")

    assert result.location.platform == "github"
    assert result.reachable is True
    assert result.stars == 500
    assert result.forks == 20
    assert result.owner_type == "Organization"
    assert result.age_days is not None and result.age_days > 0
    assert result.possible_typosquat is False


@responses.activate
def test_precheck_github_unreachable_repo():
    responses.add(
        responses.GET,
        "https://api.github.com/repos/anthropics/does-not-exist",
        json={"message": "Not Found"},
        status=404,
    )

    result = run_precheck("https://github.com/anthropics/does-not-exist")

    assert result.reachable is False
    assert result.error is not None


@responses.activate
def test_precheck_gitlab_reachable_repo():
    responses.add(
        responses.GET,
        "https://gitlab.com/api/v4/projects/gitlab-org%2Fgitlab",
        json={
            "created_at": "2019-01-01T00:00:00.000Z",
            "star_count": 300,
            "forks_count": 15,
            "namespace": {"kind": "group"},
        },
        status=200,
    )

    result = run_precheck("https://gitlab.com/gitlab-org/gitlab")

    assert result.location.platform == "gitlab"
    assert result.reachable is True
    assert result.stars == 300
    assert result.forks == 15
    assert result.owner_type == "group"


def test_precheck_unknown_platform_is_skipped_without_error():
    result = run_precheck("https://git.example.com/team/project")

    assert result.location.platform == "unknown"
    assert result.reachable is False
    assert result.error is not None


def test_precheck_flags_typosquat_candidate():
    result = run_precheck("https://git.example.com/someone/reacct")

    assert result.possible_typosquat is True
    assert result.typosquat_match == "react"


@responses.activate
def test_precheck_github_server_error_marks_unreachable_instead_of_raising():
    """A 500 from the GitHub API raises requests.exceptions.HTTPError inside
    github_client.fetch_repo_metadata (not GitHubClientError, which is only
    raised for 404s). run_precheck must catch this broader class of failure
    too, so API/network errors never crash the precheck -- they always
    degrade to reachable=False with an error message."""
    responses.add(
        responses.GET,
        "https://api.github.com/repos/anthropics/claude-code",
        json={"message": "internal error"},
        status=500,
    )

    result = run_precheck("https://github.com/anthropics/claude-code")

    assert result.reachable is False
    assert result.error is not None
