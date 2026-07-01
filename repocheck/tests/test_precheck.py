import responses

from repocheck.platform import RepoLocation
from repocheck.precheck import _extract_repo_name, run_precheck


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


def test_extract_repo_name_skips_gitlab_tree_suffix_url():
    """A GitLab-style '/-/tree/<branch>' suffix produces a path with more
    than two segments, which is no longer guessed at -- only the
    unambiguous bare 'owner/repo' shape is handled, so this returns None
    rather than risking a wrong guess."""
    location = RepoLocation(
        platform="unknown",
        owner=None,
        repo=None,
        url="https://git.example.com/team/project/-/tree/main",
    )

    assert _extract_repo_name(location) is None


def test_extract_repo_name_strips_query_string():
    """A query string glued onto the last path segment (e.g. '?ref=main')
    must be stripped so the typosquat check compares against the bare repo
    name, not 'project?ref=main'."""
    location = RepoLocation(
        platform="unknown",
        owner=None,
        repo=None,
        url="https://git.example.com/team/project?ref=main",
    )

    assert _extract_repo_name(location) == "project"


def test_extract_repo_name_skips_nested_subgroup_url():
    """Nested GitLab groups/subgroups (owner/subgroup/repo) produce a path
    with three segments. Since that shape is ambiguous (the middle segment
    could be a subgroup or the repo could be elsewhere), the conservative
    rule skips it and returns None rather than guessing."""
    location = RepoLocation(
        platform="unknown",
        owner=None,
        repo=None,
        url="https://git.example.com/group/subgroup/project",
    )

    assert _extract_repo_name(location) is None


def test_extract_repo_name_returns_none_for_ambiguous_multi_segment_path():
    """A four-segment path like 'owner/group/repo/issues' is exactly the
    ambiguity that motivated dropping the marker-based algorithm: 'issues'
    could be a route suffix or (in principle) a literal path segment, and
    there's no way to tell without host-specific routing knowledge. The
    conservative rule never guesses on non-2-segment paths, so this must
    return None (previously the marker algorithm silently guessed 'repo',
    which happened to be right here only by luck of convention)."""
    location = RepoLocation(
        platform="unknown",
        owner=None,
        repo=None,
        url="https://git.example.com/owner/group/repo/issues",
    )

    assert _extract_repo_name(location) is None


def test_extract_repo_name_handles_two_segment_marker_word_collision():
    """A repo name that happens to collide with a word the old marker-based
    algorithm treated specially (e.g. 'wiki') must still resolve correctly
    when the path is the unambiguous two-segment 'owner/repo' shape -- no
    special-casing of marker words is needed anymore."""
    location = RepoLocation(
        platform="unknown",
        owner=None,
        repo=None,
        url="https://git.example.com/octocat/wiki",
    )

    assert _extract_repo_name(location) == "wiki"


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
