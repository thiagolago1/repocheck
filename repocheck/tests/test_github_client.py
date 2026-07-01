import responses

from repocheck.github_client import GitHubClientError, fetch_repo_metadata


@responses.activate
def test_fetch_repo_metadata_returns_json_on_success():
    responses.add(
        responses.GET,
        "https://api.github.com/repos/anthropics/claude-code",
        json={"stargazers_count": 42, "created_at": "2024-01-01T00:00:00Z"},
        status=200,
    )

    metadata = fetch_repo_metadata("anthropics", "claude-code")

    assert metadata["stargazers_count"] == 42
    assert metadata["created_at"] == "2024-01-01T00:00:00Z"


@responses.activate
def test_fetch_repo_metadata_raises_on_404():
    responses.add(
        responses.GET,
        "https://api.github.com/repos/anthropics/does-not-exist",
        json={"message": "Not Found"},
        status=404,
    )

    try:
        fetch_repo_metadata("anthropics", "does-not-exist")
        assert False, "expected GitHubClientError to be raised"
    except GitHubClientError as exc:
        assert "anthropics/does-not-exist" in str(exc)


@responses.activate
def test_fetch_repo_metadata_raises_on_server_error():
    responses.add(
        responses.GET,
        "https://api.github.com/repos/anthropics/claude-code",
        json={"message": "internal error"},
        status=500,
    )

    try:
        fetch_repo_metadata("anthropics", "claude-code")
        assert False, "expected an exception to be raised"
    except Exception:
        pass
