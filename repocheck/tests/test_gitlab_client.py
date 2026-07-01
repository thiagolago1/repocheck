import responses

from repocheck.gitlab_client import GitLabClientError, fetch_repo_metadata


@responses.activate
def test_fetch_repo_metadata_returns_json_on_success():
    responses.add(
        responses.GET,
        "https://gitlab.com/api/v4/projects/gitlab-org%2Fgitlab",
        json={"star_count": 100, "created_at": "2023-05-01T00:00:00.000Z"},
        status=200,
    )

    metadata = fetch_repo_metadata("gitlab-org", "gitlab")

    assert metadata["star_count"] == 100
    assert metadata["created_at"] == "2023-05-01T00:00:00.000Z"


@responses.activate
def test_fetch_repo_metadata_raises_on_404():
    responses.add(
        responses.GET,
        "https://gitlab.com/api/v4/projects/someowner%2Fdoes-not-exist",
        json={"message": "404 Project Not Found"},
        status=404,
    )

    try:
        fetch_repo_metadata("someowner", "does-not-exist")
        assert False, "expected GitLabClientError to be raised"
    except GitLabClientError as exc:
        assert "someowner/does-not-exist" in str(exc)
