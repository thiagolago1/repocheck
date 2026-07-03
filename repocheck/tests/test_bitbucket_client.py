import responses

from repocheck.bitbucket_client import BitbucketClientError, fetch_repo_metadata


@responses.activate
def test_fetch_repo_metadata_returns_json_on_success():
    responses.add(
        responses.GET,
        "https://api.bitbucket.org/2.0/repositories/atlassian/python-bitbucket",
        json={
            "created_on": "2013-05-01T00:00:00.000000+00:00",
            "owner": {"type": "team"},
        },
        status=200,
    )

    metadata = fetch_repo_metadata("atlassian", "python-bitbucket")

    assert metadata["created_on"] == "2013-05-01T00:00:00.000000+00:00"
    assert metadata["owner"]["type"] == "team"


@responses.activate
def test_fetch_repo_metadata_raises_on_404():
    responses.add(
        responses.GET,
        "https://api.bitbucket.org/2.0/repositories/someowner/does-not-exist",
        json={"error": {"message": "Repository not found"}},
        status=404,
    )

    try:
        fetch_repo_metadata("someowner", "does-not-exist")
        assert False, "expected BitbucketClientError to be raised"
    except BitbucketClientError as exc:
        assert "someowner/does-not-exist" in str(exc)
