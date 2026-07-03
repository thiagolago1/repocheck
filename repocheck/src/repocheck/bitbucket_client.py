import requests

BITBUCKET_API_BASE = "https://api.bitbucket.org/2.0"


class BitbucketClientError(Exception):
    pass


def fetch_repo_metadata(owner: str, repo: str, timeout: float = 10.0) -> dict:
    url = f"{BITBUCKET_API_BASE}/repositories/{owner}/{repo}"
    response = requests.get(url, timeout=timeout)
    if response.status_code == 404:
        raise BitbucketClientError(f"repository not found: {owner}/{repo}")
    response.raise_for_status()
    return response.json()
