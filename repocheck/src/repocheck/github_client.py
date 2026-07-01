import requests

GITHUB_API_BASE = "https://api.github.com"


class GitHubClientError(Exception):
    pass


def fetch_repo_metadata(owner: str, repo: str, timeout: float = 10.0) -> dict:
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
    response = requests.get(
        url,
        timeout=timeout,
        headers={"Accept": "application/vnd.github+json"},
    )
    if response.status_code == 404:
        raise GitHubClientError(f"repository not found: {owner}/{repo}")
    response.raise_for_status()
    return response.json()
