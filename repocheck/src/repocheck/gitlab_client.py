from urllib.parse import quote

import requests

GITLAB_API_BASE = "https://gitlab.com/api/v4"


class GitLabClientError(Exception):
    pass


def fetch_repo_metadata(owner: str, repo: str, timeout: float = 10.0) -> dict:
    project_path = quote(f"{owner}/{repo}", safe="")
    url = f"{GITLAB_API_BASE}/projects/{project_path}"
    response = requests.get(url, timeout=timeout)
    if response.status_code == 404:
        raise GitLabClientError(f"project not found: {owner}/{repo}")
    response.raise_for_status()
    return response.json()
