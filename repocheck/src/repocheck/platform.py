import re
from dataclasses import dataclass


@dataclass
class RepoLocation:
    platform: str
    owner: str | None
    repo: str | None
    url: str


_PATTERNS = {
    "github": re.compile(r"^https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(\.git)?/?$"),
    "gitlab": re.compile(r"^https?://gitlab\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(\.git)?/?$"),
    "bitbucket": re.compile(
        r"^https?://bitbucket\.org/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(\.git)?/?$"
    ),
}


def detect_platform(url: str) -> RepoLocation:
    stripped = url.strip()
    for platform_name, pattern in _PATTERNS.items():
        match = pattern.match(stripped)
        if match:
            return RepoLocation(
                platform=platform_name,
                owner=match.group("owner"),
                repo=match.group("repo"),
                url=url,
            )
    return RepoLocation(platform="unknown", owner=None, repo=None, url=url)
