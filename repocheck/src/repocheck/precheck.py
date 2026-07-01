from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import requests

from repocheck import github_client, gitlab_client
from repocheck.platform import RepoLocation, detect_platform
from repocheck.popular_names import POPULAR_REPO_NAMES
from repocheck.typosquat import find_typosquat_match


@dataclass
class PrecheckResult:
    location: RepoLocation
    reachable: bool
    age_days: int | None = None
    stars: int | None = None
    forks: int | None = None
    owner_type: str | None = None
    possible_typosquat: bool = False
    typosquat_match: str | None = None
    error: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


def _age_in_days(created_at_iso: str | None) -> int | None:
    if created_at_iso is None:
        return None
    try:
        created = datetime.fromisoformat(created_at_iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    now = datetime.now(timezone.utc)
    return (now - created).days


def _extract_repo_name(location: RepoLocation) -> str | None:
    """Best-effort repo name for typosquat matching.

    detect_platform only populates `repo` for recognized platforms
    (github/gitlab); for "unknown" hosts it deliberately leaves owner/repo
    as None (see repocheck.platform). Typosquatting checks should still run
    against self-hosted/unknown git URLs, so fall back to parsing the URL
    path when the platform detector didn't give us a repo name.

    This has been through several iterations that each tried to be clever
    about recognizing branch/tree suffixes, nested GitLab subgroups, etc.
    Every one of those was eventually shown to be ambiguous: a marker word
    like "wiki" or "issues" can legitimately be either a route suffix or
    the literal repo name, and there's no way to tell without host-specific
    routing knowledge this generic tool doesn't have.

    So: only handle the one URL shape that is genuinely unambiguous across
    every git hosting convention -- a bare `owner/repo` path with nothing
    else in it. Anything else (nested subgroups, tree/blob suffixes, or any
    other extra path segments) returns None rather than guessing. This is a
    best-effort/advisory signal only; skipping the typosquat check for
    ambiguous URLs is an acceptable limitation, not a bug to keep patching.
    """
    if location.repo:
        return location.repo
    path = urlsplit(location.url.strip()).path
    segments = [segment for segment in path.split("/") if segment]
    if len(segments) != 2:
        return None
    repo = segments[1]
    if repo.endswith(".git"):
        repo = repo[: -len(".git")]
    return repo or None


def run_precheck(url: str) -> PrecheckResult:
    location = detect_platform(url)

    repo_name = _extract_repo_name(location)
    typosquat_match = None
    if repo_name:
        typosquat_match = find_typosquat_match(repo_name, POPULAR_REPO_NAMES)

    if location.platform == "github" and location.owner and location.repo:
        try:
            raw = github_client.fetch_repo_metadata(location.owner, location.repo)
        except (github_client.GitHubClientError, requests.exceptions.RequestException) as exc:
            return PrecheckResult(
                location=location,
                reachable=False,
                error=str(exc),
                possible_typosquat=typosquat_match is not None,
                typosquat_match=typosquat_match,
            )
        return PrecheckResult(
            location=location,
            reachable=True,
            age_days=_age_in_days(raw.get("created_at")),
            stars=raw.get("stargazers_count"),
            forks=raw.get("forks_count"),
            owner_type=(raw.get("owner") or {}).get("type"),
            possible_typosquat=typosquat_match is not None,
            typosquat_match=typosquat_match,
            raw=raw,
        )

    if location.platform == "gitlab" and location.owner and location.repo:
        try:
            raw = gitlab_client.fetch_repo_metadata(location.owner, location.repo)
        except (gitlab_client.GitLabClientError, requests.exceptions.RequestException) as exc:
            return PrecheckResult(
                location=location,
                reachable=False,
                error=str(exc),
                possible_typosquat=typosquat_match is not None,
                typosquat_match=typosquat_match,
            )
        return PrecheckResult(
            location=location,
            reachable=True,
            age_days=_age_in_days(raw.get("created_at")),
            stars=raw.get("star_count"),
            forks=raw.get("forks_count"),
            owner_type=raw.get("namespace", {}).get("kind"),
            possible_typosquat=typosquat_match is not None,
            typosquat_match=typosquat_match,
            raw=raw,
        )

    return PrecheckResult(
        location=location,
        reachable=False,
        error="unknown or unsupported platform, skipping API precheck",
        possible_typosquat=typosquat_match is not None,
        typosquat_match=typosquat_match,
    )
