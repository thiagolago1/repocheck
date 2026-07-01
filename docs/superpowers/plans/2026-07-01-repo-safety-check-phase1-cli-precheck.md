# Repo Safety Check — Fase 1: CLI + Pré-check via API — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Entregar um CLI Python (`repocheck <url>`) que identifica a plataforma de um repositório git a partir da URL e roda um pré-check de reputação via API pública (idade, estrelas, forks, tipo de dono, sinal de typosquatting), sem tocar em nenhum código do repositório-alvo.

**Architecture:** Pacote Python `repocheck` com módulos isolados por responsabilidade — detecção de plataforma a partir da URL, clientes HTTP finos para GitHub e GitLab, detecção de typosquatting por distância de string, um orquestrador (`precheck.py`) que combina tudo em um resultado estruturado, e uma CLI (`cli.py`) via Click que expõe isso como comando de terminal.

**Tech Stack:** Python >= 3.11, Click (CLI), Requests (HTTP), pytest + responses (testes, mockando toda chamada HTTP).

## Global Constraints

- Esta fase nunca clona, baixa ou executa qualquer conteúdo do repositório-alvo — só metadados via API pública.
- Toda chamada de rede tem timeout explícito (padrão 10s).
- Falha de API/rede nunca vira "seguro" silenciosamente — o resultado marca `reachable=False` e propaga o motivo.
- Plataformas desconhecidas/não suportadas não geram erro — o pré-check é pulado de forma explícita (`platform="unknown"`).
- Pacote vive em `repocheck/` na raiz do repositório (`agentes`), para deixar espaço para outros projetos no futuro.

---

## Task 1: Scaffolding do projeto + detecção de plataforma

**Files:**
- Create: `repocheck/pyproject.toml`
- Create: `repocheck/src/repocheck/__init__.py`
- Create: `repocheck/src/repocheck/platform.py`
- Test: `repocheck/tests/test_platform.py`

**Interfaces:**
- Produces: `repocheck.platform.RepoLocation` (dataclass com campos `platform: str`, `owner: str | None`, `repo: str | None`, `url: str`) e `repocheck.platform.detect_platform(url: str) -> RepoLocation`.

- [ ] **Step 1: Criar a estrutura de diretórios e o `pyproject.toml`**

Criar os diretórios:

```bash
mkdir -p repocheck/src/repocheck repocheck/tests
```

Criar `repocheck/pyproject.toml`:

```toml
[project]
name = "repocheck"
version = "0.1.0"
description = "Analisa repositórios git em busca de código malicioso antes de clonar/instalar localmente."
requires-python = ">=3.11"
dependencies = [
    "click>=8.1",
    "requests>=2.31",
]

[project.scripts]
repocheck = "repocheck.cli:main"

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "responses>=0.25",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/repocheck"]
```

Criar `repocheck/src/repocheck/__init__.py` (vazio):

```python
```

- [ ] **Step 2: Instalar o projeto em modo editável com dependências de dev**

```bash
cd repocheck && python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
```

Expected: instalação termina sem erro, com `click`, `requests`, `pytest` e `responses` instalados.

- [ ] **Step 3: Escrever o teste de detecção de plataforma (deve falhar)**

Criar `repocheck/tests/test_platform.py`:

```python
from repocheck.platform import detect_platform


def test_detects_github_https_url():
    location = detect_platform("https://github.com/anthropics/claude-code")
    assert location.platform == "github"
    assert location.owner == "anthropics"
    assert location.repo == "claude-code"
    assert location.url == "https://github.com/anthropics/claude-code"


def test_detects_github_url_with_git_suffix():
    location = detect_platform("https://github.com/anthropics/claude-code.git")
    assert location.platform == "github"
    assert location.owner == "anthropics"
    assert location.repo == "claude-code"


def test_detects_github_url_with_trailing_slash():
    location = detect_platform("https://github.com/anthropics/claude-code/")
    assert location.platform == "github"
    assert location.owner == "anthropics"
    assert location.repo == "claude-code"


def test_detects_gitlab_https_url():
    location = detect_platform("https://gitlab.com/gitlab-org/gitlab")
    assert location.platform == "gitlab"
    assert location.owner == "gitlab-org"
    assert location.repo == "gitlab"


def test_unknown_platform_for_self_hosted_url():
    location = detect_platform("https://git.example.com/team/project")
    assert location.platform == "unknown"
    assert location.owner is None
    assert location.repo is None
    assert location.url == "https://git.example.com/team/project"
```

- [ ] **Step 4: Rodar os testes e confirmar que falham**

```bash
cd repocheck && .venv/bin/pytest tests/test_platform.py -v
```

Expected: FAIL com `ModuleNotFoundError: No module named 'repocheck.platform'`.

- [ ] **Step 5: Implementar `detect_platform`**

Criar `repocheck/src/repocheck/platform.py`:

```python
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
```

- [ ] **Step 6: Rodar os testes e confirmar que passam**

```bash
cd repocheck && .venv/bin/pytest tests/test_platform.py -v
```

Expected: 5 passed.

- [ ] **Step 7: Commit**

```bash
git add repocheck/pyproject.toml repocheck/src/repocheck/__init__.py repocheck/src/repocheck/platform.py repocheck/tests/test_platform.py
git commit -m "feat(repocheck): add project scaffolding and URL platform detection"
```

---

## Task 2: Lista de nomes populares + detecção de typosquatting

**Files:**
- Create: `repocheck/src/repocheck/popular_names.py`
- Create: `repocheck/src/repocheck/typosquat.py`
- Test: `repocheck/tests/test_typosquat.py`

**Interfaces:**
- Consumes: nada de tasks anteriores.
- Produces: `repocheck.popular_names.POPULAR_REPO_NAMES` (`list[str]`), `repocheck.typosquat.levenshtein(a: str, b: str) -> int`, `repocheck.typosquat.find_typosquat_match(name: str, popular_names: list[str], max_distance: int = 2) -> str | None`.

- [ ] **Step 1: Escrever o teste de typosquatting (deve falhar)**

Criar `repocheck/tests/test_typosquat.py`:

```python
from repocheck.typosquat import find_typosquat_match, levenshtein


def test_levenshtein_identical_strings():
    assert levenshtein("react", "react") == 0


def test_levenshtein_one_substitution():
    assert levenshtein("react", "reAct".lower()) == 0
    assert levenshtein("react", "reasct") == 1


def test_levenshtein_empty_strings():
    assert levenshtein("", "") == 0
    assert levenshtein("abc", "") == 3
    assert levenshtein("", "abc") == 3


def test_finds_close_match_to_popular_name():
    match = find_typosquat_match("reacct", ["react", "vue", "django"])
    assert match == "react"


def test_exact_match_is_not_typosquat():
    match = find_typosquat_match("react", ["react", "vue", "django"])
    assert match is None


def test_unrelated_name_has_no_match():
    match = find_typosquat_match("my-cool-project", ["react", "vue", "django"])
    assert match is None


def test_respects_max_distance():
    match = find_typosquat_match("reactionwheel", ["react"], max_distance=2)
    assert match is None
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

```bash
cd repocheck && .venv/bin/pytest tests/test_typosquat.py -v
```

Expected: FAIL com `ModuleNotFoundError: No module named 'repocheck.typosquat'`.

- [ ] **Step 3: Implementar a lista de nomes populares**

Criar `repocheck/src/repocheck/popular_names.py`:

```python
POPULAR_REPO_NAMES = [
    "react", "vue", "angular", "django", "flask", "requests", "numpy",
    "pandas", "tensorflow", "pytorch", "express", "lodash", "axios",
    "webpack", "babel", "eslint", "jest", "kubernetes", "docker",
    "ansible", "terraform", "vscode", "electron", "next.js", "nuxt",
    "svelte", "rails", "laravel", "symfony", "spring-boot", "gin",
    "fastapi", "scikit-learn", "opencv", "ffmpeg", "nginx", "redis",
    "postgres", "mongodb", "elasticsearch", "kafka", "spark",
]
```

- [ ] **Step 4: Implementar `levenshtein` e `find_typosquat_match`**

Criar `repocheck/src/repocheck/typosquat.py`:

```python
def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current_row = [i]
        for j, char_b in enumerate(b, start=1):
            insert_cost = current_row[j - 1] + 1
            delete_cost = previous_row[j] + 1
            replace_cost = previous_row[j - 1] + (char_a != char_b)
            current_row.append(min(insert_cost, delete_cost, replace_cost))
        previous_row = current_row
    return previous_row[-1]


def find_typosquat_match(
    name: str, popular_names: list[str], max_distance: int = 2
) -> str | None:
    normalized = name.lower()
    for popular in popular_names:
        popular_lower = popular.lower()
        if normalized == popular_lower:
            return None
        distance = levenshtein(normalized, popular_lower)
        if 0 < distance <= max_distance:
            return popular
    return None
```

- [ ] **Step 5: Rodar os testes e confirmar que passam**

```bash
cd repocheck && .venv/bin/pytest tests/test_typosquat.py -v
```

Expected: 7 passed.

- [ ] **Step 6: Commit**

```bash
git add repocheck/src/repocheck/popular_names.py repocheck/src/repocheck/typosquat.py repocheck/tests/test_typosquat.py
git commit -m "feat(repocheck): add typosquatting detection via Levenshtein distance"
```

---

## Task 3: Cliente da API do GitHub

**Files:**
- Create: `repocheck/src/repocheck/github_client.py`
- Test: `repocheck/tests/test_github_client.py`

**Interfaces:**
- Consumes: nada de tasks anteriores.
- Produces: `repocheck.github_client.GitHubClientError` (exception), `repocheck.github_client.fetch_repo_metadata(owner: str, repo: str, timeout: float = 10.0) -> dict`.

- [ ] **Step 1: Escrever o teste do cliente GitHub (deve falhar)**

Criar `repocheck/tests/test_github_client.py`:

```python
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
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

```bash
cd repocheck && .venv/bin/pytest tests/test_github_client.py -v
```

Expected: FAIL com `ModuleNotFoundError: No module named 'repocheck.github_client'`.

- [ ] **Step 3: Implementar `fetch_repo_metadata`**

Criar `repocheck/src/repocheck/github_client.py`:

```python
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
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

```bash
cd repocheck && .venv/bin/pytest tests/test_github_client.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add repocheck/src/repocheck/github_client.py repocheck/tests/test_github_client.py
git commit -m "feat(repocheck): add GitHub API client for repo metadata"
```

---

## Task 4: Cliente da API do GitLab

**Files:**
- Create: `repocheck/src/repocheck/gitlab_client.py`
- Test: `repocheck/tests/test_gitlab_client.py`

**Interfaces:**
- Consumes: nada de tasks anteriores.
- Produces: `repocheck.gitlab_client.GitLabClientError` (exception), `repocheck.gitlab_client.fetch_repo_metadata(owner: str, repo: str, timeout: float = 10.0) -> dict`.

- [ ] **Step 1: Escrever o teste do cliente GitLab (deve falhar)**

Criar `repocheck/tests/test_gitlab_client.py`:

```python
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
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

```bash
cd repocheck && .venv/bin/pytest tests/test_gitlab_client.py -v
```

Expected: FAIL com `ModuleNotFoundError: No module named 'repocheck.gitlab_client'`.

- [ ] **Step 3: Implementar `fetch_repo_metadata`**

Criar `repocheck/src/repocheck/gitlab_client.py`:

```python
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
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

```bash
cd repocheck && .venv/bin/pytest tests/test_gitlab_client.py -v
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add repocheck/src/repocheck/gitlab_client.py repocheck/tests/test_gitlab_client.py
git commit -m "feat(repocheck): add GitLab API client for repo metadata"
```

---

## Task 5: Orquestração do pré-check

**Files:**
- Create: `repocheck/src/repocheck/precheck.py`
- Test: `repocheck/tests/test_precheck.py`

**Interfaces:**
- Consumes: `repocheck.platform.RepoLocation`, `repocheck.platform.detect_platform` (Task 1); `repocheck.popular_names.POPULAR_REPO_NAMES`, `repocheck.typosquat.find_typosquat_match` (Task 2); `repocheck.github_client.fetch_repo_metadata`, `repocheck.github_client.GitHubClientError` (Task 3); `repocheck.gitlab_client.fetch_repo_metadata`, `repocheck.gitlab_client.GitLabClientError` (Task 4).
- Produces: `repocheck.precheck.PrecheckResult` (dataclass com campos `location: RepoLocation`, `reachable: bool`, `age_days: int | None`, `stars: int | None`, `forks: int | None`, `owner_type: str | None`, `possible_typosquat: bool`, `typosquat_match: str | None`, `error: str | None`, `raw: dict`), `repocheck.precheck.run_precheck(url: str) -> PrecheckResult`.

- [ ] **Step 1: Escrever o teste de orquestração do pré-check (deve falhar)**

Criar `repocheck/tests/test_precheck.py`:

```python
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
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

```bash
cd repocheck && .venv/bin/pytest tests/test_precheck.py -v
```

Expected: FAIL com `ModuleNotFoundError: No module named 'repocheck.precheck'`.

- [ ] **Step 3: Implementar `run_precheck`**

Criar `repocheck/src/repocheck/precheck.py`:

```python
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

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


def _age_in_days(created_at_iso: str) -> int:
    created = datetime.fromisoformat(created_at_iso.replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    return (now - created).days


def run_precheck(url: str) -> PrecheckResult:
    location = detect_platform(url)

    typosquat_match = None
    if location.repo:
        typosquat_match = find_typosquat_match(location.repo, POPULAR_REPO_NAMES)

    if location.platform == "github" and location.owner and location.repo:
        try:
            raw = github_client.fetch_repo_metadata(location.owner, location.repo)
        except github_client.GitHubClientError as exc:
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
            age_days=_age_in_days(raw["created_at"]),
            stars=raw.get("stargazers_count"),
            forks=raw.get("forks_count"),
            owner_type=raw.get("owner", {}).get("type"),
            possible_typosquat=typosquat_match is not None,
            typosquat_match=typosquat_match,
            raw=raw,
        )

    if location.platform == "gitlab" and location.owner and location.repo:
        try:
            raw = gitlab_client.fetch_repo_metadata(location.owner, location.repo)
        except gitlab_client.GitLabClientError as exc:
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
            age_days=_age_in_days(raw["created_at"]),
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
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

```bash
cd repocheck && .venv/bin/pytest tests/test_precheck.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add repocheck/src/repocheck/precheck.py repocheck/tests/test_precheck.py
git commit -m "feat(repocheck): orchestrate platform detection, API clients, and typosquat check into a precheck result"
```

---

## Task 6: CLI

**Files:**
- Create: `repocheck/src/repocheck/cli.py`
- Test: `repocheck/tests/test_cli.py`

**Interfaces:**
- Consumes: `repocheck.precheck.run_precheck`, `repocheck.precheck.PrecheckResult` (Task 5).
- Produces: comando de terminal `repocheck <url>` (entry point `repocheck.cli:main`), suportando a flag `--json`.

- [ ] **Step 1: Escrever o teste da CLI (deve falhar)**

Criar `repocheck/tests/test_cli.py`:

```python
import json
from unittest.mock import patch

from click.testing import CliRunner

from repocheck.cli import main
from repocheck.platform import RepoLocation
from repocheck.precheck import PrecheckResult


def _fake_result() -> PrecheckResult:
    return PrecheckResult(
        location=RepoLocation(
            platform="github", owner="anthropics", repo="claude-code",
            url="https://github.com/anthropics/claude-code",
        ),
        reachable=True,
        age_days=500,
        stars=1000,
        forks=50,
        owner_type="Organization",
        possible_typosquat=False,
        typosquat_match=None,
        raw={"stargazers_count": 1000},
    )


def test_cli_human_readable_output():
    runner = CliRunner()
    with patch("repocheck.cli.run_precheck", return_value=_fake_result()):
        result = runner.invoke(main, ["https://github.com/anthropics/claude-code"])

    assert result.exit_code == 0
    assert "Platform: github" in result.output
    assert "Stars: 1000" in result.output


def test_cli_json_output():
    runner = CliRunner()
    with patch("repocheck.cli.run_precheck", return_value=_fake_result()):
        result = runner.invoke(
            main, ["https://github.com/anthropics/claude-code", "--json"]
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["location"]["platform"] == "github"
    assert payload["stars"] == 1000


def test_cli_warns_on_typosquat():
    typosquat_result = _fake_result()
    typosquat_result.possible_typosquat = True
    typosquat_result.typosquat_match = "react"

    runner = CliRunner()
    with patch("repocheck.cli.run_precheck", return_value=typosquat_result):
        result = runner.invoke(main, ["https://github.com/someone/reacct"])

    assert "WARNING" in result.output
    assert "react" in result.output
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

```bash
cd repocheck && .venv/bin/pytest tests/test_cli.py -v
```

Expected: FAIL com `ModuleNotFoundError: No module named 'repocheck.cli'`.

- [ ] **Step 3: Implementar a CLI**

Criar `repocheck/src/repocheck/cli.py`:

```python
import json
from dataclasses import asdict

import click

from repocheck.precheck import run_precheck


@click.command()
@click.argument("url")
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Output raw JSON instead of a human-readable summary.",
)
def main(url: str, as_json: bool) -> None:
    result = run_precheck(url)

    if as_json:
        click.echo(json.dumps(asdict(result), indent=2, default=str))
        return

    click.echo(f"Platform: {result.location.platform}")
    click.echo(f"Owner/repo: {result.location.owner}/{result.location.repo}")

    if not result.reachable:
        click.echo(f"Reachable: no ({result.error})")
    else:
        click.echo("Reachable: yes")
        click.echo(f"Age (days): {result.age_days}")
        click.echo(f"Stars: {result.stars}")
        click.echo(f"Forks: {result.forks}")
        click.echo(f"Owner type: {result.owner_type}")

    if result.possible_typosquat:
        click.echo(
            f"WARNING: name is suspiciously close to popular repo '{result.typosquat_match}'"
        )


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

```bash
cd repocheck && .venv/bin/pytest tests/test_cli.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Rodar a suíte completa de testes da fase 1**

```bash
cd repocheck && .venv/bin/pytest -v
```

Expected: todos os testes das Tasks 1-6 passam (25 passed).

- [ ] **Step 6: Testar manualmente o CLI de ponta a ponta**

```bash
cd repocheck && .venv/bin/repocheck https://github.com/anthropics/claude-code
```

Expected: saída mostrando `Platform: github`, dados de estrelas/forks/idade reais (chamada real à API pública do GitHub, sem autenticação).

- [ ] **Step 7: Commit**

```bash
git add repocheck/src/repocheck/cli.py repocheck/tests/test_cli.py
git commit -m "feat(repocheck): add CLI entry point for URL precheck"
```

---

## Escopo desta fase — o que fica para depois

- Nenhuma VM é criada ainda (fases 2+). O CLI desta fase só roda o pré-check via API e imprime o resultado.
- Veredito final (SEGURO/SUSPEITO/MALICIOSO) não existe ainda — isso é montado na fase 5, combinando esta saída com os achados das fases 2-4.
- Suporte a Bitbucket e outras plataformas fica como extensão natural do padrão em `platform.py`/clientes, mas não é escopo desta fase (spec cobre GitHub/GitLab como plataformas de referência; "unknown" já é tratado de forma segura).
