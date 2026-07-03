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


def test_detects_bitbucket_https_url():
    location = detect_platform("https://bitbucket.org/atlassian/python-bitbucket")
    assert location.platform == "bitbucket"
    assert location.owner == "atlassian"
    assert location.repo == "python-bitbucket"


def test_detects_bitbucket_url_with_git_suffix():
    location = detect_platform("https://bitbucket.org/atlassian/python-bitbucket.git")
    assert location.platform == "bitbucket"
    assert location.owner == "atlassian"
    assert location.repo == "python-bitbucket"


def test_unknown_platform_for_self_hosted_url():
    location = detect_platform("https://git.example.com/team/project")
    assert location.platform == "unknown"
    assert location.owner is None
    assert location.repo is None
    assert location.url == "https://git.example.com/team/project"
