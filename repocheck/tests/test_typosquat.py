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
