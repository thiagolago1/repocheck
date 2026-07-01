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
