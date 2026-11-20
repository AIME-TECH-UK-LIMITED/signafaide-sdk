"""A count with its noun in the right number."""


def plural(n: int, one: str, many: str = "") -> str:
    """``1 record``, ``2 records``."""
    return f"{n} {one if n == 1 else many or one + 's'}"
