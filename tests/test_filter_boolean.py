def calculate_hidden(severity: int, minimum: int, query: str, haystack: str) -> bool:
    severity_hidden = severity < minimum
    text_hidden = bool(query) and query not in haystack
    return bool(severity_hidden or text_hidden)


def test_empty_query_returns_boolean_false():
    result = calculate_hidden(40, 0, "", "sample finding")
    assert result is False
    assert isinstance(result, bool)


def test_nonmatching_query_returns_boolean_true():
    result = calculate_hidden(40, 0, "missing", "sample finding")
    assert result is True
    assert isinstance(result, bool)


def test_severity_filter_returns_boolean_true():
    result = calculate_hidden(10, 30, "", "sample finding")
    assert result is True
    assert isinstance(result, bool)
