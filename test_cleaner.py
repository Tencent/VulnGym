from cleaner import clean_trace


def test_remove_duplicates():
    trace = [
        {"file": "a.py", "line": 10, "code": "x=1"},
        {"file": "a.py", "line": 10, "code": "x=1"},
    ]
    result = clean_trace(trace, 1, 20)
    assert len(result["trace"]) == 1
    assert result["stats"]["duplicates_removed"] == 1


def test_out_of_order():
    trace = [
        {"file": "a.py", "line": 5, "code": "x=1"},
    ]
    result = clean_trace(trace, 10, 20)
    assert result["stats"]["out_of_order_detected"] == 1