from src.detection.alert_dedup import AlertDeduplicator


def test_duplicate_alert_is_suppressed_within_window():
    dedup = AlertDeduplicator(window_seconds=30)
    event = {
        "type": "possible_scan",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 443,
    }

    assert dedup.is_duplicate(event, now=100.0) is False
    assert dedup.is_duplicate(event, now=110.0) is True
    assert dedup.is_duplicate(event, now=131.0) is False


def test_different_alert_signatures_are_not_duplicates():
    dedup = AlertDeduplicator(window_seconds=30)

    first = {
        "type": "possible_scan",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 443,
    }
    second = {
        "type": "possible_scan",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.3",
        "dst_port": 443,
    }

    assert dedup.is_duplicate(first, now=100.0) is False
    assert dedup.is_duplicate(second, now=101.0) is False


def test_clear_allows_same_alert_again():
    dedup = AlertDeduplicator(window_seconds=30)
    event = {"type": "possible_dga", "src_ip": "10.0.0.1", "domain": "x.example"}

    assert dedup.is_duplicate(event, now=100.0) is False
    assert dedup.is_duplicate(event, now=101.0) is True
    dedup.clear()
    assert dedup.is_duplicate(event, now=102.0) is False
