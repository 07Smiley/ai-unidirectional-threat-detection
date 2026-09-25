from unittest.mock import MagicMock, patch

from src.ingest.live_packet_capture import LivePacketCapture


def test_capture_requires_interface():
    try:
        LivePacketCapture("", lambda rows: None)
    except ValueError as exc:
        assert "interface" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


@patch("src.ingest.live_packet_capture.AsyncSniffer")
def test_capture_starts_and_stops(mock_sniffer):
    instance = MagicMock()
    instance.running = False
    mock_sniffer.return_value = instance

    received = []
    capture = LivePacketCapture("test0", received.append)

    capture.start()

    mock_sniffer.assert_called_once()
    kwargs = mock_sniffer.call_args.kwargs
    assert kwargs["iface"] == "test0"
    assert kwargs["store"] is False
    assert callable(kwargs["prn"])

    instance.running = True
    capture.stop()

    instance.stop.assert_called_once()
    assert capture.running is False


@patch("src.ingest.live_packet_capture.AsyncSniffer")
def test_capture_reports_permission_error(mock_sniffer):
    instance = MagicMock()
    mock_sniffer.return_value = instance
    instance.start.side_effect = PermissionError("Operation not permitted")

    capture = LivePacketCapture("wlan0", lambda rows: None)

    try:
        capture.start()
    except RuntimeError as exc:
        assert "permission" in str(exc).lower()
        assert "wlan0" in str(exc)
    else:
        raise AssertionError("Expected RuntimeError for capture permission failure")

    assert capture.running is False
    assert capture.error is not None
