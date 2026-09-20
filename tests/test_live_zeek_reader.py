from pathlib import Path

from src.ingest.live_zeek_reader import LiveZeekReader


def write_log(path: Path, rows: list[str]) -> None:
    path.write_text(
        "#separator \\x09\n"
        "#fields ts\tid.orig_h\tid.resp_h\tproto\n"
        + "".join(row + "\n" for row in rows),
        encoding="utf-8",
    )


def test_reader_returns_only_new_records(tmp_path):
    path = tmp_path / "conn.log"
    write_log(path, ["1\t10.0.0.1\t10.0.0.2\ttcp"])

    reader = LiveZeekReader(path)
    first = reader.read_new()

    assert first is not None
    assert len(first) == 1
    assert first.iloc[0]["id.orig_h"] == "10.0.0.1"

    with path.open("a", encoding="utf-8") as file:
        file.write("2\t10.0.0.3\t10.0.0.4\tudp\n")

    second = reader.read_new()
    assert second is not None
    assert len(second) == 1
    assert second.iloc[0]["id.resp_h"] == "10.0.0.4"


def test_reader_can_start_at_end(tmp_path):
    path = tmp_path / "conn.log"
    write_log(path, ["1\t10.0.0.1\t10.0.0.2\ttcp"])

    reader = LiveZeekReader(path, start_at_end=True)
    assert reader.read_new() is None

    with path.open("a", encoding="utf-8") as file:
        file.write("2\t10.0.0.3\t10.0.0.4\ttcp\n")

    batch = reader.read_new()
    assert batch is not None
    assert len(batch) == 1


def test_reader_skips_zeek_metadata(tmp_path):
    path = tmp_path / "conn.log"
    write_log(path, ["1\t10.0.0.1\t10.0.0.2\ttcp"])

    reader = LiveZeekReader(path)
    batch = reader.read_new()

    assert batch is not None
    assert len(batch) == 1
