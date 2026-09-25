import app


def test_capture_privileges_skip_after_relaunch(monkeypatch):
    monkeypatch.setenv("AI_UD_PRIV_ESCALATED", "1")
    app.ensure_capture_privileges()


def test_linux_capture_privileges_relaunches_with_sudo(monkeypatch):
    monkeypatch.delenv("AI_UD_PRIV_ESCALATED", raising=False)
    monkeypatch.setattr(app.os, "name", "posix")
    monkeypatch.setattr(app.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(app.shutil, "which", lambda name: "/usr/bin/sudo" if name == "sudo" else None)

    calls = []

    def fake_execvpe(file, args, env):
        calls.append((file, args, env))

    monkeypatch.setattr(app.os, "execvpe", fake_execvpe)
    app.ensure_capture_privileges()

    assert calls
    file, args, env = calls[0]
    assert file == "/usr/bin/sudo"
    assert args[:2] == ["/usr/bin/sudo", "-E"]
    assert args[2] == app.sys.executable
    assert args[3].endswith("app.py")
    assert env["AI_UD_PRIV_ESCALATED"] == "1"


def test_linux_capture_privileges_errors_without_sudo(monkeypatch):
    monkeypatch.delenv("AI_UD_PRIV_ESCALATED", raising=False)
    monkeypatch.setattr(app.os, "name", "posix")
    monkeypatch.setattr(app.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(app.shutil, "which", lambda name: None)

    try:
        app.ensure_capture_privileges()
    except RuntimeError as exc:
        assert "sudo was not found" in str(exc)
    else:
        raise AssertionError("Expected a sudo error")
