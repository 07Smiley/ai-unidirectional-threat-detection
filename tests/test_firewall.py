from src.response.firewall import FirewallActionError, HostFirewall


def test_validate_ip():
    assert HostFirewall._validate_ip("192.168.1.20") == "192.168.1.20"
    assert HostFirewall._validate_ip("2001:db8::1") == "2001:db8::1"


def test_validate_ip_rejects_invalid():
    try:
        HostFirewall._validate_ip("not-an-ip")
    except FirewallActionError:
        return
    raise AssertionError("invalid IP should be rejected")


def test_linux_command_uses_argument_list(monkeypatch):
    firewall = HostFirewall()
    monkeypatch.setattr("src.response.firewall.platform.system", lambda: "Linux")
    monkeypatch.setattr("src.response.firewall.shutil.which", lambda name: "/usr/sbin/iptables")
    command = firewall._command("192.0.2.10", "block")
    assert command[:6] == ["iptables", "-I", "INPUT", "-s", "192.0.2.10", "-j"]
    assert "DROP" in command
    assert "AI-UTD" in command
