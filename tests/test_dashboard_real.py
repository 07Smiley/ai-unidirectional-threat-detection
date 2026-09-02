"""Tests for the real-data-backed Flask dashboard.

These tests verify that the dashboard API endpoints return data derived from
real Zeek logs and the rule-based detection pipeline, NOT from SAMPLE_LOGS.
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure the project root is importable
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# Fixture: a minimal Zeek conn.log for testing
# ---------------------------------------------------------------------------

MINIMAL_CONN_LOG = """\
#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tconn
#open\t2026-09-02-00-00-00
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\tip_proto
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]\tcount
1747147647.668533\tCeyl8h2fIQgW9E6dd6\t192.168.1.8\t52917\t192.0.78.212\t80\ttcp\thttp\t0.098478\t71\t377\tSF\tT\tF\t0\tShADadFf\t6\t335\t4\t549\t-\t6
1747147654.275660\tCHaOzk4Nigv8kcVRwl\t192.168.1.8\t52918\t192.0.78.150\t80\ttcp\thttp\t0.100107\t73\t377\tSF\tT\tF\t0\tShADadFf\t6\t337\t4\t549\t-\t6
1747147700.000000\tCtest1234567890ab\t10.0.0.5\t12345\t10.0.0.1\t443\ttcp\tssl\t1.500000\t500\t1000\tSF\tT\tF\t0\tShADadFf\t10\t700\t8\t1200\t-\t6
#close\t2026-09-02-00-00-01
"""


@pytest.fixture
def zeek_dir(tmp_path):
    """Create a temporary directory with a minimal Zeek conn.log."""
    conn_log = tmp_path / "conn.log"
    conn_log.write_text(MINIMAL_CONN_LOG)
    return tmp_path


@pytest.fixture
def app_client(zeek_dir):
    """Create a Flask test client pointed at the temporary Zeek directory."""
    # Patch ZEEK_LOG_DIR to point at our temp dir
    with patch.dict(os.environ, {"ZEEK_LOG_DIR": str(zeek_dir)}):
        # Re-import to pick up the patched environment
        import importlib
        import dashboard as dash_module
        importlib.reload(dash_module)

        # Force the data provider to refresh with our test data
        dash_module._data_provider = dash_module.RealDataProvider()
        dash_module._data_provider.refresh()

        dash_module.app.config["TESTING"] = True
        with dash_module.app.test_client() as client:
            yield client, dash_module


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAPIStats:
    def test_stats_returns_real_flow_count(self, app_client):
        client, dash = app_client
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.get_json()
        # We have 3 flows in our minimal conn.log
        assert data["flows_analyzed"] == 3
        assert data["model"] == "Rule-Based Engine"
        # No fake values like FLOWS_ANALYZED = 223082
        assert data["flows_analyzed"] != 223082

    def test_stats_has_no_xgboost(self, app_client):
        client, dash = app_client
        resp = client.get("/api/stats")
        data = resp.get_json()
        assert data["model"] != "XGBoost"
        assert data["model"] == "Rule-Based Engine"


class TestAPIGroups:
    def test_groups_returns_real_sources(self, app_client):
        client, dash = app_client
        resp = client.get("/api/groups")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        # We should have 2 distinct source IPs: 192.168.1.8 and 10.0.0.5
        src_ips = {g["src_ip"] for g in data}
        assert "192.168.1.8" in src_ips
        assert "10.0.0.5" in src_ips

    def test_groups_do_not_contain_sample_ips(self, app_client):
        client, dash = app_client
        resp = client.get("/api/groups")
        data = resp.get_json()
        src_ips = {g["src_ip"] for g in data}
        # These are the old SAMPLE_LOGS IPs — must NOT appear
        assert "203.0.113.44" not in src_ips
        assert "198.51.100.9" not in src_ips
        assert "203.0.113.51" not in src_ips
        assert "192.0.2.77" not in src_ips
        assert "198.51.100.14" not in src_ips

    def test_group_has_required_fields(self, app_client):
        client, dash = app_client
        resp = client.get("/api/groups")
        data = resp.get_json()
        for g in data:
            assert "group_id" in g
            assert "src_ip" in g
            assert "request_count" in g
            assert "label" in g
            assert "last_seen" in g


class TestAPIGroupLogs:
    def test_logs_returns_flows_for_known_source(self, app_client):
        client, dash = app_client
        resp = client.get("/api/groups/192.168.1.8/logs")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert len(data) == 2  # Two flows from 192.168.1.8
        for log in data:
            assert log["src_ip"] == "192.168.1.8"

    def test_logs_returns_404_for_unknown_source(self, app_client):
        client, dash = app_client
        resp = client.get("/api/groups/99.99.99.99/logs")
        assert resp.status_code == 404

    def test_log_entries_have_required_fields(self, app_client):
        client, dash = app_client
        resp = client.get("/api/groups/192.168.1.8/logs")
        data = resp.get_json()
        for log in data:
            assert "id" in log
            assert "src_ip" in log
            assert "dst_ip" in log
            assert "timestamp" in log
            assert "label" in log
            assert "protocol" in log
            assert "packets_per_sec" in log


class TestAPIGroupAnalysis:
    def test_analysis_returns_verdict(self, app_client):
        client, dash = app_client
        resp = client.get("/api/groups/192.168.1.8/analysis")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "lead" in data
        assert "label" in data

    def test_analysis_returns_404_for_unknown_source(self, app_client):
        client, dash = app_client
        resp = client.get("/api/groups/99.99.99.99/analysis")
        assert resp.status_code == 404


class TestAPIChatHistory:
    def test_chat_history_returns_empty_for_new_source(self, app_client):
        client, dash = app_client
        resp = client.get("/api/groups/192.168.1.8/chat/history")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)

    def test_chat_history_returns_404_for_unknown_source(self, app_client):
        client, dash = app_client
        resp = client.get("/api/groups/99.99.99.99/chat/history")
        assert resp.status_code == 404


class TestHomePage:
    def test_home_renders(self, app_client):
        client, dash = app_client
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"Sentry" in resp.data


class TestNoSampleData:
    """Verify that SAMPLE_LOGS no longer exists or is not used."""

    def test_no_sample_logs_variable(self, app_client):
        client, dash = app_client
        assert not hasattr(dash, "SAMPLE_LOGS"), "SAMPLE_LOGS should be removed"

    def test_no_fake_model_name(self, app_client):
        client, dash = app_client
        assert not hasattr(dash, "MODEL_NAME"), "MODEL_NAME constant should be removed"

    def test_no_fake_flows_analyzed(self, app_client):
        client, dash = app_client
        assert not hasattr(dash, "FLOWS_ANALYZED"), "FLOWS_ANALYZED constant should be removed"


class TestErrorHandling:
    def test_stats_with_no_zeek_dir(self):
        """When no Zeek logs exist anywhere, the API should return gracefully."""
        with patch("dashboard._find_zeek_log_dir", return_value=None):
            import importlib
            import dashboard as dash_module
            provider = dash_module.RealDataProvider()
            provider.refresh()
            dash_module._data_provider = provider

            dash_module.app.config["TESTING"] = True
            with dash_module.app.test_client() as client:
                resp = client.get("/api/stats")
                assert resp.status_code == 200
                data = resp.get_json()
                assert "error" in data or data["flows_analyzed"] == 0
