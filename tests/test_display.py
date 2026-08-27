"""Tests for display filtering and truncation."""

from unittest import mock

from openports import display


def test_visible_keeps_real_process_named_system():
    entries = [{"port": 135, "name": "System"}]
    assert display._visible(entries) == entries


def test_visible_drops_rows_without_port_or_name():
    entries = [
        {"port": None, "name": None},
        {"port": 3000, "name": "node"},
    ]
    assert display._visible(entries) == [{"port": 3000, "name": "node"}]


def test_visible_keeps_port_without_name():
    entries = [{"port": 22, "name": None}]
    assert display._visible(entries) == entries


def test_cmdline_truncates_by_default():
    entry = {"cmdline": "x" * 100}
    out = display._cmdline(entry, verbose=False)
    assert len(out) <= display._CMDLINE_TRUNCATE
    assert out.endswith("…")


def test_cmdline_full_when_verbose():
    entry = {"cmdline": "x" * 100}
    assert display._cmdline(entry, verbose=True) == "x" * 100


def test_cmdline_short_not_truncated():
    entry = {"cmdline": "short"}
    assert display._cmdline(entry, verbose=False) == "short"


def test_cmdline_none_returns_empty():
    entry = {"cmdline": None}
    assert display._cmdline(entry, verbose=False) == ""


def test_render_empty_prints_message(capsys):
    display.render([])
    assert "No listening ports found." in capsys.readouterr().out


def test_render_drops_invisible_entries():
    """render() should only show visible entries."""
    entries = [
        {"port": None, "name": None},
        {"port": 3000, "name": "node", "proto": "TCP", "status": "LISTENING",
         "pid": 1234, "memory": "10MB", "cmdline": None},
    ]
    # Just ensure no crash; visible logic is tested above
    display.render(entries)


def test_render_plain_with_rich_disabled(monkeypatch, capsys):
    """_render_plain outputs a formatted table."""
    monkeypatch.setattr("openports.display.HAS_RICH", False)
    entries = [{
        "port": 8080, "name": "nginx", "proto": "TCP", "status": "LISTENING",
        "pid": 1234, "memory": "10.5MB", "cmdline": "nginx -g daemon off;"
    }]
    display.render(entries, verbose=True)
    output = capsys.readouterr().out
    assert "8080" in output
    assert "nginx" in output
    assert "LISTENING" in output
    assert "1234" in output


def test_render_plain_without_cmdline(monkeypatch, capsys):
    """_render_plain handles entries without cmdline."""
    monkeypatch.setattr("openports.display.HAS_RICH", False)
    entries = [{
        "port": 3000, "name": "node", "proto": "TCP", "status": "LISTENING",
        "pid": 5678, "memory": "50MB", "cmdline": None
    }]
    display.render(entries, verbose=False)
    output = capsys.readouterr().out
    assert "3000" in output
    assert "node" in output


def test_render_plain_truncates_cmdline(monkeypatch, capsys):
    """_render_plain truncates long cmdline in non-verbose mode."""
    monkeypatch.setattr("openports.display.HAS_RICH", False)
    long_cmd = "x" * 100
    entries = [{
        "port": 8080, "name": "proc", "proto": "TCP", "status": "LISTENING",
        "pid": 9999, "memory": "5MB", "cmdline": long_cmd
    }]
    display.render(entries, verbose=False)
    output = capsys.readouterr().out
    # Should contain truncated version with ellipsis
    assert "…" in output


def test_render_plain_header_present(monkeypatch, capsys):
    """_render_plain outputs a header row."""
    monkeypatch.setattr("openports.display.HAS_RICH", False)
    entries = [{
        "port": 80, "name": "nginx", "proto": "TCP", "status": "LISTENING",
        "pid": 1, "memory": "1MB", "cmdline": None
    }]
    display.render(entries)
    output = capsys.readouterr().out
    assert "Port" in output
    assert "Proto" in output
    assert "Process" in output
    assert "PID" in output


def test_render_rich_path(monkeypatch, capsys):
    """render() uses rich when available."""
    monkeypatch.setattr("openports.display.HAS_RICH", True)
    # Mock rich console to capture output
    fake_console = mock.MagicMock()
    monkeypatch.setattr("openports.display.Console", lambda: fake_console)

    entries = [{
        "port": 3000, "name": "node", "proto": "TCP", "status": "LISTENING",
        "pid": 1234, "memory": "10MB", "cmdline": "node server.js"
    }]
    display.render(entries, verbose=False)
    fake_console.print.assert_called_once()


def test_render_rich_dev_port_highlighted(monkeypatch, capsys):
    """DEV_PORTS are highlighted in bold green in rich rendering."""
    monkeypatch.setattr("openports.display.HAS_RICH", True)
    fake_table = mock.MagicMock()
    monkeypatch.setattr("openports.display.Table", mock.MagicMock(return_value=fake_table))
    fake_console = mock.MagicMock()
    monkeypatch.setattr("openports.display.Console", lambda: fake_console)

    entries = [{
        "port": 3000, "name": "node", "proto": "TCP", "status": "LISTENING",
        "pid": 1234, "memory": "10MB", "cmdline": None
    }]
    display.render(entries, verbose=False)

    # Check that add_row was called with the dev port highlighted
    call_args = fake_table.add_row.call_args
    port_text = call_args[0][0]
    assert "bold green" in port_text


def test_render_rich_non_dev_port_not_highlighted(monkeypatch, capsys):
    """Non-dev ports are shown as plain numbers."""
    monkeypatch.setattr("openports.display.HAS_RICH", True)
    fake_table = mock.MagicMock()
    monkeypatch.setattr("openports.display.Table", mock.MagicMock(return_value=fake_table))
    fake_console = mock.MagicMock()
    monkeypatch.setattr("openports.display.Console", lambda: fake_console)

    entries = [{
        "port": 22, "name": "sshd", "proto": "TCP", "status": "LISTENING",
        "pid": 1234, "memory": "5MB", "cmdline": None
    }]
    display.render(entries, verbose=False)

    call_args = fake_table.add_row.call_args
    port_text = call_args[0][0]
    assert port_text == "22"


def test_render_rich_unknown_name_shows_unknown(monkeypatch, capsys):
    """When name is None, 'Unknown' is shown."""
    monkeypatch.setattr("openports.display.HAS_RICH", True)
    fake_table = mock.MagicMock()
    monkeypatch.setattr("openports.display.Table", mock.MagicMock(return_value=fake_table))
    fake_console = mock.MagicMock()
    monkeypatch.setattr("openports.display.Console", lambda: fake_console)

    entries = [{
        "port": 80, "name": None, "proto": "TCP", "status": "LISTENING",
        "pid": 0, "memory": "N/A", "cmdline": None
    }]
    display.render(entries, verbose=False)

    call_args = fake_table.add_row.call_args
    process_name = call_args[0][2]
    assert process_name == "Unknown"


def test_dev_ports_frozenset_contents():
    """DEV_PORTS contains expected development server ports."""
    assert 3000 in display.DEV_PORTS
    assert 8080 in display.DEV_PORTS
    assert 5432 in display.DEV_PORTS
    assert 6379 in display.DEV_PORTS
    # Regular system ports not included
    assert 22 not in display.DEV_PORTS
    assert 443 not in display.DEV_PORTS
