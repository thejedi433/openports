"""Tests for previously uncovered edge cases in scanner.py."""

from types import SimpleNamespace
from unittest import mock

import pytest

from openports.scanner import PortScanner, _format_status


LISTEN = "LISTEN"
ESTABLISHED = "ESTABLISHED"


def conn(port, pid, status=LISTEN, ctype=1, ip="0.0.0.0"):
    return SimpleNamespace(
        laddr=SimpleNamespace(ip=ip, port=port),
        raddr=None, pid=pid, status=status, type=ctype,
    )


def test_find_pids_by_port_handles_psutil_error(monkeypatch):
    """Test that find_pids_by_port falls back when psutil raises an error."""
    fake = mock.MagicMock()
    fake.Error = Exception
    fake.net_connections.side_effect = Exception("psutil error")
    
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", True)
    monkeypatch.setattr("openports.scanner.psutil", fake)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "Linux")
    monkeypatch.setattr("openports.scanner.subprocess.check_output", 
                       lambda *a, **k: b"")
    
    scanner = PortScanner()
    result = scanner.find_pids_by_port(80)
    # Should fall back to Unix method, which returns empty from empty lsof output
    assert isinstance(result, list)


def test_find_pids_unix_handles_non_int_tokens(monkeypatch):
    """Test _find_pids_unix skips non-integer tokens from lsof output."""
    lsof_output = b"1234\nnotanumber\n5678\n"
    
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "Linux")
    monkeypatch.setattr("openports.scanner.subprocess.check_output",
                       lambda *a, **k: lsof_output)
    
    scanner = PortScanner()
    result = scanner._find_pids_unix(80)
    assert result == [1234, 5678]


def test_list_windows_deduplicates_entries(monkeypatch):
    """Test _list_windows skips duplicate port/pid/state combinations."""
    netstat_output = (
        "  Proto  Local Address          Foreign Address        State    PID\n"
        "  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING   1234\n"
        "  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING   1234\n"  # duplicate
        "  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING   5678\n"
    )
    
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "Windows")
    monkeypatch.setattr("openports.scanner.subprocess.check_output",
                       lambda *a, **k: netstat_output.encode())
    monkeypatch.setattr("openports.scanner.PortScanner._process_info",
                       lambda self, pid: {"name": f"proc{pid}", "cmdline": None,
                                         "user": "test", "memory": "10MB", "threads": "4"})
    
    scanner = PortScanner()
    entries = scanner._list_windows(filter_port=80, search=None, show_all=False)
    
    # Should have 2 unique entries (1234 and 5678), not 3
    assert len(entries) == 2
    pids = [e["pid"] for e in entries]
    assert 1234 in pids
    assert 5678 in pids


def test_list_unix_skips_non_int_pid(monkeypatch):
    """Test _list_unix skips lines with non-integer PIDs."""
    lsof_output = b"""\
COMMAND  PID   USER   FD   TYPE  DEVICE  SIZE/OFF  NODE  NAME
python   1234  user   3u   IPv4  12345   0t0       TCP   *:80 (LISTEN)
python   badpid  user   3u   IPv4  12345   0t0       TCP   *:8080 (LISTEN)
"""
    
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "Linux")
    monkeypatch.setattr("openports.scanner.subprocess.check_output",
                       lambda *a, **k: lsof_output)
    
    scanner = PortScanner()
    entries = scanner._list_unix(filter_port=None, search=None, show_all=True)
    
    # Should only have the valid entry with pid 1234
    assert len(entries) == 1
    assert entries[0]["pid"] == 1234


def test_list_unix_skips_non_int_port(monkeypatch):
    """Test _list_unix skips lines with non-integer ports."""
    lsof_output = b"""\
COMMAND  PID   USER   FD   TYPE  DEVICE  SIZE/OFF  NODE  NAME
python   1234  user   3u   IPv4  12345   0t0       TCP   *:80 (LISTEN)
python   5678  user   3u   IPv4  12345   0t0       TCP   *:badport (LISTEN)
"""
    
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "Linux")
    monkeypatch.setattr("openports.scanner.subprocess.check_output",
                       lambda *a, **k: lsof_output)
    
    scanner = PortScanner()
    entries = scanner._list_unix(filter_port=None, search=None, show_all=True)
    
    # Should only have the valid entry with port 80
    assert len(entries) == 1
    assert entries[0]["port"] == 80


def test_list_unix_handles_proc_read_failure_with_search(monkeypatch, tmp_path):
    """Test _list_unix handles OSError when reading /proc/PID/cmdline."""
    lsof_output = b"""\
COMMAND  PID   USER   FD   TYPE  DEVICE  SIZE/OFF  NODE  NAME
python   1234  user   3u   IPv4  12345   0t0       TCP   *:80 (LISTEN)
"""
    
    # Create a fake /proc that will fail to read
    def mock_open(filename, *args, **kwargs):
        raise OSError("Permission denied")
    
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "Linux")
    monkeypatch.setattr("openports.scanner.subprocess.check_output",
                       lambda *a, **k: lsof_output)
    monkeypatch.setattr("builtins.open", mock_open)
    
    scanner = PortScanner()
    # With search, it tries to read /proc/PID/cmdline
    entries = scanner._list_unix(filter_port=None, search="python", show_all=True)
    
    # Should still return entries even if cmdline read fails
    assert len(entries) == 1
    assert entries[0]["pid"] == 1234


def test_format_status_without_psutil(monkeypatch):
    """Test _format_status returns str(status) when psutil is not available."""
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    
    result = _format_status(999)
    assert result == "999"
    
    result = _format_status("CUSTOM")
    assert result == "CUSTOM"
