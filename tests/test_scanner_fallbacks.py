"""Tests for fallback code paths in PortScanner (no psutil, subprocess-based)."""

from types import SimpleNamespace
from unittest import mock

import pytest

from openports.scanner import PortScanner


LISTEN = "LISTEN"
ESTABLISHED = "ESTABLISHED"


def conn(port, pid, status=LISTEN, ctype=1, ip="0.0.0.0"):
    return SimpleNamespace(
        laddr=SimpleNamespace(ip=ip, port=port),
        raddr=None, pid=pid, status=status, type=ctype,
    )


@pytest.fixture
def scanner_with_psutil(monkeypatch):
    """Create a PortScanner with psutil mocked."""
    fake = mock.MagicMock()
    fake.CONN_LISTEN = LISTEN
    fake.CONN_ESTABLISHED = ESTABLISHED
    fake.CONN_NONE = "NONE"
    fake.Error = Exception
    fake.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
    fake.AccessDenied = type("AccessDenied", (Exception,), {})
    fake.TimeoutExpired = type("TimeoutExpired", (Exception,), {})

    def make_proc(pid):
        proc = mock.MagicMock()
        proc.oneshot.return_value.__enter__ = lambda *a: None
        proc.oneshot.return_value.__exit__ = lambda *a: False
        proc.name.return_value = "proc{}".format(pid)
        proc.cmdline.return_value = ["proc{}".format(pid), "--serve"]
        proc.username.return_value = "alice"
        proc.memory_info.return_value = SimpleNamespace(rss=10 * 1024 * 1024)
        proc.num_threads.return_value = 4
        return proc

    fake.Process.side_effect = make_proc
    fake.net_connections.return_value = []
    
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", True)
    monkeypatch.setattr("openports.scanner.psutil", fake)
    
    return PortScanner(), fake


# ─────────────────────────────────────────────────────────────────────────────
# _find_pids_windows
# ─────────────────────────────────────────────────────────────────────────────


def test_find_pids_windows_parses_netstat(monkeypatch):
    """_find_pids_windows parses netstat output correctly."""
    netstat_output = (
        "  Proto  Local Address          Foreign Address        State    PID\n"
        "  TCP    0.0.0.0:80             0.0.0.0:0              LISTEN   1234\n"
        "  TCP    0.0.0.0:80             0.0.0.0:0              LISTEN   5678\n"
        "  TCP    0.0.0.0:443            0.0.0.0:0              LISTEN   9999\n"
    )
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        lambda *a, **k: netstat_output.encode(),
    )

    scanner = PortScanner()
    assert scanner._find_pids_windows(80) == [1234, 5678]
    assert scanner._find_pids_windows(443) == [9999]
    assert scanner._find_pids_windows(9999) == []


def test_find_pids_windows_handles_bad_pid(monkeypatch):
    """_find_pids_windows ignores lines with non-integer PIDs."""
    netstat_output = (
        "  TCP    0.0.0.0:80   0.0.0.0:0   LISTEN   1234\n"
        "  TCP    0.0.0.0:80   0.0.0.0:0   LISTEN   notapid\n"
    )
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        lambda *a, **k: netstat_output.encode(),
    )

    scanner = PortScanner()
    assert scanner._find_pids_windows(80) == [1234]


def test_find_pids_windows_handles_subprocess_failure(monkeypatch):
    """_find_pids_windows returns [] when netstat fails."""
    import subprocess

    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        mock.Mock(side_effect=subprocess.SubprocessError("boom")),
    )

    scanner = PortScanner()
    assert scanner._find_pids_windows(80) == []


# ─────────────────────────────────────────────────────────────────────────────
# _find_pids_unix
# ─────────────────────────────────────────────────────────────────────────────


def test_find_pids_unix_parses_lsof(monkeypatch):
    """_find_pids_unix parses lsof output correctly."""
    lsof_output = "100\n200\n300\n"
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        lambda *a, **k: lsof_output.encode(),
    )

    scanner = PortScanner()
    assert scanner._find_pids_unix(80) == [100, 200, 300]


def test_find_pids_unix_dedups(monkeypatch):
    """_find_pids_unix deduplicates PIDs."""
    lsof_output = "100\n100\n200\n"
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        lambda *a, **k: lsof_output.encode(),
    )

    scanner = PortScanner()
    assert scanner._find_pids_unix(80) == [100, 200]


def test_find_pids_unix_handles_empty_output(monkeypatch):
    """_find_pids_unix returns [] for empty output."""
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        lambda *a, **k: b"",
    )

    scanner = PortScanner()
    assert scanner._find_pids_unix(80) == []


def test_find_pids_unix_handles_subprocess_failure(monkeypatch):
    """_find_pids_unix returns [] when lsof fails."""
    import subprocess

    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        mock.Mock(side_effect=subprocess.SubprocessError("boom")),
    )

    scanner = PortScanner()
    assert scanner._find_pids_unix(80) == []


# ─────────────────────────────────────────────────────────────────────────────
# _get_process_name (no psutil, falls back to /proc)
# ─────────────────────────────────────────────────────────────────────────────


def test_get_process_name_reads_proc_comm(monkeypatch, tmp_path):
    """_get_process_name reads /proc/<pid>/comm when psutil is unavailable."""
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "linux")

    fake_proc = tmp_path / "1234" / "comm"
    fake_proc.parent.mkdir()
    fake_proc.write_text("myprocess\n")

    import builtins
    original_open = builtins.open

    def patched_open(path, *a, **k):
        if str(path).startswith("/proc/"):
            new_path = str(path).replace("/proc/", str(tmp_path) + "/", 1)
            return original_open(new_path, *a, **k)
        return original_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", patched_open)

    scanner = PortScanner()
    scanner._proc_cache.clear()
    name = scanner._get_process_name(1234)
    assert name == "myprocess"


def test_get_process_name_returns_unknown_on_failure(monkeypatch):
    """_get_process_name returns 'Unknown' when /proc read fails."""
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "linux")

    scanner = PortScanner()
    # No /proc file exists; should return Unknown
    name = scanner._get_process_name(99999999)
    assert name == "Unknown"


def test_get_process_name_non_unix_falls_back_to_unknown(monkeypatch):
    """_get_process_name on non-unix without psutil returns 'Unknown'."""
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "Windows")

    scanner = PortScanner()
    name = scanner._get_process_name(1234)
    assert name == "Unknown"


# ─────────────────────────────────────────────────────────────────────────────
# _kill_process (psutil path with timeout escalation)
# ─────────────────────────────────────────────────────────────────────────────


def test_kill_process_escalates_to_sigkill_on_timeout(scanner_with_psutil):
    """_kill_process calls proc.kill() if terminate+wait times out."""
    scanner, fake_psutil = scanner_with_psutil

    proc = mock.MagicMock()
    proc.wait.side_effect = [fake_psutil.TimeoutExpired(3), None]
    # Override the fixture's side_effect for this test
    fake_psutil.Process.side_effect = None
    fake_psutil.Process.return_value = proc

    result = scanner._kill_process(1234, "testproc")
    assert result is True
    proc.terminate.assert_called_once()
    assert proc.wait.call_count == 2
    proc.kill.assert_called_once()


def test_kill_process_without_psutil_unix(monkeypatch):
    """_kill_process uses os.kill on Unix without psutil."""
    import os as os_module

    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "linux")

    kill_calls = []

    def fake_kill(pid, sig):
        kill_calls.append((pid, sig))
        # After SIGTERM, simulate process gone on second kill(pid, 0)
        if sig == 0 and len(kill_calls) >= 2:
            raise OSError("process gone")

    monkeypatch.setattr("openports.scanner.os.kill", fake_kill)
    monkeypatch.setattr("openports.scanner.time.sleep", lambda s: None)

    scanner = PortScanner()
    result = scanner._kill_process(1234, "testproc")
    assert result is True
    assert kill_calls[0] == (1234, 15)  # SIGTERM


def test_kill_process_without_psutil_unix_needs_sigkill(monkeypatch):
    """_kill_process falls back to SIGKILL if process still alive after SIGTERM."""
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "linux")

    call_log = []

    def fake_kill(pid, sig):
        call_log.append(sig)
        # Process is still alive after SIGTERM (os.kill(pid, 0) succeeds)
        # so we should escalate to SIGKILL
        if sig == 0:
            pass  # still alive
        elif sig == 9:
            pass  # SIGKILL

    # We need: first call SIGTERM(15), then os.kill(pid, 0) succeeds (no exception)
    # then os.kill(pid, SIGKILL)
    # But in the source code, after sleep(1), it does os.kill(pid, 0) to check,
    # and only kills with SIGKILL if that succeeds (process still alive).
    # Then the final os.kill(pid, SIGKILL) would cause OSError on next check.

    # Actually re-reading the code: after SIGTERM, sleep 1s, then:
    #   try:
    #       os.kill(pid, 0)        # check if alive
    #       os.kill(pid, SIGKILL)  # still alive -> force kill
    #   except OSError:
    #       pass                   # already dead

    import signal

    monkeypatch.setattr("openports.scanner.os.kill", fake_kill)
    monkeypatch.setattr("openports.scanner.time.sleep", lambda s: None)

    scanner = PortScanner()
    result = scanner._kill_process(1234, "testproc")
    assert result is True
    # SIGTERM, then check (0), then SIGKILL
    assert signal.SIGTERM in call_log
    assert signal.SIGKILL in call_log


def test_kill_process_without_psutil_windows(monkeypatch):
    """_kill_process uses taskkill on Windows without psutil."""
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "Windows")

    ran_cmds = []

    def fake_run(cmd, *a, **k):
        ran_cmds.append(cmd)

    monkeypatch.setattr("openports.scanner.subprocess.run", fake_run)

    scanner = PortScanner()
    result = scanner._kill_process(1234, "testproc")
    assert result is True
    assert ran_cmds == [["taskkill", "/PID", "1234", "/F"]]


def test_kill_process_handles_error(monkeypatch, capsys):
    """_kill_process handles errors gracefully."""
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "linux")
    monkeypatch.setattr(
        "openports.scanner.os.kill",
        mock.Mock(side_effect=PermissionError("denied")),
    )
    monkeypatch.setattr("openports.scanner.time.sleep", lambda s: None)

    scanner = PortScanner()
    result = scanner._kill_process(1234, "testproc")
    assert result is False
    assert "Failed to kill" in capsys.readouterr().out


# ─────────────────────────────────────────────────────────────────────────────
# _confirm positive path
# ─────────────────────────────────────────────────────────────────────────────


def test_confirm_yes_path(scanner_with_psutil, monkeypatch):
    """_confirm returns True when user types 'y'."""
    scanner, _ = scanner_with_psutil
    monkeypatch.setattr("builtins.input", lambda _: "y")
    assert scanner._confirm("testproc", 1234) is True


def test_confirm_yes_full(scanner_with_psutil, monkeypatch):
    """_confirm returns True when user types 'yes'."""
    scanner, _ = scanner_with_psutil
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    assert scanner._confirm("testproc", 1234) is True


def test_confirm_eof(scanner_with_psutil, monkeypatch, capsys):
    """_confirm returns False on EOFError."""
    scanner, _ = scanner_with_psutil
    monkeypatch.setattr("builtins.input", mock.Mock(side_effect=EOFError))
    assert scanner._confirm("testproc", 1234) is False
    assert "cancelled" in capsys.readouterr().out.lower()


# ─────────────────────────────────────────────────────────────────────────────
# _list_windows (full parsing)
# ─────────────────────────────────────────────────────────────────────────────


def test_list_windows_parses_tcp_and_udp(monkeypatch):
    """_list_windows parses both TCP and UDP lines."""
    netstat_output = (
        "  Proto  Local Address          Foreign Address        State    PID\n"
        "  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING  1234\n"
        "  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING  5678\n"
        "  UDP    0.0.0.0:53             0.0.0.0:0                       9999\n"
    )
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        lambda *a, **k: netstat_output.encode(),
    )

    scanner = PortScanner()
    entries = scanner._list_windows(None, None, show_all=True)
    assert len(entries) == 3
    ports = sorted(e["port"] for e in entries)
    assert ports == [53, 80, 443]

    udp_entry = [e for e in entries if e["port"] == 53][0]
    assert udp_entry["proto"] == "UDP"
    assert udp_entry["status"] == "UDP"


def test_list_windows_filters_by_port(monkeypatch):
    """_list_windows respects filter_port."""
    netstat_output = (
        "  TCP    0.0.0.0:80    0.0.0.0:0    LISTENING    1234\n"
        "  TCP    0.0.0.0:443   0.0.0.0:0    LISTENING    5678\n"
    )
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        lambda *a, **k: netstat_output.encode(),
    )

    scanner = PortScanner()
    entries = scanner._list_windows(filter_port=443, search=None, show_all=True)
    assert len(entries) == 1
    assert entries[0]["port"] == 443


def test_list_windows_show_all_false_only_listening(monkeypatch):
    """_list_windows show_all=False filters to only LISTENING state."""
    netstat_output = (
        "  TCP    0.0.0.0:80    0.0.0.0:0    LISTENING     1234\n"
        "  TCP    0.0.0.0:443   0.0.0.0:0    ESTABLISHED   5678\n"
    )
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        lambda *a, **k: netstat_output.encode(),
    )

    scanner = PortScanner()
    entries = scanner._list_windows(None, None, show_all=False)
    assert len(entries) == 1
    assert entries[0]["port"] == 80


def test_list_windows_handles_subprocess_failure(monkeypatch):
    """_list_windows returns [] when netstat fails."""
    import subprocess

    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        mock.Mock(side_effect=subprocess.SubprocessError("boom")),
    )

    scanner = PortScanner()
    entries = scanner._list_windows(None, None, show_all=True)
    assert entries == []


def test_list_windows_skips_malformed_lines(monkeypatch):
    """_list_windows skips lines that don't match expected format."""
    netstat_output = (
        "  TCP    0.0.0.0:80   0.0.0.0:0   LISTENING   1234\n"
        "  BADPROT something\n"  # bad protocol
        "  TCP    notanumber    0.0.0.0:0   LISTENING   abcd\n"  # bad PID
    )
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        lambda *a, **k: netstat_output.encode(),
    )

    scanner = PortScanner()
    entries = scanner._list_windows(None, None, show_all=True)
    assert len(entries) == 1
    assert entries[0]["port"] == 80


def test_list_windows_search_filter(monkeypatch):
    """_list_windows respects search filter."""
    netstat_output = (
        "  TCP    0.0.0.0:80    0.0.0.0:0    LISTENING    1234\n"
        "  TCP    0.0.0.0:443   0.0.0.0:0    LISTENING    5678\n"
    )
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        lambda *a, **k: netstat_output.encode(),
    )

    scanner = PortScanner()
    # Mock _process_info to return specific names
    scanner._process_info = lambda pid: {
        "name": "nginx" if pid == 1234 else "apache",
        "cmdline": None,
        "user": "root",
        "memory": "10MB",
        "threads": 2,
    }

    entries = scanner._list_windows(None, search="nginx", show_all=True)
    assert len(entries) == 1
    assert entries[0]["pid"] == 1234


# ─────────────────────────────────────────────────────────────────────────────
# _list_unix (full parsing)
# ─────────────────────────────────────────────────────────────────────────────


def test_list_unix_parses_lsof_output(monkeypatch):
    """_list_unix parses lsof output correctly."""
    lsof_output = (
        "COMMAND  PID USER  FD  TYPE  DEVICE  SIZE/OFF  NODE  NAME\n"
        "nginx    1234 root  6u  IPv4  12345   0t0       TCP   *:80 (LISTEN)\n"
        "apache   5678 root  4u  IPv4  67890   0t0       TCP   *:443 (LISTEN)\n"
    )
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        lambda *a, **k: lsof_output.encode(),
    )

    scanner = PortScanner()
    entries = scanner._list_unix(None, None, show_all=False)
    assert len(entries) == 2
    ports = sorted(e["port"] for e in entries)
    assert ports == [80, 443]
    assert all(e["status"] == "LISTENING" for e in entries)


def test_list_unix_show_all_includes_established(monkeypatch):
    """_list_unix show_all=True includes established connections."""
    lsof_output = (
        "COMMAND  PID USER  FD  TYPE  DEVICE  SIZE/OFF  NODE  NAME\n"
        "nginx    1234 root  6u  IPv4  12345   0t0       TCP   *:80 (LISTEN)\n"
        "curl     5678 user  4u  IPv4  67890   0t0       TCP   1.2.3.4:54321\n"
    )
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        lambda *a, **k: lsof_output.encode(),
    )

    scanner = PortScanner()
    entries = scanner._list_unix(None, None, show_all=True)
    assert len(entries) == 2
    statuses = {e["status"] for e in entries}
    assert statuses == {"LISTENING", "ESTABLISHED"}


def test_list_unix_filters_by_port(monkeypatch):
    """_list_unix respects filter_port."""
    lsof_output = (
        "COMMAND  PID USER  FD  TYPE  DEVICE  SIZE/OFF  NODE  NAME\n"
        "nginx    1234 root  6u  IPv4  12345   0t0       TCP   *:80 (LISTEN)\n"
        "apache   5678 root  4u  IPv4  67890   0t0       TCP   *:443 (LISTEN)\n"
    )
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        lambda *a, **k: lsof_output.encode(),
    )

    scanner = PortScanner()
    entries = scanner._list_unix(filter_port=443, search=None, show_all=False)
    assert len(entries) == 1
    assert entries[0]["port"] == 443


def test_list_unix_handles_subprocess_failure(monkeypatch):
    """_list_unix returns [] when lsof fails."""
    import subprocess

    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        mock.Mock(side_effect=subprocess.SubprocessError("boom")),
    )

    scanner = PortScanner()
    entries = scanner._list_unix(None, None, show_all=True)
    assert entries == []


def test_list_unix_skips_short_lines(monkeypatch):
    """_list_unix skips lines with too few fields."""
    lsof_output = (
        "COMMAND  PID USER  FD  TYPE  DEVICE  SIZE/OFF  NODE  NAME\n"
        "short line\n"
        "nginx    1234 root  6u  IPv4  12345   0t0       TCP   *:80 (LISTEN)\n"
    )
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        lambda *a, **k: lsof_output.encode(),
    )

    scanner = PortScanner()
    entries = scanner._list_unix(None, None, show_all=False)
    assert len(entries) == 1
    assert entries[0]["port"] == 80


def test_list_unix_handles_no_colon_in_name(monkeypatch):
    """_list_unix includes entries with no colon in name field (port becomes None)."""
    lsof_output = (
        "COMMAND  PID USER  FD  TYPE  DEVICE  SIZE/OFF  NODE  NAME\n"
        "nginx    1234 root  6u  IPv4  12345   0t0       TCP   nocolon\n"
        "apache   5678 root  4u  IPv4  67890   0t0       TCP   *:443 (LISTEN)\n"
    )
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        lambda *a, **k: lsof_output.encode(),
    )

    scanner = PortScanner()
    entries = scanner._list_unix(None, None, show_all=False)
    # Both entries are included - nginx has port=None, apache has port=443
    assert len(entries) == 2
    port_pids = {(e["port"], e["pid"]) for e in entries}
    assert (None, 1234) in port_pids
    assert (443, 5678) in port_pids


def test_list_unix_with_search_reads_cmdline(monkeypatch, tmp_path):
    """_list_unix reads /proc/<pid>/cmdline when searching."""
    lsof_output = (
        "COMMAND  PID USER  FD  TYPE  DEVICE  SIZE/OFF  NODE  NAME\n"
        "nginx    1234 root  6u  IPv4  12345   0t0       TCP   *:80 (LISTEN)\n"
    )
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        lambda *a, **k: lsof_output.encode(),
    )

    # Create a fake /proc/1234/cmdline
    cmdline_dir = tmp_path / "1234"
    cmdline_dir.mkdir()
    (cmdline_dir / "cmdline").write_bytes(b"nginx\x00-g\x00now\n")

    import builtins
    original_open = builtins.open

    def patched_open(path, *a, **k):
        if str(path).startswith("/proc/"):
            new_path = str(path).replace("/proc/", str(tmp_path) + "/", 1)
            return original_open(new_path, *a, **k)
        return original_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", patched_open)

    scanner = PortScanner()
    # Search for 'nginx' - should match
    entries = scanner._list_unix(None, search="nginx", show_all=False)
    assert len(entries) == 1
    assert entries[0]["cmdline"] is not None

    # Search for 'apache' - should not match
    entries = scanner._list_unix(None, search="apache", show_all=False)
    assert len(entries) == 0


def test_list_unix_deduplicates_entries(monkeypatch):
    """_list_unix deduplicates entries with same port/pid/status."""
    lsof_output = (
        "COMMAND  PID USER  FD  TYPE  DEVICE  SIZE/OFF  NODE  NAME\n"
        "nginx    1234 root  6u  IPv4  12345   0t0       TCP   *:80 (LISTEN)\n"
        "nginx    1234 root  7u  IPv4  12346   0t0       TCP   *:80 (LISTEN)\n"
    )
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr(
        "openports.scanner.subprocess.check_output",
        lambda *a, **k: lsof_output.encode(),
    )

    scanner = PortScanner()
    entries = scanner._list_unix(None, None, show_all=False)
    assert len(entries) == 1


# ─────────────────────────────────────────────────────────────────────────────
# find_pids_by_port: dispatch to Windows vs Unix
# ─────────────────────────────────────────────────────────────────────────────


def test_find_pids_by_port_dispatches_to_windows(monkeypatch):
    """find_pids_by_port calls _find_pids_windows on Windows."""
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "Windows")

    scanner = PortScanner()
    called = []
    scanner._find_pids_windows = lambda port: called.append(port) or [42]

    result = scanner.find_pids_by_port(80)
    assert result == [42]
    assert called == [80]


def test_find_pids_by_port_dispatches_to_unix(monkeypatch):
    """find_pids_by_port calls _find_pids_unix on Linux."""
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "Linux")

    scanner = PortScanner()
    called = []
    scanner._find_pids_unix = lambda port: called.append(port) or [99]

    result = scanner.find_pids_by_port(443)
    assert result == [99]
    assert called == [443]


# ─────────────────────────────────────────────────────────────────────────────
# list_ports: dispatch to Windows vs Unix
# ─────────────────────────────────────────────────────────────────────────────


def test_list_ports_dispatches_to_windows(monkeypatch):
    """list_ports calls _list_windows on Windows when psutil is unavailable."""
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "Windows")

    scanner = PortScanner()
    scanner._list_windows = mock.Mock(return_value=[{"port": 80}])
    result = scanner.list_ports()
    scanner._list_windows.assert_called_once()
    assert result == [{"port": 80}]


def test_list_ports_dispatches_to_unix(monkeypatch):
    """list_ports calls _list_unix on Linux when psutil is unavailable."""
    monkeypatch.setattr("openports.scanner.HAS_PSUTIL", False)
    monkeypatch.setattr("openports.scanner.platform.system", lambda: "Linux")

    scanner = PortScanner()
    scanner._list_unix = mock.Mock(return_value=[{"port": 443}])
    result = scanner.list_ports()
    scanner._list_unix.assert_called_once()
    assert result == [{"port": 443}]
