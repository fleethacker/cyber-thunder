"""Bounded reads for dependency evidence; never use the general recording/scan paths."""
from __future__ import annotations

import base64
import json
import os
import shlex
import signal
import subprocess
import time
from pathlib import Path

from cyberthunder.transport.base import CommandResult, TransportError

MAX_OUTPUT = 65536
CALL_TIMEOUT = 10
MAX_CALLS = 8
TOTAL_TIMEOUT = 60
PROCESS_CLEANUP_TIMEOUT = 3


class ReadFailure(TransportError):
    """A fixed reason, safe to expose without transport stderr or credentials."""


def _check_size(stdout, stderr):
    if len(stdout) + len(stderr) > MAX_OUTPUT:
        raise ReadFailure("output_limit")


def _stop_process(proc):
    """Bounded tree termination and reaping, including descendants holding pipes.

    POSIX owns a new process group. Windows uses taskkill /T while the parent is
    alive; without a Job Object, already orphaned/detached children may survive.
    No cleanup path waits indefinitely for a process or inherited pipe handle.
    """
    deadline = time.monotonic() + PROCESS_CLEANUP_TIMEOUT
    try:
        if os.name == "nt":
            if proc.poll() is None:
                taskkill = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32" / "taskkill.exe"
                killer = subprocess.Popen([str(taskkill), "/PID", str(proc.pid), "/T", "/F"],
                                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
                try:
                    killer.wait(timeout=PROCESS_CLEANUP_TIMEOUT / 2)
                except subprocess.TimeoutExpired:
                    killer.kill()
                    killer.wait(timeout=max(0, deadline - time.monotonic()))
        else:
            # Kill the group even if its leader has exited but children hold pipes.
            os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=max(0, deadline - time.monotonic()))
    except (OSError, subprocess.TimeoutExpired):
        # SIGKILL/TerminateProcess has been requested; never extend the bound.
        pass


def _read_available(stream):
    """Read raw pipe bytes without a blocking buffered reader or drain thread."""
    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes

        peek = ctypes.WinDLL("kernel32", use_last_error=True).PeekNamedPipe
        peek.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                         wintypes.LPVOID, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID)
        peek.restype = wintypes.BOOL
        available = wintypes.DWORD()
        if not peek(msvcrt.get_osfhandle(stream.fileno()), None, 0, None, ctypes.byref(available), None):
            if ctypes.get_last_error() == 109:  # ERROR_BROKEN_PIPE
                return b""
            raise ReadFailure("invalid_output")
        return stream.read(min(4096, available.value)) if available.value else None
    import select
    return stream.read(4096) if select.select([stream], [], [], 0)[0] else None


def _process(argv, timeout, *, cwd=None, env=None, guard=lambda: None):
    """Bound both output streams and wall time; poll scope/kill during the call.

    Cleanup adds at most PROCESS_CLEANUP_TIMEOUT. Raw, nonblocking pipe reads
    avoid context-manager close deadlocks when a descendant inherits handles.
    """
    deadline = time.monotonic() + timeout
    guard()
    kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {"start_new_session": True}
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=cwd, env=env, shell=False, bufsize=0, **kwargs)
    except OSError:
        raise ReadFailure("process_unavailable") from None
    output, eof = [bytearray(), bytearray()], [False, False]
    try:
        while True:
            guard()
            if time.monotonic() >= deadline:
                raise ReadFailure("timeout")
            for index, pipe in enumerate((proc.stdout, proc.stderr)):
                if eof[index]:
                    continue
                block = _read_available(pipe)
                if block == b"":
                    eof[index] = True
                elif block:
                    if sum(map(len, output)) + len(block) > MAX_OUTPUT:
                        raise ReadFailure("output_limit")
                    output[index].extend(block)
            if proc.poll() is not None and all(eof):
                guard()
                return CommandResult("", proc.returncode, *(bytes(b).decode("utf-8", "replace") for b in output))
            time.sleep(min(0.01, max(0, deadline - time.monotonic())))
    finally:
        _stop_process(proc)
        # FileIO (bufsize=0), with no reader threads: close cannot wait for their locks.
        proc.stdout.close()
        proc.stderr.close()


def _ssh(transport, command, timeout, guard):
    # Reuse the transport's resolved connection values, with explicit connect/auth/channel limits.
    import paramiko

    deadline = time.monotonic() + timeout
    if not transport._password and not transport._key:
        # Automatic agent/key discovery can try an unbounded number of identities.
        raise ReadFailure("explicit_ssh_credential_required")
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(transport.host, port=transport.port, username=transport.username,
                       password=transport._password, key_filename=transport._key,
                       timeout=min(3, timeout), auth_timeout=min(3, timeout),
                       banner_timeout=min(3, timeout), channel_timeout=min(3, timeout),
                       look_for_keys=False, allow_agent=False)
        guard()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ReadFailure("timeout")
        channel = client.get_transport().open_session(timeout=remaining)
        try:
            guard()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ReadFailure("timeout")
            channel.settimeout(remaining)
            channel.exec_command(command)
            guard()
            out, err = bytearray(), bytearray()
            while True:
                if time.monotonic() >= deadline:
                    raise ReadFailure("timeout")
                if channel.recv_ready():
                    out.extend(channel.recv(4096))
                if channel.recv_stderr_ready():
                    err.extend(channel.recv_stderr(4096))
                _check_size(out, err)
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    return CommandResult("", channel.recv_exit_status(),
                                         out.decode("utf-8", "replace"), err.decode("utf-8", "replace"))
                time.sleep(0.01)
        finally:
            channel.close()
    finally:
        client.close()


def _winrm(transport, command, timeout, guard):
    # Session.run_ps/get_command_output retries operation timeouts indefinitely. Read single
    # protocol frames instead, with a deadline and short HTTP timeouts, then always clean up.
    from winrm.exceptions import WinRMOperationTimeoutError

    transport.operation_timeout_s = 2
    transport.read_timeout_s = 3
    if transport._session is not None:
        raise ReadFailure("reused_session")
    protocol = transport._sess().protocol
    deadline = time.monotonic() + timeout
    shell = command_id = None
    try:
        guard()
        shell = protocol.open_shell(noprofile=True, codepage=65001)
        guard()
        encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
        command_id = protocol.run_command(shell, "powershell.exe",
                                         ["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded])
        guard()
        out, err = bytearray(), bytearray()
        while time.monotonic() < deadline:
            guard()
            try:
                stdout, stderr, code, done = protocol.get_command_output_raw(shell, command_id)
            except WinRMOperationTimeoutError:
                guard()
                continue
            guard()
            out.extend(stdout)
            err.extend(stderr)
            _check_size(out, err)
            if done:
                return CommandResult("", code, out.decode("utf-8", "replace"), err.decode("utf-8", "replace"))
        raise ReadFailure("timeout")
    finally:
        # Cleanup is required even after scope revocation/kill; it cancels our own read only.
        try:
            if command_id is not None:
                protocol.cleanup_command(shell, command_id)
        finally:
            if shell is not None:
                protocol.close_shell(shell)
            transport._session = None


def _fixture(transport, command):
    # FixtureTransport.run creates missing.log; dependency collection must not do that.
    # Exact fixture entries only: regex replay would allow unbounded regular-expression work.
    if not isinstance(transport.entries, list) or len(transport.entries) > 128:
        raise ReadFailure("fixture_limit")
    entry = next((e for e in transport.entries if isinstance(e, dict) and e.get("match") == command), None)
    if entry is None:
        raise ReadFailure("fixture_missing")
    out = entry.get("stdout", "")
    if isinstance(out, dict) and isinstance(out.get("file"), str):
        root = transport.root.resolve()
        path = (root / out["file"]).resolve()
        if not path.is_relative_to(root):
            raise ReadFailure("fixture_invalid")
        with path.open("rb") as stream:
            data = stream.read(MAX_OUTPUT + 1)
        _check_size(data, b"")
        out = data.decode("utf-8", "replace")
    return CommandResult("", int(entry.get("exit", 0)), out, entry.get("stderr", ""))


def read_command(transport, command, *, timeout, guard):
    """Only collector-built commands reach here. Unknown transports fail closed."""
    from cyberthunder.adapters.kubernetes.kubectl import KubectlTransport
    from cyberthunder.transport.fixture import FixtureTransport
    from cyberthunder.transport.local import LocalTransport
    from cyberthunder.transport.ssh import SSHTransport
    from cyberthunder.transport.winrm import WinRMTransport

    guard()
    if isinstance(transport, FixtureTransport):
        result = _fixture(transport, command)
    elif type(transport) is KubectlTransport:
        argv, stdin = transport.build_argv(command)
        if stdin is not None:
            raise ReadFailure("unsupported_command")
        result = _process(argv, timeout, guard=guard)
    elif type(transport) is LocalTransport:
        argv = shlex.split(command) if command.startswith("systemctl show ") else transport._argv(command)
        result = _process(argv, timeout, cwd=transport.cwd, env=transport.env, guard=guard)
    elif type(transport) is SSHTransport:
        result = _ssh(transport, command, timeout, guard)
    elif type(transport) is WinRMTransport:
        result = _winrm(transport, command, timeout, guard)
    else:
        raise ReadFailure("unsupported_transport")
    if not isinstance(result.stdout, str) or not isinstance(result.stderr, str):
        raise ReadFailure("invalid_output")
    _check_size(result.stdout.encode("utf-8"), result.stderr.encode("utf-8"))
    if result.exit_code != 0:
        raise ReadFailure("command_failed")
    guard()
    return result.stdout


def read_json(text):
    try:
        result = json.loads(text)
    except (ValueError, TypeError, RecursionError):
        raise ReadFailure("invalid_json") from None
    if not isinstance(result, dict):
        raise ReadFailure("invalid_json")
    return result
