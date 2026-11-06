"""Bounded reads for dependency evidence; never use the general recording/scan paths."""
from __future__ import annotations

import base64
from contextlib import contextmanager
import json
import math
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
    import selectors
    # The platform selector handles descriptors above select's fixed ceiling.
    # Close its own kernel resource after every nonblocking readiness check.
    with selectors.DefaultSelector() as readiness:
        readiness.register(stream, selectors.EVENT_READ)
        ready = readiness.select(timeout=0)
    return stream.read(4096) if ready else None


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


@contextmanager
def _close_after_read(resource):
    failed = False
    try:
        yield resource
    except BaseException:
        failed = True
        raise
    finally:
        try:
            resource.close()
        except Exception:
            if not failed:
                raise


def _ssh(transport, command, timeout, guard, *, deadline=None):
    # Share host trust policy; keep bounded probes free of implicit identities.
    deadline = time.monotonic() + timeout if deadline is None else deadline

    def check():
        if time.monotonic() >= deadline:
            raise ReadFailure("timeout")
        transport._guard()
        guard()
        if time.monotonic() >= deadline:
            raise ReadFailure("timeout")

    check()
    from cyberthunder.security.secret_resolver import CredentialUse
    use = transport._credential_use
    if use is not None and not isinstance(use, CredentialUse):
        raise ReadFailure("explicit_ssh_credential_required")
    if not transport._password and not transport._key and use is None:
        # Automatic agent/key discovery can try an unbounded number of identities.
        raise ReadFailure("explicit_ssh_credential_required")
    client = transport.connect_client(timeout=min(3, deadline - time.monotonic()),
                                      deadline=deadline, guard=check, allow_agent=False)
    with _close_after_read(client):
        check()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ReadFailure("timeout")
        channel = client.get_transport().open_session(timeout=remaining)
        with _close_after_read(channel):
            check()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ReadFailure("timeout")
            channel.settimeout(remaining)
            channel.exec_command(command)
            check()
            out, err = bytearray(), bytearray()
            while True:
                check()
                if time.monotonic() >= deadline:
                    raise ReadFailure("timeout")
                channel.settimeout(deadline - time.monotonic())
                if channel.recv_ready():
                    out.extend(channel.recv(4096))
                    check()
                if channel.recv_stderr_ready():
                    err.extend(channel.recv_stderr(4096))
                    check()
                _check_size(out, err)
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    check()
                    code = channel.recv_exit_status()
                    check()
                    return CommandResult("", code,
                                         out.decode("utf-8", "replace"), err.decode("utf-8", "replace"))
                time.sleep(0.01)


def _winrm(transport, command, timeout, guard, *, deadline=None):
    # Session.run_ps/get_command_output retries operation timeouts indefinitely. Read single
    # protocol frames instead, with a deadline and short HTTP timeouts, then always clean up.
    from winrm.exceptions import WinRMOperationTimeoutError

    deadline = time.monotonic() + timeout if deadline is None else deadline
    if transport._session is not None:
        raise ReadFailure("reused_session")
    with transport.bounded_reader(guard=guard, deadline=deadline) as operation:
        operation.open()
        encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
        operation.run("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded])
        out, err = bytearray(), bytearray()
        while time.monotonic() < deadline:
            try:
                stdout, stderr, code, done = operation.receive()
            except WinRMOperationTimeoutError:
                continue
            if not isinstance(stdout, bytes) or not isinstance(stderr, bytes) or type(done) is not bool:
                raise ReadFailure("invalid_output")
            if len(out) + len(err) + len(stdout) + len(stderr) > MAX_OUTPUT:
                raise ReadFailure("output_limit")
            out.extend(stdout)
            err.extend(stderr)
            if done:
                if type(code) is not int:
                    raise ReadFailure("invalid_output")
                return CommandResult("", code, out.decode("utf-8", "replace"), err.decode("utf-8", "replace"))
        raise ReadFailure("timeout")


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
    # Sanitize provider and cleanup errors outside their exception handlers so
    # traceback chaining cannot export credentials. Keep authorization signals.
    from cyberthunder.control.killswitch import KillSwitchEngaged
    from cyberthunder.transport.trust import TrustError
    failure = None
    try:
        return _read_command(transport, command, timeout=timeout, guard=guard)
    except (ReadFailure, KillSwitchEngaged, TrustError):
        raise
    except PermissionError:
        failure = "permission"
    except TimeoutError:
        failure = "timeout"
    except Exception:
        failure = "transport_failed"
    if failure == "permission":
        raise PermissionError("Dependency principal revoked or access refused") from None
    raise ReadFailure(failure) from None


def _read_command(transport, command, *, timeout, guard):
    """Only collector-built commands reach here. Unknown transports fail closed."""
    from cyberthunder.adapters.kubernetes.kubectl import KubectlTransport
    from cyberthunder.transport.fixture import FixtureTransport
    from cyberthunder.transport.local import LocalTransport
    from cyberthunder.transport.ssh import SSHTransport
    from cyberthunder.transport.winrm import WinRMTransport

    if isinstance(timeout, bool) or not isinstance(timeout, (float, int)) or not math.isfinite(timeout) or timeout <= 0:
        raise ReadFailure("timeout")
    deadline = time.monotonic() + timeout
    caller_guard = guard
    def guard():
        if time.monotonic() >= deadline:
            raise ReadFailure("timeout")
        caller_guard()
        for name in ("account_guard", "_guard"):
            check = getattr(transport, name, None)
            if callable(check):
                check()
        if time.monotonic() >= deadline:
            raise ReadFailure("timeout")

    guard()
    if isinstance(transport, FixtureTransport):
        result = _fixture(transport, command)
    elif type(transport) is KubectlTransport:
        argv, stdin = transport.build_argv(command)
        if stdin is not None:
            raise ReadFailure("unsupported_command")
        from cyberthunder.security.kube_credentials import kube_subprocess_env
        env = kube_subprocess_env() if getattr(transport, "account_binding", None) is not None else None
        result = _process(argv, timeout, guard=guard, env=env)
    elif type(transport) is LocalTransport:
        argv = shlex.split(command) if command.startswith("systemctl show ") else transport._argv(command)
        result = _process(argv, timeout, cwd=transport.cwd, env=transport.env, guard=guard)
    elif type(transport) is SSHTransport:
        result = _ssh(transport, command, timeout, guard, deadline=deadline)
    elif type(transport) is WinRMTransport:
        result = _winrm(transport, command, timeout, guard, deadline=deadline)
    else:
        raise ReadFailure("unsupported_transport")
    if not isinstance(result.stdout, str) or not isinstance(result.stderr, str) or type(result.exit_code) is not int:
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
