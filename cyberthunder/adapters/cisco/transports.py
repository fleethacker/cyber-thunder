"""Transports for Cisco devices.

file       ConfigFileTransport: a saved running-config on disk (target.options.config_path). Reading
           'show running-config' returns the file; writing 'running-config' saves it. This is how a
           config pulled by hand (or by another tool) over the constrained link is assessed and fixed.
simulated  SimulatedTransport: a file transport over <state_dir>/simulated/<target_id>.cfg, seeded from
           range/cisco/seeded_switch.cfg (or options.seed_config) on first use. Applying a fix really
           changes that file, so verify and rollback are real state transitions in the demo.
ssh        the generic SSHTransport; IOSCli drives its interactive shell (network devices do not run a
           POSIX shell, so exec_command is not used for configuration).
"""
from __future__ import annotations

import re
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

from cyberthunder.transport.base import CommandResult, Transport, TransportError

from .parser import parse_config

REPO_ROOT = Path(__file__).resolve().parents[3]
RANGE_DIR = REPO_ROOT / "range" / "cisco"
DEFAULT_SEED = RANGE_DIR / "seeded_switch.cfg"

CONFIG_NAMES = ("running-config", "system:running-config", "nvram:startup-config", "startup-config")


class ConfigFileTransport(Transport):
    """A device represented by its running-config text in one file."""
    kind = "file"

    def __init__(self, path: str | Path):
        self.path = Path(path)

    # -- config text ----------------------------------------------------------------------------
    def read_config(self) -> str:
        if not self.path.exists():
            raise TransportError(f"config file not found: {self.path}")
        with self.path.open("r", encoding="utf-8", newline="") as fh:
            return fh.read()

    def write_config(self, text: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        tmp.replace(self.path)

    # -- Transport ------------------------------------------------------------------------------
    def run(self, command: str, *, timeout: int = 120, sudo: bool = False) -> CommandResult:
        cmd = " ".join(command.split()).lower()
        t0 = time.time()
        try:
            if cmd in ("show running-config", "show run", "more system:running-config"):
                return CommandResult(command, 0, self.read_config(), "", time.time() - t0, t0)
            if cmd in ("show version", "show ver"):
                m = parse_config(self.read_config())
                out = (f"Cisco IOS XE Software, Version {m.version or 'unknown'}\n"
                       f"{m.hostname or 'device'} uptime is unknown (offline configuration file)\n")
                return CommandResult(command, 0, out, "", time.time() - t0, t0)
            if cmd == "show clock":
                now = datetime.now(timezone.utc).strftime("*%H:%M:%S.000 UTC %a %b %d %Y")
                return CommandResult(command, 0, now + "\n", "", time.time() - t0, t0)
            if cmd in ("terminal length 0", "terminal width 0"):
                return CommandResult(command, 0, "", "", 0.0, t0)
        except TransportError as e:
            return CommandResult(command, 1, "", str(e), time.time() - t0, t0)
        return CommandResult(command, 127, "", f"{self.kind} transport: command not available offline: {command!r}",
                             0.0, t0)

    def read_file(self, path: str) -> bytes:
        if path in CONFIG_NAMES or Path(path) == self.path:
            return self.path.read_bytes() if self.path.exists() else b""
        raise TransportError(f"{self.kind} transport only holds the running-config, not {path!r}")

    def write_file(self, path: str, data: bytes, *, mode: int | None = None, sudo: bool = False) -> None:
        if path in CONFIG_NAMES or Path(path) == self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_bytes(data)
            tmp.replace(self.path)
            return
        raise TransportError(f"{self.kind} transport only holds the running-config, not {path!r}")


class SimulatedTransport(ConfigFileTransport):
    """Stateful emulated device: a copy of a seeded config under the state directory."""
    kind = "simulated"

    def __init__(self, path: str | Path, seed: str | Path = DEFAULT_SEED):
        super().__init__(path)
        self.seed = Path(seed)
        if not self.path.exists():
            self.reset()

    def reset(self) -> None:
        if not self.seed.exists():
            raise TransportError(f"seed config not found: {self.seed}")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.seed, self.path)


# -- live CLI -----------------------------------------------------------------------------------------

PROMPT_RE = re.compile(r"(?:^|[\r\n])[A-Za-z0-9_.\-/:]+(?:\([A-Za-z0-9_.\-/]+\))?[#>]\s*$")
MORE_RE = re.compile(r"\s*--More--\s*$")
CLI_ERROR_RE = re.compile(r"^\s*% ?(Invalid input|Incomplete command|Ambiguous command|Unknown command|Error)",
                          re.M | re.I)


class IOSCli:
    """Minimal driver for an IOS interactive shell (paramiko Channel or anything with send/recv)."""

    def __init__(self, channel, *, timeout: float = 30.0, quiet: float = 1.0):
        self.ch = channel
        self.timeout = timeout
        self.quiet = quiet
        self._read(expect_prompt=True, timeout=min(timeout, 10.0))   # login banner + first prompt

    def _ready(self) -> bool:
        fn = getattr(self.ch, "recv_ready", None)
        return bool(fn()) if fn else True

    def _read(self, *, expect_prompt: bool = True, timeout: float | None = None) -> str:
        deadline = time.time() + (timeout or self.timeout)
        buf = ""
        last = time.time()
        while time.time() < deadline:
            if self._ready():
                chunk = self.ch.recv(65535)
                if not chunk:
                    break
                buf += chunk.decode("utf-8", "replace") if isinstance(chunk, bytes) else chunk
                last = time.time()
                if MORE_RE.search(buf):
                    buf = MORE_RE.sub("", buf)
                    self.ch.send(" ")
                    continue
                if expect_prompt and PROMPT_RE.search(buf):
                    return buf
                continue
            if not expect_prompt and buf and time.time() - last >= self.quiet:
                return buf
            if not expect_prompt and not buf and time.time() - last >= self.quiet:
                return buf
            time.sleep(0.05)
        if expect_prompt:
            raise TransportError(f"device did not return a prompt within {timeout or self.timeout:.0f}s")
        return buf

    def send(self, line: str, *, expect_prompt: bool = True, timeout: float | None = None) -> str:
        self.ch.send(line + "\n")
        out = self._read(expect_prompt=expect_prompt, timeout=timeout)
        out = out.replace("\r\n", "\n").replace("\r", "\n")
        lines = out.split("\n")
        if lines and lines[0].strip() == line.strip():
            lines = lines[1:]                         # echoed command
        if expect_prompt and lines and PROMPT_RE.search("\n" + lines[-1]):
            lines = lines[:-1]                        # trailing prompt
        return "\n".join(lines)

    def show(self, command: str, timeout: float | None = None) -> str:
        return self.send(command, timeout=timeout)

    def close(self) -> None:
        try:
            self.ch.close()
        except Exception:  # noqa: BLE001
            pass


def open_cli(transport: Transport, timeout: float = 30.0) -> IOSCli:
    opener = getattr(transport, "open_shell", None)
    if opener is None:
        raise TransportError(f"transport {transport.kind} has no interactive shell")
    channel = opener()
    try:
        cli = IOSCli(channel, timeout=timeout)
        cli.send("terminal length 0")
        cli.send("terminal width 0")
    except Exception:
        try:
            channel.close()
        except Exception:  # noqa: BLE001
            pass
        raise
    return cli


def strip_show_output(text: str) -> str:
    """Remove the 'Building configuration...' preamble so the result parses like a saved config."""
    lines = text.replace("\r\n", "\n").split("\n")
    out = []
    started = False
    for ln in lines:
        if not started and (ln.startswith("Building configuration") or ln.startswith("Current configuration")
                            or not ln.strip()):
            continue
        started = True
        out.append(ln)
    s = "\n".join(out).rstrip("\n")
    return s + "\n" if s else ""
