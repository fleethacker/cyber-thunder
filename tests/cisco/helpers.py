"""Shared test helpers for the Cisco adapter: config paths and an emulated IOS shell."""
from __future__ import annotations

from pathlib import Path

from cyberthunder.adapters.cisco.snippet import apply_snippet
from cyberthunder.transport.base import CommandResult, Transport

ROOT = Path(__file__).resolve().parents[2]
RANGE = ROOT / "range" / "cisco"
FIXTURES = ROOT / "tests" / "fixtures" / "cisco"
SEEDED_SWITCH = RANGE / "seeded_switch.cfg"
CLEAN_SWITCH = RANGE / "clean_switch.cfg"
SEEDED_ROUTER = RANGE / "seeded_router.cfg"
CLEAN_ROUTER = FIXTURES / "clean_router.cfg"
ANSWER_KEY = ROOT / "range" / "answer_key" / "cisco_ios.json"

ROUTER_OPTS = {"known_users": ["admin"], "known_syslog": ["10.1.1.5", "10.1.2.5"]}


def read(p: Path) -> str:
    with p.open("r", encoding="utf-8", newline="") as fh:
        return fh.read()


class FakeIOSChannel:
    """Enough of an IOS exec/config shell to drive IOSCli: echo, prompts, config mode, archive, replace."""

    def __init__(self, device: "FakeIOSDevice"):
        self.dev = device
        self.out: list[str] = [f"\r\n{self.dev.hostname}#"]
        self.mode = "exec"
        self.pending: list[str] = []
        self.in_banner: str | None = None
        self.copying: tuple[str, str] | None = None
        self.closed = False

    def recv_ready(self) -> bool:
        return bool(self.out)

    def recv(self, n: int) -> bytes:
        data = "".join(self.out)
        self.out = []
        return data.encode("utf-8")

    def _prompt(self) -> str:
        return f"{self.dev.hostname}(config)#" if self.mode == "config" else f"{self.dev.hostname}#"

    def send(self, data: str) -> int:
        lines = data.split("\n")
        if data.endswith("\n"):
            lines.pop()
        for line in lines:
            if line == "" and self.copying is None:      # a bare Enter only matters at a copy prompt
                continue
            self._line(line)
        return len(data)

    def _line(self, line: str) -> None:
        self.dev.typed.append(line)
        echo = line + "\r\n"
        s = line.strip()
        if self.mode == "config":
            if self.in_banner is not None:
                self.pending.append(line.replace("^", "^C") if "^" in line else line)
                if "^" in line:
                    self.in_banner = None
                    self.out.append(echo + self._prompt())
                else:
                    self.out.append(echo)
                return
            if s == "end":
                self.dev.config = apply_snippet(self.dev.config, "\n".join(self.pending))
                self.pending = []
                self.mode = "exec"
                self.out.append(echo + self._prompt())
                return
            if s.startswith("bogus"):
                self.out.append(echo + "% Invalid input detected at '^' marker.\r\n" + self._prompt())
                return
            if s.startswith("banner "):
                self.pending.append(line.replace("^", "^C"))
                self.in_banner = "^"
                self.out.append(echo + "Enter TEXT message.  End with the character '^'.\r\n")
                return
            self.pending.append(line)
            self.out.append(echo + self._prompt())
            return
        if s == "configure terminal":
            self.mode = "config"
            body = "Enter configuration commands, one per line.  End with CNTL/Z.\r\n"
        elif s == "show running-config":
            body = "Building configuration...\r\n\r\nCurrent configuration : 4242 bytes\r\n" + \
                self.dev.config.replace("\n", "\r\n")
        elif s == "show version":
            body = "Cisco IOS XE Software, Version 17.09.04a\r\ncisco C9300-48P (X86) processor\r\n" \
                   "Model Number                       : C9300-48P\r\n"
        elif s == "show clock":
            body = "*12:00:00.000 UTC Wed Nov 4 2026\r\n"
        elif s == "write memory":
            self.dev.saved = self.dev.config
            body = "Building configuration...\r\n[OK]\r\n"
        elif self.copying is not None:
            dest, step = self.copying
            if step == "name" and dest in self.dev.files:
                self.copying = (dest, "confirm")
                self.out.append(echo + "%Warning:There is a file already existing with this name\r\n"
                                       "Do you want to over write? [confirm]")
                return
            self.dev.files[dest] = self.dev.config
            self.copying = None
            body = f"{len(self.dev.config)} bytes copied in 0.120 secs\r\n"
        elif s.startswith("copy running-config "):
            dest = s.split(None, 2)[2]
            self.copying = (dest, "name")
            self.out.append(echo + f"Destination filename [{dest.split(':')[-1]}]? ")
            return
        elif s == "archive config":
            self.dev.archive = self.dev.config
            name = f"flash:ct-archive-{len(self.dev.archives) + 1}"
            self.dev.archives.append(name)
            self.dev.files[name] = self.dev.config
            body = ""
        elif s == "show archive":
            rows = "".join(f"   {i}        {n}{' <- Most Recent' if i == len(self.dev.archives) else ''}\r\n"
                           for i, n in enumerate(self.dev.archives, 1))
            body = "The maximum archive configurations allowed is 10.\r\n Archive #  Name\r\n" + rows
        elif s.startswith("configure replace "):
            path = s.split()[2]
            if path not in self.dev.files:
                body = f"%Error opening {path} (No such file or directory)\r\n"
            else:
                self.dev.config = self.dev.files[path]
                body = "Total number of passes: 1\r\nRollback Done\r\n"
        else:
            body = ""
        self.out.append(echo + body + self._prompt())

    def close(self) -> None:
        self.closed = True


class FakeIOSDevice:
    def __init__(self, config: str, hostname: str = "swi-01"):
        self.config = config
        self.hostname = hostname
        self.saved: str | None = None
        self.archive: str | None = None
        self.archives: list[str] = []
        self.files: dict[str, str] = {}             # device filesystem, e.g. flash:ct-pre.cfg
        self.typed: list[str] = []
        self.channels: list[FakeIOSChannel] = []


class FakeSSHTransport(Transport):
    """Stands in for SSHTransport: only open_shell() is used for network devices."""
    kind = "ssh"

    def __init__(self, device: FakeIOSDevice):
        self.device = device

    def open_shell(self, width: int = 200, height: int = 50):
        ch = FakeIOSChannel(self.device)
        self.device.channels.append(ch)
        return ch

    def run(self, command: str, *, timeout: int = 120, sudo: bool = False) -> CommandResult:
        raise AssertionError("network devices are driven through the shell, not exec")

    def read_file(self, path: str) -> bytes:
        raise AssertionError("not used")

    def write_file(self, path: str, data: bytes, *, mode=None, sudo: bool = False) -> None:
        raise AssertionError("not used")
