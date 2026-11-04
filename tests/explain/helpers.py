"""Shared helpers for explain tests: findings, a fix entry, a fake backend and an app context."""
from __future__ import annotations

import json
from pathlib import Path

from cyberthunder.adapters.base import make_finding
from cyberthunder.inventory.targets import Target
from cyberthunder.remediation.library import FixEntry

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "explain"


def responses() -> dict:
    return json.loads((FIXTURES / "responses.json").read_text(encoding="utf-8"))


def canned(name: str) -> str:
    r = responses()[name]
    return r if isinstance(r, str) else json.dumps(r)


TARGET = Target(id="web01", name="web01", asset_type="linux", transport="fixture")


def ssh_root_finding(**kw):
    args = dict(target=TARGET, source="openscap", rule_id="SV-257985r925540_rule",
                title="RHEL 9 must not permit direct logons to the root account using remote access via SSH",
                severity="medium", rule_version="RHEL-09-255045", group_id="V-257985",
                description="Even though the communications channel may be encrypted, an additional layer of "
                            "security is gained by extending the policy of not logging directly on as root. More text.",
                evidence="PermitRootLogin yes", references=["CCI-000770"],
                fix_ref="ssg:sshd_disable_root_login")
    args.update(kw)
    return make_finding(**args)


def cron_finding(**kw):
    args = dict(target=TARGET, source="hunt", rule_id="hunt:linux:cron_persistence",
                title="Unexpected root cron job runs a script from /dev/shm", severity="high",
                description="A cron entry executes a file in a world-writable tmpfs. Typical persistence.",
                evidence="* * * * * root /dev/shm/.x", references=["T1053.003"])
    args.update(kw)
    return make_finding(**args)


SSH_FIX = FixEntry(fix_ref="ssg:sshd_disable_root_login", title="Disable SSH root login", asset_type="linux",
                   applies_to=["RHEL-09-255045"], payload="sed -i ... /etc/ssh/sshd_config",
                   restarts_services=["sshd"], verify={"rule_ids": ["SV-257985r925540_rule"]})


class FakeBackend:
    """Returns canned responses in order; repeats the last one. Records prompts."""
    name = "fake"

    def __init__(self, outputs, model: str = "fake-model", available: bool = True):
        self.outputs = list(outputs)
        self.model = model
        self._available = available
        self.prompts: list[str] = []

    def available(self):
        return (self._available, "fake ok" if self._available else "fake down")

    def generate(self, prompt, *, json_mode=True, timeout=180):
        self.prompts.append(prompt)
        if not self.outputs:
            return None
        return self.outputs.pop(0) if len(self.outputs) > 1 else self.outputs[0]


def make_ctx(state_dir, **overrides):
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext
    overrides.setdefault("llm_backend", "template")
    ctx = AppContext(Settings.from_env(state_dir=state_dir, **overrides))
    ctx.library.add(SSH_FIX)
    return ctx
