"""Regenerate tests/fixtures/linux/sim_recorded from the simulated host.

Run from the worktree root with an isolated state dir, e.g.:
    CT_STATE_DIR=$(mktemp -d) python tests/linux/tools/record_sim_fixture.py

It records one full read-only collect() of the simulated host through RecordingTransport, so the detection
tests can replay static command output instead of the live emulator.
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from cyberthunder.adapters.linux import LinuxAdapter
from cyberthunder.adapters.linux.simhost import SimulatedLinuxHost
from cyberthunder.config import Settings
from cyberthunder.transport.fixture import RecordingTransport

OUT = Path(__file__).resolve().parents[2] / "fixtures" / "linux" / "sim_recorded"


def main() -> None:
    adapter = LinuxAdapter()
    target = adapter.demo_targets()[0]
    settings = Settings.from_env()
    if OUT.exists():
        shutil.rmtree(OUT)
    (OUT / "files").mkdir(parents=True)
    sim = SimulatedLinuxHost(target.id, settings.state_dir)
    rec = RecordingTransport(sim, OUT)
    adapter.collect(target, rec, Path(tempfile.mkdtemp()))
    print(f"recorded {len(rec.entries)} commands to {OUT}")


if __name__ == "__main__":
    main()
