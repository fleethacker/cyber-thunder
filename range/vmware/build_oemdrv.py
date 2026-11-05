#!/usr/bin/env python3
"""Build a tiny ISO labelled OEMDRV that carries a kickstart file.

Anaconda automatically loads ``/ks.cfg`` from any block device whose filesystem label is
``OEMDRV``, which is how new-range-vm.ps1 drives a hands-off Rocky 9 install without touching
the Rocky ISO or passing any boot arguments.

Run with -P so the script directory is kept off the import path (a planted sibling module
cannot shadow a stdlib import) while installed packages such as pycdlib still load:

    python -P build_oemdrv.py --ks range/.local/ks.filled.cfg --out C:\\VM\\acd-target-01\\oemdrv.iso

Only dependency is pycdlib (``pip install pycdlib``).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


def build(ks_path: Path, out_path: Path) -> None:
    import pycdlib

    data = ks_path.read_bytes()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    iso = pycdlib.PyCdlib()
    # Rock Ridge keeps the real name "ks.cfg"; Joliet is a courtesy for other readers.
    # The volume identifier is what blkid/udev report as the label, so it MUST be OEMDRV.
    iso.new(interchange_level=3, vol_ident="OEMDRV", rock_ridge="1.09", joliet=3)
    iso.add_fp(__import__("io").BytesIO(data), len(data),
               "/KS.CFG;1", rr_name="ks.cfg", joliet_path="/ks.cfg")
    iso.write(str(out_path))
    iso.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build an OEMDRV kickstart ISO.")
    ap.add_argument("--ks", required=True, type=Path, help="path to the filled kickstart file")
    ap.add_argument("--out", required=True, type=Path, help="output ISO path (e.g. ...\\oemdrv.iso)")
    a = ap.parse_args(argv)

    if not a.ks.is_file():
        print(f"kickstart not found: {a.ks}", file=sys.stderr)
        return 2
    try:
        build(a.ks, a.out)
    except Exception as e:  # noqa: BLE001 - surface a clear message to the PowerShell caller
        print(f"OEMDRV build failed: {e}", file=sys.stderr)
        return 1
    size = a.out.stat().st_size
    print(f"wrote {a.out} ({size} bytes, label OEMDRV, /ks.cfg)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
