"""Remove only the unique Linux directory named in this run's receipts."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys


def main(receipts):
    receipts = Path(receipts).resolve(strict=True)
    task = Path((receipts / "linux-directory.txt").read_text().strip())
    run_id = (receipts / "run-id.txt").read_text().strip()
    if (task.parent != Path("/tmp") or not re.fullmatch(r"ct-container-scap-[A-Za-z0-9]{8}", task.name)
            or task.name.lower() != run_id or task.is_symlink() or task.resolve(strict=True) != task
            or task.stat().st_uid != os.getuid() or not shutil.rmtree.avoids_symlink_attacks):
        raise ValueError("refusing cleanup outside the exact owned temporary directory")
    receipt = {"directory": str(task), "run_id": run_id}
    archive = task / "image.tar"
    if archive.is_file() and not archive.is_symlink():
        with archive.open("rb") as source:
            receipt["export_sha256"] = hashlib.file_digest(source, "sha256").hexdigest()
    # Do not follow image links. Restore write permission only to owned directories.
    for directory, dirs, files in os.walk(task, topdown=True, followlinks=False):
        current = Path(directory)
        if current.is_symlink() or os.path.ismount(current):
            raise ValueError("refusing cleanup of a link or mounted directory")
        os.chmod(current, stat.S_IMODE(current.stat().st_mode) | 0o700, follow_symlinks=False)
        dirs[:] = [name for name in dirs if not (current / name).is_symlink()]
    shutil.rmtree(task)
    receipt["removed"] = not task.exists()
    (receipts / "linux-cleanup.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main(*sys.argv[1:])
