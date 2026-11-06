"""Extract one Docker export without following archive links or creating devices.

Only use a new task-owned directory. Files precede links, all parents must be
directories, and hard links may name only regular files from this archive.
Absolute image symlinks are preserved only after all regular file writes finish; their
lexical destinations must remain inside the image namespace. Never traverse
this tree with a host scanner or execute its files.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sys
import tarfile


def relative(name):
    p = PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts or not p.parts:
        raise ValueError(f"unsafe member: {name!r}")
    return p


def main(archive, destination, receipt):
    root = Path(destination).resolve(strict=True)
    if any(root.iterdir()):
        raise ValueError("destination must be empty")
    counts = {"directories": 0, "files": 0, "hardlinks": 0, "symlinks": 0}
    skipped = []
    with tarfile.open(archive, "r:") as tf:
        entries = tf.getmembers()
        if len(entries) > 200000 or sum(e.size for e in entries) > 4 * 1024**3:
            raise ValueError("export exceeds extraction budget")
        members = {}
        for entry in entries:
            if entry.name in (".", "./") and entry.isdir():
                continue
            p = relative(entry.name)
            if str(p) in members:
                raise ValueError("duplicate archive path")
            members[str(p)] = entry
        # No archive entry may be nested under a link or other nondirectory.
        for name in members:
            for parent in PurePosixPath(name).parents:
                if str(parent) in members and not members[str(parent)].isdir():
                    raise ValueError("nondirectory archive parent")
        for name, entry in members.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if entry.isdir():
                path.mkdir(exist_ok=True)
                counts["directories"] += 1
            elif entry.isfile():
                with tf.extractfile(entry) as src, path.open("xb") as dst:
                    shutil.copyfileobj(src, dst)
                os.chmod(path, entry.mode)
                os.utime(path, (entry.mtime, entry.mtime))
                counts["files"] += 1
            elif not (entry.issym() or entry.islnk()):
                skipped.append({"path": name, "type": entry.type.decode("ascii")})
        for name, entry in members.items():
            if entry.islnk():
                target = str(relative(entry.linkname))
                if target not in members or not members[target].isfile():
                    raise ValueError("hard link does not target an archive regular file")
                os.link(root / target, root / name)
                counts["hardlinks"] += 1
        for name, entry in members.items():
            if not entry.issym():
                continue
            link = PurePosixPath(entry.linkname)
            parts = [] if link.is_absolute() else list(PurePosixPath(name).parent.parts)
            for part in link.parts:
                if part in ("/", "."):
                    continue
                if part == "..":
                    if not parts:
                        raise ValueError("symlink escapes image namespace")
                    parts.pop()
                else:
                    parts.append(part)
            os.symlink(entry.linkname, root / name)
            counts["symlinks"] += 1
        # Every directory and its parents were verified as directories above.
        # Apply restrictive modes last so unprivileged extraction can create links.
        for name, entry in reversed(list(members.items())):
            if entry.isdir():
                os.chmod(root / name, entry.mode, follow_symlinks=False)
                os.utime(root / name, (entry.mtime, entry.mtime), follow_symlinks=False)
    with open(archive, "rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    Path(receipt).write_text(json.dumps({"archive_sha256": digest, "counts": counts,
        "skipped_special_files": skipped, "ownership_preserved": False,
        "xattrs_preserved": False, "symlinks": "original text; created after all file writes",
        "limits": "200000 entries; 4 GiB expanded; no devices or archive traversal"}, indent=2) + "\n")


if __name__ == "__main__":
    main(*sys.argv[1:])
