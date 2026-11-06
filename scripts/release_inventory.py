"""Bounded, offline, partial release inventory. Python 3.12 standard library only."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from email.parser import BytesParser
from email.policy import default
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import threading
import tomllib
import zipfile
import zlib

SCHEMA = "http://cyclonedx.org/schema/bom-1.6.schema.json"
MAX_TEXT = 8 * 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_FILES = 10000
MAX_EXPANDED = 256 * 1024 * 1024
MAX_METADATA = 1024 * 1024
MAX_RATIO = 200
MAX_JSON_DEPTH = 64
LIMITATIONS = [
    "FUTURE candidate for ATO-02; partial inventory, not release approval.",
    "Declared versions are not installed versions. Wheel presence does not prove installation or dependency closure.",
    "Wheel CRC and hashes prove observed bytes, not trusted origin, signatures, or RECORD authenticity.",
    "npm lock declarations are not downloaded package verification; dev flags do not establish bundle membership.",
    "UI asset hashes do not establish the source commit or lockfile used to build them.",
    "Image references are declarations only; no registry resolution, layers, OS packages, or approved-image status.",
    "Manifest extraction covers literal FROM, image:, and block images: entries only; templates and other YAML forms need review.",
    "No vulnerability scan, license determination, dependency resolution, or complete transitive graph is performed.",
    "External runtime/model deployments remain unknown; optional local declarations are unverified claims.",
    "Git tree identifies HEAD; observed source hashes identify working files, including ignored UI assets. Not an atomic snapshot.",
]


class InventoryError(ValueError):
    """Unsafe, malformed, or over-budget input; no successful artifact may be emitted."""


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def props(**values):
    def check(value):
        if isinstance(value, str):
            text(value)
            if "://" in value:
                safe_reference(value)
        elif isinstance(value, dict):
            for key, item in value.items():
                check(key)
                check(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                check(item)
    check(values)
    return [{"name": "release-inventory:" + key.replace("_", "-"),
             "value": value if isinstance(value, str) else json.dumps(value, sort_keys=True, separators=(",", ":"))}
            for key, value in sorted(values.items())]


def text(value, limit=4096):
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 for c in value):
        raise InventoryError("invalid or oversized metadata string")
    return value


def safe_reference(value):
    value = text(value)
    if re.search(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s]*@", value) or ("://" in value and "?" in value):
        raise InventoryError("credential-bearing or query-bearing reference rejected")
    return value


def relative(value):
    text(value)
    parts = value.split("/")
    if not value or "\\" in value or ":" in value or any(p in ("", ".", "..") for p in parts):
        raise InventoryError("unsafe relative path")
    return PurePosixPath(value)


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InventoryError("duplicate JSON key")
        result[key] = value
    return result


def json_object(data):
    if len(data) > MAX_TEXT:
        raise InventoryError("JSON byte budget exceeded")
    # Scan before recursive decoding, including fields that will not be consumed.
    document = data.decode("utf-8") if isinstance(data, bytes) else data
    depth, quoted, escaped = 0, False, False
    for char in document:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise InventoryError("JSON nesting budget exceeded")
        elif char in "]}":
            depth -= 1
    result = json.loads(data, object_pairs_hook=object_pairs,
                        parse_constant=lambda _: (_ for _ in ()).throw(InventoryError("non-finite JSON")))
    if not isinstance(result, dict):
        raise InventoryError("expected JSON object")
    return result


def git(root, *args):
    # No shell, external diff, credential helper, hooks, or inherited GIT_* overrides.
    env = {k: v for k, v in os.environ.items()
           if k.upper() in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0")
    command = ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
               "-C", str(root), *args]
    with subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        timer = threading.Timer(20, process.kill)
        timer.start()
        try:
            data = process.stdout.read(MAX_TEXT + 1)
            if len(data) > MAX_TEXT:
                process.kill()
                raise InventoryError("git output exceeds budget")
            if process.wait() != 0:
                raise InventoryError("git read failed or timed out")
            return data
        finally:
            timer.cancel()


class Reader:
    def __init__(self, root):
        self.root = Path(root).resolve(strict=True)
        self.sources = {}
        self.total = 0
        self.visited = 0

    def path(self, name):
        rel = relative(name)
        path = self.root
        for part in rel.parts:
            path = path / part
            if path.is_symlink() or path.is_junction():
                raise InventoryError("linked source path rejected")
        if not path.resolve().is_relative_to(self.root):
            raise InventoryError("source outside repository")
        return path

    def read(self, name, limit=MAX_TEXT):
        path = self.path(name)
        if not path.exists():
            return None
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise InventoryError("non-regular, hard-linked, or oversized source")
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise InventoryError("source grew beyond budget")
        self.total += len(data)
        if self.total > MAX_TOTAL or len(self.sources) >= MAX_FILES:
            raise InventoryError("source budget exceeded")
        self.sources[name] = {"path": name, "sha256": digest(data), "bytes": len(data)}
        return data

    def files(self, directory, recursive=False):
        base = self.path(directory)
        if not base.exists():
            return []
        if not base.is_dir():
            raise InventoryError("expected directory")
        result = []
        pending = [base]
        while pending:
            current = pending.pop()
            with os.scandir(current) as entries:
                for entry in entries:
                    self.visited += 1
                    if self.visited > MAX_FILES:
                        raise InventoryError("directory entry budget exceeded")
                    name = Path(entry.path).relative_to(self.root).as_posix()
                    path = self.path(name)
                    if entry.is_dir(follow_symlinks=False):
                        if recursive:
                            pending.append(path)
                    else:
                        result.append(name)
        return sorted(result)


def wheel(data):
    """Verify all ZIP members (including CRC) without extracting or importing any."""
    # Bound central-directory parsing before ZipFile allocates one object per entry.
    end = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if end < 0 or end + 22 > len(data):
        raise InventoryError("missing ZIP end record")
    disk, central_disk, disk_count, count, size, offset, comment = struct.unpack_from("<4H2LH", data, end + 4)
    if (disk or central_disk or count != disk_count or count > MAX_FILES or size > MAX_TEXT
            or offset + size != end or end + 22 + comment != len(data)):
        raise InventoryError("unsupported or oversized ZIP directory (ZIP64 and multipart excluded)")
    cursor, observed = offset, 0
    while cursor < end:
        if data[cursor:cursor + 4] != b"PK\x01\x02" or cursor + 46 > end:
            raise InventoryError("invalid ZIP directory")
        name_size, extra_size, comment_size = struct.unpack_from("<3H", data, cursor + 28)
        cursor += 46 + name_size + extra_size + comment_size
        observed += 1
        if observed > MAX_FILES:
            raise InventoryError("wheel member budget exceeded")
    if cursor != end or observed != count:
        raise InventoryError("ZIP entry count mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        if len(members) > MAX_FILES:
            raise InventoryError("wheel member budget exceeded")
        seen, metadata, expanded = set(), [], 0
        for member in members:
            relative(member.filename.rstrip("/"))
            if member.filename.casefold() in seen:
                raise InventoryError("duplicate wheel member")
            seen.add(member.filename.casefold())
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode) or member.flag_bits & 1:
                raise InventoryError("linked or encrypted wheel member")
            if member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise InventoryError("unsupported wheel compression")
            expanded += member.file_size
            if expanded > MAX_EXPANDED or member.file_size > max(1, member.compress_size) * MAX_RATIO:
                raise InventoryError("wheel expansion budget exceeded")
            if re.fullmatch(r"[^/]+\.dist-info/METADATA", member.filename):
                if member.file_size > MAX_METADATA:
                    raise InventoryError("wheel metadata budget exceeded")
                metadata.append(member)
        if len(metadata) != 1:
            raise InventoryError("wheel must have exactly one METADATA")
        actual = 0
        for member in members:
            with archive.open(member) as stream:
                while chunk := stream.read(65536):
                    actual += len(chunk)
                    if actual > MAX_EXPANDED:
                        raise InventoryError("wheel expansion budget exceeded")
        message = BytesParser(policy=default).parsebytes(archive.read(metadata[0]))
        if message.defects or len(message.get_all("Name", [])) != 1 or len(message.get_all("Version", [])) != 1:
            raise InventoryError("invalid wheel identity")
        name, version = text(str(message["Name"])), text(str(message["Version"]))
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) or not version:
            raise InventoryError("invalid wheel identity")
        declared = {key: [text(str(v)) for v in message.get_all(key, [])]
                    for key in ("Requires-Dist", "Requires-Python", "License-Expression")}
        return name, version, declared


class Inventory:
    def __init__(self, root):
        self.reader = Reader(root)
        self.components = []
        self.gaps = []
        self.application = None

    def add(self, kind, name, source, version=None, sha=None, **evidence):
        if len(self.components) >= MAX_FILES:
            raise InventoryError("component budget exceeded")
        key = source + "\0" + name + "\0" + str(len(self.components))
        component = {"type": kind, "name": text(name), "bom-ref": "urn:sha256:" + digest(key.encode()),
                     "properties": props(source=source, artifact_evidence="complete-observed-bytes" if sha else "declaration-only",
                                         component_coverage="incomplete", **evidence)}
        if version is not None:
            component["version"] = text(version, limit=1024)
        if sha:
            component["hashes"] = [{"alg": "SHA-256", "content": sha}]
        self.components.append(component)

    def missing(self, source, reason):
        self.gaps.append({"source": source, "reason": reason})

    def read(self, name):
        data = self.reader.read(name)
        if data is None:
            self.missing(name, "missing")
        return data

    def python(self):
        data = self.read("pyproject.toml")
        if data is not None:
            config = tomllib.loads(data.decode("utf-8"))
            project = config.get("project", {})
            self.add("application", project.get("name", "unknown-project"), "pyproject.toml",
                     project.get("version"), evidence="repository-declaration",
                     dependencies=project.get("dependencies", []),
                     optional_dependencies=project.get("optional-dependencies", {}),
                     build_system=config.get("build-system", {}),
                     requires_python=project.get("requires-python", "unknown"))
            self.application = self.components.pop()
            if not project.get("name") or not project.get("version"):
                self.missing("pyproject.toml", "application name/version absent or empty; identity incomplete")
        for name in ("requirements.txt", "requirements-dev.txt"):
            data = self.read(name)
            if data is not None:
                declarations = [safe_reference(line.strip()) for line in data.decode().splitlines()
                                if line.strip() and not line.lstrip().startswith("#")]
                self.add("file", name, name, sha=digest(data), declarations=declarations,
                         evidence="unresolved-requirement-declarations")
        names = [name for name in self.reader.files("vendor") if name.endswith(".whl")]
        if not names:
            self.missing("vendor/*.whl", "no wheels observed")
        for source in names:
            data = self.reader.read(source, MAX_FILE)
            name, version, declared = wheel(data)
            self.add("library", name, source, version, digest(data), evidence="wheel-bytes-and-metadata",
                     zip_integrity="all-members-crc-checked", declared_metadata=declared,
                     installation="unknown", platform="wheel-filename-declaration-only")
        self.missing("python-dependency-closure", "not resolved; wheel versions/platforms may not satisfy declarations")

    def npm(self):
        source = "cyberthunder/ui/package.json"
        data = self.read(source)
        if data is not None:
            package = json_object(data)
            self.add("application", package.get("name", "unknown-ui"), source, package.get("version"),
                     evidence="repository-declaration", dependencies=package.get("dependencies", {}),
                     dev_dependencies=package.get("devDependencies", {}))
        source = "cyberthunder/ui/package-lock.json"
        data = self.read(source)
        if data is not None:
            lock = json_object(data)
            packages = lock.get("packages")
            if lock.get("lockfileVersion") not in (2, 3) or not isinstance(packages, dict):
                raise InventoryError("only npm lockfile v2/v3 packages maps supported")
            if len(packages) > MAX_FILES:
                raise InventoryError("npm package budget exceeded")
            for location, entry in sorted(packages.items()):
                if not location:
                    continue
                relative(location)
                if not isinstance(entry, dict):
                    raise InventoryError("invalid npm package entry")
                name = entry.get("name") or location.rsplit("node_modules/", 1)[-1]
                for flag in ("dev", "devOptional", "optional", "inBundle", "link"):
                    if flag in entry and not isinstance(entry[flag], bool):
                        raise InventoryError("invalid npm flag")
                role = "development" if entry.get("dev") else "runtime-eligible"
                if entry.get("devOptional"):
                    role = "development-or-optional-runtime"
                version = entry.get("version")
                self.add("library", name, source + "#" + location, version,
                         evidence="lock-declaration", dependency_role=role,
                         resolved=safe_reference(entry.get("resolved", "unknown")),
                         integrity=text(entry.get("integrity", "unknown")),
                         optional=entry.get("optional", False), link=entry.get("link", False),
                         lock_in_bundle=entry.get("inBundle", False), ui_bundle_membership="unknown",
                         dependencies=entry.get("dependencies", {}),
                         peer_dependencies=entry.get("peerDependencies", {}),
                         optional_dependencies=entry.get("optionalDependencies", {}))
                if version is None or not entry.get("integrity") or entry.get("link"):
                    self.missing(source + "#" + location, "version/integrity absent or local link; package bytes unverified")
        assets = self.reader.files("cyberthunder/ui/dist", recursive=True)
        if not assets:
            self.missing("cyberthunder/ui/dist", "no built assets observed")
        for source in assets:
            data = self.reader.read(source, MAX_FILE)
            self.add("file", source, source, sha=digest(data), evidence="observed-ui-asset",
                     source_build_provenance="unknown")
        self.missing("ui-bundle-membership", "no bundler provenance supplied; dev/runtime lock flags cannot prove shipped membership")

    def images(self):
        # Only tracked deployment manifests; do not walk private directories or follow references.
        tracked = git(self.reader.root, "ls-files", "-z", "--", "deploy", "packages").decode().split("\0")
        sources = ["Dockerfile", "Containerfile"] + sorted(
            p for p in tracked if p.endswith((".yaml", ".yml")))
        for source in sources:
            data = self.read(source)
            if data is None:
                continue
            block_indent = None
            for line_number, line in enumerate(data.decode().splitlines(), 1):
                stripped = line.strip()
                indent = len(line) - len(line.lstrip())
                reference = None
                match = re.match(r"(?i)^FROM\s+(?:--platform=\S+\s+)?(\S+)", stripped)
                if match:
                    reference = match[1]
                match = re.match(r"^(?:-\s+)?image:\s*([^#]+)", stripped)
                if match:
                    reference = match[1].strip().strip("\"'")
                if stripped == "images:":
                    block_indent = indent
                elif block_indent is not None and stripped and not stripped.startswith("#"):
                    if indent > block_indent and stripped.startswith("- "):
                        reference = stripped[2:].split(" #", 1)[0].strip().strip("\"'")
                    else:
                        block_indent = None
                if reference:
                    pinned = bool(re.fullmatch(r"[^\s@$]+@sha256:[0-9a-f]{64}", reference))
                    self.add("container", safe_reference(reference), source + ":" + str(line_number),
                             evidence="image-reference-declaration", digest_pinned=pinned,
                             image_contents="unknown", approval="unknown")
                    if not pinned:
                        self.missing(source + ":" + str(line_number), "image not pinned to a literal SHA-256 digest")
                match = re.match(r"^ARG\s+([A-Z0-9_]*VERSION)=([^\s]+)$", stripped)
                if match:
                    self.add("application", match[1], source + ":" + str(line_number), match[2],
                             evidence="build-argument-default", resolved_artifact="unknown")
        self.missing("container-and-build-runtime", "OS packages, fetched tools, build stages, and deployed image bytes not inspected")

    def external(self, source):
        if source is None:
            self.missing("external-models-and-runtimes", "no explicit local metadata supplied")
            return
        data = self.read(source)
        if data is None:
            raise InventoryError("requested external metadata is missing")
        document = json_object(data)
        if set(document) != {"components"} or not isinstance(document["components"], list):
            raise InventoryError("external metadata must contain only components array")
        for entry in document["components"]:
            if not isinstance(entry, dict) or set(entry) - {"kind", "name", "version", "reference", "sha256"}:
                raise InventoryError("invalid external component fields")
            if entry.get("kind") not in ("model", "runtime"):
                raise InventoryError("external kind must be model or runtime")
            sha = entry.get("sha256")
            if sha is not None and not re.fullmatch("[0-9a-f]{64}", text(sha)):
                raise InventoryError("invalid external digest declaration")
            self.add("machine-learning-model" if entry["kind"] == "model" else "application",
                     entry.get("name"), source, entry.get("version"),
                     evidence="unverified-local-declaration", declared_sha256=sha or "unknown",
                     reference=safe_reference(entry.get("reference", "unknown")), deployment="unknown")
        self.missing("external-models-and-runtimes", "local claims supplied; deployment and artifact bytes unverified")

    def generate(self, external_metadata=None):
        root = self.reader.root
        generator = Reader(Path(__file__).resolve().parent)
        generator_bytes = generator.read(Path(__file__).name)
        top = Path(git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve()
        if top != root:
            raise InventoryError("repo must be the Git worktree root")
        commit = git(root, "rev-parse", "HEAD").decode().strip()
        tree = git(root, "rev-parse", "HEAD^{tree}").decode().strip()
        status = git(root, "status", "--porcelain=v1", "-z", "--untracked-files=normal")
        self.python()
        self.npm()
        self.images()
        self.external(external_metadata)
        # Include the generator itself in observed source provenance, when present.
        self.read("scripts/release_inventory.py")
        sources = [self.reader.sources[key] for key in sorted(self.reader.sources)]
        for source in sources:
            path = self.reader.path(source["path"])
            with path.open("rb") as stream:
                current = stream.read(MAX_FILE + 1)
            if digest(current) != source["sha256"]:
                raise InventoryError("source changed during inventory")
        if (git(root, "rev-parse", "HEAD").decode().strip() != commit
                or git(root, "status", "--porcelain=v1", "-z", "--untracked-files=normal") != status):
            raise InventoryError("repository changed during inventory")
        if generator.read(Path(__file__).name) != generator_bytes:
            raise InventoryError("generator changed during inventory")
        return {"$schema": SCHEMA, "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "metadata": {**({"component": self.application} if self.application else {}), "properties": props(
                    candidate="FUTURE / ATO-02", coverage="partial", source_commit=commit,
                    generator_sha256=digest(generator_bytes),
                    source_head_tree=tree, source_dirty=bool(status), source_status_sha256=digest(status),
                    sources=sources, source_set_sha256=digest(encoded(sources)),
                    limitations=LIMITATIONS, unresolved=sorted(self.gaps, key=lambda gap: (gap["source"], gap["reason"])))},
                "components": self.components, "compositions": [{"aggregate": "incomplete"}]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new file outside inputs or in .build/release-inventory")
    parser.add_argument("--receipt", type=Path, required=True, help="new file outside inputs or in .build/release-inventory")
    parser.add_argument("--external-metadata", help="explicit repo-relative JSON; declarations only")
    args = parser.parse_args(argv)
    try:
        root = args.repo.resolve(strict=True)
        output, receipt = args.output.resolve(), args.receipt.resolve()
        allowed = root / ".build" / "release-inventory"
        if output == receipt or any((p.is_relative_to(root) and not p.is_relative_to(allowed)) or p.exists()
                                    for p in (output, receipt)):
            raise InventoryError("outputs must be distinct new files outside inputs")
        if args.external_metadata and root.joinpath(args.external_metadata).resolve() in (output, receipt):
            raise InventoryError("output overlaps external metadata")
        document = Inventory(root).generate(args.external_metadata)
        data = encoded(document)
        if len(data) > 32 * 1024 * 1024:
            raise InventoryError("artifact budget exceeded")
        evidence = encoded({"generated_at": datetime.now(timezone.utc).isoformat(),
                            "artifact_sha256": digest(data), "artifact_bytes": len(data),
                            "coverage": "partial", "metadata": document["metadata"],
                            "vulnerability_scan": "not performed", "schema_validation": "not performed by generator"})
        with output.open("xb") as stream:
            stream.write(data)
        with receipt.open("xb") as stream:
            stream.write(evidence)
        print(json.dumps({"artifact_sha256": digest(data), "components": len(document["components"]),
                          "coverage": "partial"}))
        return 0
    except (InventoryError, OSError, ValueError, TypeError, KeyError, AttributeError,
            RecursionError, zipfile.BadZipFile, EOFError, struct.error, zlib.error):
        # Do not echo arbitrary metadata, environment values, or parser payloads in error logs.
        print("Inventory failed: unsafe, malformed, missing required input, changed source, or exceeded budget.",
              file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
