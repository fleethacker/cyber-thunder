"""Bounded local inventory proof; never hash or resolve credential values."""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import stat

MAX_INVENTORY_BYTES = 1024 * 1024
MAX_PARSE_ITEMS = 32768
MAX_DEPTH = 16


def _identity(info):
    # Windows stat/fstat can disagree on ctime; use portable identity fields.
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _nonlink_stat(path):
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("linked inventory path")
    return info


def inventory_text(path):
    """At most 1 MiB, regular/nonlinked, readable and unchanged during the read.

    Check the opened descriptor as well as the path. Nonblocking/no-follow flags
    prevent POSIX FIFO/symlink replacements from turning validation into a wait.
    No buffered background readers or unlimited stream.read() calls are used.
    """
    path = Path(os.path.abspath(path))
    before = _nonlink_stat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_INVENTORY_BYTES:
        raise ValueError("unsupported inventory file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    raw = bytearray()
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or _identity(opened) != _identity(before):
            raise ValueError("inventory changed during open")
        while block := os.read(fd, min(65536, MAX_INVENTORY_BYTES + 1 - len(raw))):
            raw.extend(block)
            if len(raw) > MAX_INVENTORY_BYTES:
                raise ValueError("inventory size limit")
        if len(raw) != opened.st_size or _identity(os.fstat(fd)) != _identity(opened):
            raise ValueError("inventory changed during read")
        if _identity(_nonlink_stat(path)) != _identity(opened):
            raise ValueError("inventory replaced during read")
    finally:
        os.close(fd)
    return raw.decode("utf-8")


def _pairs(items):
    result = {}
    for key, value in items:
        if not isinstance(key, str) or key in result:
            raise ValueError("invalid or duplicate inventory key")
        result[key] = value
    return result


def _values(value, depth=0, budget=None):
    budget = [MAX_PARSE_ITEMS] if budget is None else budget
    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_DEPTH:
        raise ValueError("inventory complexity limit")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("invalid inventory key")
            _values(item, depth + 1, budget)
    elif isinstance(value, list):
        for item in value:
            _values(item, depth + 1, budget)
    elif type(value) is float:
        if not math.isfinite(value):
            raise ValueError("invalid inventory number")
    elif value is not None and type(value) not in (str, int, bool):
        raise ValueError("invalid inventory value")


def inventory_document(text, path):
    """Parse bounded JSON/YAML with duplicate, alias, and complexity rejection."""
    if len(text.encode("utf-8")) > MAX_INVENTORY_BYTES:
        raise ValueError("inventory size limit")
    if Path(path).suffix.lower() in {".yaml", ".yml"}:
        import yaml
        depth = 0
        for count, event in enumerate(yaml.parse(text)):
            if count > MAX_PARSE_ITEMS or isinstance(event, yaml.AliasEvent):
                raise ValueError("inventory complexity or alias")
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
            elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
            if depth > MAX_DEPTH:
                raise ValueError("inventory depth limit")

        class UniqueLoader(yaml.SafeLoader):
            def construct_mapping(self, node, deep=False):
                return _pairs((self.construct_object(k, deep=deep), self.construct_object(v, deep=deep))
                              for k, v in node.value)
        document = yaml.load(text, Loader=UniqueLoader)
    else:
        # Preflight nesting before the decoder can recurse/materialize objects.
        quoted = escaped = False
        depth = 0
        for char in text:
            if escaped:
                escaped = False
            elif quoted and char == "\\":
                escaped = True
            elif char == '"':
                quoted = not quoted
            elif not quoted:
                if char in "[{":
                    depth += 1
                elif char in "]}":
                    depth -= 1
                if depth > MAX_DEPTH:
                    raise ValueError("inventory depth limit")
        document = json.loads(text, object_pairs_hook=_pairs)
    _values(document)
    if not isinstance(document, dict) or set(document) != {"targets"} or not isinstance(document["targets"], list):
        raise ValueError("inventory shape")
    if len(document["targets"]) > 4096:
        raise ValueError("inventory target limit")
    return document
