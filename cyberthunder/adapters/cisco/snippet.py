"""Deterministic config-snippet editing for IOS running-config text.

``apply_snippet(config_text, snippet)`` applies the same lines an engineer would type in
``configure terminal`` to a saved running-config, without a device:

* a global line is added next to similar lines (or replaces the line holding the same setting,
  e.g. ``exec-timeout 5 0`` replaces ``exec-timeout 30 0``);
* ``no <line>`` removes every line that starts with ``<line>`` (with its sub-block, so
  ``no interface Tunnel9`` or ``no event manager applet X`` removes the whole stanza). For settings IOS
  shows explicitly when disabled (``no ip http server``, ``no ip proxy-arp`` ...) the ``no`` line is kept;
* an indented line in the snippet edits the block it sits under (``line vty 0 4``, ``interface Gi1/0/5``),
  creating the block if needed.

The result is idempotent: applying the same snippet twice gives the same text. It is used in file and
simulated modes, by the live-device emulator in tests, and to compute the diff shown to the approver.

``inverse_snippet(before, after)`` produces the lines that take ``after`` back to ``before``; it is the
rollback for a live device when no ``configure replace`` archive is available.
"""
from __future__ import annotations

import difflib

from .parser import Node, banner_body, render, split_lines, tokenize

# Settings IOS prints explicitly as "no ..." when they are off (their default is on).
DEFAULT_ON = {
    "ip http server", "service pad", "ip bootp server", "cdp run", "ip domain lookup", "ip domain-lookup",
    "ip source-route", "ip gratuitous-arps", "ip finger", "service config", "ip proxy-arp", "ip redirects",
    "ip unreachables", "cdp enable", "ip route-cache", "mop enabled", "logging on", "logging trap",
    "logging console", "ip http secure-server", "vstack", "service dhcp", "ip mask-reply",
}

# Lines that are keystrokes, not configuration. Skipped when a snippet is applied to text.
CONTROL = {"configure terminal", "conf t", "config t", "end", "exit", "write memory", "wr mem", "wr",
           "copy running-config startup-config", "!"}

# Settings that hold one value: a new line with the same key replaces the old one.
_SINGLE = [tuple(s.split()) for s in (
    "hostname", "enable secret", "enable password", "exec-timeout", "transport input", "transport output",
    "transport preferred", "ip ssh version", "ip ssh time-out", "ip ssh authentication-retries",
    "ip ssh server algorithm mac", "ip ssh server algorithm encryption", "ip ssh dh min size",
    "logging buffered", "logging trap", "logging console", "logging monitor", "logging source-interface",
    "logging origin-id", "login block-for", "login on-failure", "login on-success", "login",
    "switchport mode", "switchport access vlan", "switchport trunk native vlan", "switchport trunk allowed vlan",
    "switchport voice vlan", "switchport port-security maximum", "switchport port-security violation",
    "ip address", "description", "security passwords min-length", "session-limit", "privilege level",
    "spanning-tree portfast bpduguard", "spanning-tree portfast", "spanning-tree mode", "spanning-tree guard",
    "ip domain name", "ip domain-name", "vtp mode", "vtp domain", "vtp version", "vtp password",
    "clock timezone", "ntp source", "snmp-server location", "snmp-server contact", "ip http authentication",
    "ip http timeout-policy", "ip http max-connections", "ip dhcp snooping vlan", "ip default-gateway",
    "version", "service timestamps debug", "service timestamps log", "aaa authentication login default",
    "aaa authorization exec default", "aaa accounting exec default", "aaa accounting commands 15 default",
    "address ipv4", "key", "min-length", "max-length", "path", "maximum", "password", "duplex", "speed",
    "mtu", "ip mtu", "tunnel source", "tunnel destination", "tunnel mode",
)]
_SINGLE.sort(key=len, reverse=True)

_KEYED = [(tuple(p.split()), n) for p, n in (
    ("username", 2), ("snmp-server community", 3), ("snmp-server group", 3), ("ntp server", 3),
    ("logging host", 3), ("ntp authentication-key", 3), ("ntp trusted-key", 3), ("snmp-server host", 3),
)]


def _norm(text: str) -> str:
    return " ".join(text.split()) if "\n" not in text else text


def setting_key(text: str) -> str | None:
    """Key identifying which setting a line holds, or None when the whole line is its own identity."""
    t = text.strip()
    if t.startswith("no "):
        t = t[3:]
    if t.startswith("banner "):
        parts = t.split()
        return "banner " + parts[1] if len(parts) > 1 else None
    w = t.split()
    if not w:
        return None
    if w[0] == "access-class" and len(w) >= 3:
        return f"access-class {w[-1]}"
    if w[:2] == ["ip", "access-group"] and len(w) >= 4:
        return f"ip access-group {w[3]}"
    for prefix, n in _KEYED:
        if tuple(w[:len(prefix)]) == prefix and len(w) >= n:
            return " ".join(w[:n])
    for prefix in _SINGLE:
        if tuple(w[:len(prefix)]) == prefix:
            return " ".join(prefix)
    return None


def _matches(text: str, target: str) -> bool:
    t = _norm(text)
    if "\n" in t:
        t = t.split("\n", 1)[0].strip()
    return t == target or t.startswith(target + " ")


def _first_words(text: str, n: int) -> tuple[str, ...]:
    return tuple(text.split()[:n])


def _insert_pos(container: list[Node], text: str, top: bool) -> int:
    """Index to insert a new line: after the last sibling that looks alike, else before 'line'/'end'."""
    for n in (2, 1):
        fw = _first_words(text.split("\n", 1)[0], n)
        if len(fw) < n:
            continue
        idx = [i for i, c in enumerate(container) if _first_words(c.text.split("\n", 1)[0], n) == fw]
        if idx:
            return idx[-1] + 1
    if top:
        if text.startswith("interface "):
            for i, c in enumerate(container):
                if c.text.startswith("line ") or c.text == "end":
                    return i
        for i, c in enumerate(container):
            if c.text.startswith("line ") or c.text == "end":
                # keep the separator that precedes the line blocks with them
                while i > 0 and container[i - 1].text == "!":
                    i -= 1
                return i
    return len(container)


def _apply_line(container: list[Node], line: str, indent: int, top: bool) -> None:
    line = _norm(line)
    if line.startswith("no ") and "\n" not in line:
        target = line[3:]
        if target.startswith("banner "):
            container[:] = [c for c in container if not _matches(c.text, target)]
            return
        first = next((i for i, c in enumerate(container) if _matches(c.text, target)), None)
        container[:] = [c for c in container if not _matches(c.text, target)]
        if target in DEFAULT_ON and not any(_norm(c.text) == line for c in container):
            pos = first if first is not None else _insert_pos(container, target, top)
            container.insert(pos, Node(line, indent))
        return
    key = setting_key(line)

    def _is_no_form(c: Node) -> bool:
        return c.text.startswith("no ") and (_norm(c.text[3:]) == line or bool(key and setting_key(c.text[3:]) == key))

    # a positive line cancels its explicit "no" form and takes its place
    first = next((i for i, c in enumerate(container) if _is_no_form(c)), None)
    container[:] = [c for c in container if not _is_no_form(c)]
    if any(_norm(c.text) == line for c in container):
        return
    if key:
        for c in container:
            if not c.text.startswith("no ") and setting_key(c.text) == key:
                c.text = line
                return
    pos = first if first is not None else _insert_pos(container, line, top)
    container.insert(pos, Node(line, indent))


def _apply_nodes(container: list[Node], ops: list[Node], indent: int, top: bool) -> None:
    for op in ops:
        text = op.text if "\n" in op.text else _norm(op.text)
        if not text or text in CONTROL:
            continue
        if op.children and not text.startswith("no "):
            blk = next((c for c in container if _norm(c.text) == text), None)
            if blk is None:
                blk = Node(text, indent)
                container.insert(_insert_pos(container, text, top), blk)
            child_indent = blk.children[0].indent if blk.children else blk.indent + 1
            _apply_nodes(blk.children, op.children, child_indent, False)
        else:
            _apply_line(container, text, indent, top)


def snippet_ops(snippet: str) -> list[Node]:
    """Parse a snippet into the same tree shape as a config; control keystrokes removed."""
    return [n for n in tokenize(snippet) if n.text and _norm(n.text) not in CONTROL]


def apply_snippet(config_text: str, snippet: str) -> str:
    nodes = tokenize(config_text)
    _apply_nodes(nodes, tokenize(snippet), 0, True)
    trailing = config_text.endswith("\n") or config_text.endswith("\r")
    out = render(nodes, trailing_newline=trailing)
    if "\r\n" in config_text:
        out = out.replace("\n", "\r\n")
    return out


# -- inverse -----------------------------------------------------------------------------------------

_SKIP = {"", "!", "end"}


def _subtree_lines(n: Node, indent: int) -> list[str]:
    out = [n.text if "\n" in n.text else " " * indent + n.text]
    for c in n.children:
        out.extend(_subtree_lines(c, indent + 1))
    return out


def _inverse(before: list[Node], after: list[Node], indent: int) -> list[str]:
    b_map = {_norm(n.text): n for n in before if _norm(n.text) not in _SKIP}
    a_map = {_norm(n.text): n for n in after if _norm(n.text) not in _SKIP}
    removed = [k for k in b_map if k not in a_map]
    added = [k for k in a_map if k not in b_map]
    removed_keys = {setting_key(k) for k in removed} - {None}
    out: list[str] = []
    pad = " " * indent
    for k in added:
        n = a_map[k]
        key = setting_key(k)
        if key and key in removed_keys:
            continue                                   # the re-added old value replaces it
        if "\n" in k:                                   # banner that did not exist before
            out.append(f"{pad}no banner {banner_body(k)[0]}")
        elif k.startswith("no "):
            out.append(pad + k[3:])
        else:
            out.append(pad + "no " + k)
    for k in removed:
        out.extend(_subtree_lines(b_map[k], indent))
    for k, bn in b_map.items():
        an = a_map.get(k)
        if an is None or (not bn.children and not an.children):
            continue
        sub = _inverse(bn.children, an.children, indent + 1)
        if sub:
            out.append(pad + k)
            out.extend(sub)
    # Drop repeats within one block only: the same child line under two different headers
    # (e.g. ' permit ip any any' in two ACLs) must be kept for each.
    seen: set[tuple[str, str]] = set()
    result: list[str] = []
    context = ""
    for x in out:
        if len(x) - len(x.lstrip(" ")) <= indent:
            context, key = x, ("", x)
        else:
            key = (context, x)
        if key in seen:
            continue
        seen.add(key)
        result.append(x)
    return result


def inverse_snippet(before_text: str, after_text: str) -> str:
    """Lines that turn ``after_text`` back into ``before_text`` (same settings; line order may differ)."""
    lines = _inverse(tokenize(before_text), tokenize(after_text), 0)
    return "\n".join(lines)


def unified_diff(before_text: str, after_text: str, name: str = "running-config") -> str:
    if before_text == after_text:
        return ""
    return "\n".join(difflib.unified_diff(split_lines(before_text), split_lines(after_text),
                                          fromfile=f"{name} (before)", tofile=f"{name} (after)", lineterm=""))


def snippet_lines(snippet: str) -> list[str]:
    """The lines of a snippet as they would be typed (banners split back into lines)."""
    out: list[str] = []
    for raw in split_lines(snippet):
        if raw.strip():
            out.append(raw.rstrip())
    return out
