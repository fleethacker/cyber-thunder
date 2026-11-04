"""OVAL definitions parser.

Namespace-agnostic like parsers/xccdf.py: DISA wraps the same elements in the oval-definitions-5 namespace and
its #windows / #independent sub-namespaces, sometimes as default namespaces redeclared per element. Elements
are matched on their local names; the family comes from the namespace fragment.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from .model import (Component, Criteria, Criterion, Definition, Entity, ExtendDefinition, ObjectDef, OvalDocument,
                    SetDef, StateDef, TestDef, Variable)

XSI_NIL = "{http://www.w3.org/2001/XMLSchema-instance}nil"
# children of an object that are not entities
OBJECT_META = {"behaviors", "set", "filter", "notes", "signature"}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _family(tag: str) -> str:
    if tag.startswith("{"):
        ns = tag[1:].split("}", 1)[0]
        if "#" in ns:
            return ns.rsplit("#", 1)[1]
    return ""


def _bool(v: str | None) -> bool:
    return str(v).strip().lower() in ("true", "1")


def _entity(el: ET.Element) -> Entity:
    nil = _bool(el.get(XSI_NIL))
    fields = [_entity(f) for f in el if _local(f.tag) == "field"]
    text = el.text if el.text is not None else ""
    e = Entity(name=_local(el.tag) if _local(el.tag) != "field" else (el.get("name") or "").lower(),
               value=None if nil else text, datatype=el.get("datatype") or "string",
               operation=el.get("operation") or "equals", var_ref=el.get("var_ref"),
               var_check=el.get("var_check") or "all", entity_check=el.get("entity_check") or "all", nil=nil,
               fields=fields)
    if fields:
        e.value = None
    return e


def _set(el: ET.Element) -> SetDef:
    s = SetDef(operator=(el.get("set_operator") or "UNION").upper())
    for ch in el:
        n = _local(ch.tag)
        if n == "object_reference":
            s.object_refs.append((ch.text or "").strip())
        elif n == "filter":
            s.filters.append(((ch.get("action") or "exclude").lower(), (ch.text or "").strip()))
        elif n == "set":
            s.sets.append(_set(ch))
    return s


def _criteria(el: ET.Element) -> Criteria:
    c = Criteria(operator=(el.get("operator") or "AND").upper(), negate=_bool(el.get("negate")),
                 comment=el.get("comment") or "")
    for ch in el:
        n = _local(ch.tag)
        if n == "criteria":
            c.children.append(_criteria(ch))
        elif n == "criterion":
            c.children.append(Criterion(ch.get("test_ref", ""), _bool(ch.get("negate")), ch.get("comment") or ""))
        elif n == "extend_definition":
            c.children.append(ExtendDefinition(ch.get("definition_ref", ""), _bool(ch.get("negate")),
                                               ch.get("comment") or ""))
    return c


def _component(el: ET.Element) -> Component:
    return Component(kind=_local(el.tag), attrs={k: v for k, v in el.attrib.items() if "}" not in k},
                     text=el.text if len(el) == 0 else None, children=[_component(c) for c in el])


def _definition(el: ET.Element) -> Definition:
    title = ""
    crit = None
    for ch in el:
        n = _local(ch.tag)
        if n == "metadata":
            t = next((x for x in ch if _local(x.tag) == "title"), None)
            title = " ".join((t.text or "").split()) if t is not None else ""
        elif n == "criteria":
            crit = _criteria(ch)
    return Definition(id=el.get("id", ""), cls=el.get("class") or "compliance", title=title, criteria=crit)


def _test(el: ET.Element) -> TestDef:
    t = TestDef(id=el.get("id", ""), type=_local(el.tag), family=_family(el.tag), check=el.get("check") or "all",
                check_existence=el.get("check_existence") or "at_least_one_exists",
                state_operator=(el.get("state_operator") or "AND").upper(), comment=el.get("comment") or "")
    for ch in el:
        n = _local(ch.tag)
        if n == "object":
            t.object_ref = ch.get("object_ref")
        elif n == "state":
            t.state_refs.append(ch.get("state_ref", ""))
    return t


def _object(el: ET.Element) -> ObjectDef:
    o = ObjectDef(id=el.get("id", ""), type=_local(el.tag), family=_family(el.tag), comment=el.get("comment") or "")
    for ch in el:
        n = _local(ch.tag)
        if n == "behaviors":
            o.behaviors = dict(ch.attrib)
        elif n == "set":
            o.set = _set(ch)
        elif n == "filter":
            o.filters.append(((ch.get("action") or "exclude").lower(), (ch.text or "").strip()))
        elif n not in OBJECT_META:
            o.entities.append(_entity(ch))
    return o


def _state(el: ET.Element) -> StateDef:
    return StateDef(id=el.get("id", ""), type=_local(el.tag), family=_family(el.tag),
                    operator=(el.get("operator") or "AND").upper(), comment=el.get("comment") or "",
                    entities=[_entity(ch) for ch in el if _local(ch.tag) not in ("notes", "signature")])


def _variable(el: ET.Element) -> Variable:
    kind = _local(el.tag).replace("_variable", "")
    v = Variable(id=el.get("id", ""), kind=kind, datatype=el.get("datatype") or "string",
                 comment=el.get("comment") or "")
    if kind == "constant":
        v.values = [(c.text or "") for c in el if _local(c.tag) == "value"]
    elif kind == "local":
        comps = [c for c in el if _local(c.tag) not in ("notes", "signature")]
        v.component = _component(comps[0]) if comps else None
    return v


def parse_oval_element(root: ET.Element) -> OvalDocument:
    """Parse an <oval_definitions> element (or any element containing one or more)."""
    doc = OvalDocument()
    sections = {"definitions": (_definition, doc.definitions), "tests": (_test, doc.tests),
                "objects": (_object, doc.objects), "states": (_state, doc.states),
                "variables": (_variable, doc.variables)}
    roots = [root] if _local(root.tag) == "oval_definitions" else [
        e for e in root.iter() if _local(e.tag) == "oval_definitions"]
    for od in roots:
        for sec in od:
            entry = sections.get(_local(sec.tag))
            if entry is None:
                continue
            fn, into = entry
            for el in sec:
                if el.get("id"):
                    into[el.get("id")] = fn(el)
    return doc


def parse_oval(path: str | Path) -> OvalDocument:
    return parse_oval_element(ET.parse(str(path)).getroot())
