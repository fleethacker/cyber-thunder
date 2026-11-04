"""OVAL 5.11 definitions model: just what evaluation needs, independent of XML namespaces.

A definition holds a criteria tree whose leaves are tests (criterion) or other definitions (extend_definition).
A test names one object (what to collect) and zero or more states (what the collected items must look like).
Objects and states are lists of entities; an entity is one element such as <hive>, <key> or <value> with its
operation, datatype and an optional variable reference.
"""
from __future__ import annotations

from dataclasses import dataclass, field

KINDS = ("definitions", "tests", "objects", "states", "variables")


@dataclass
class Entity:
    name: str
    value: str | None = None            # element text; None when xsi:nil
    datatype: str = "string"
    operation: str = "equals"
    var_ref: str | None = None
    var_check: str = "all"
    entity_check: str = "all"
    nil: bool = False
    fields: list["Entity"] = field(default_factory=list)   # record datatype (wmi57 result): one entity per field


@dataclass
class SetDef:
    operator: str = "UNION"              # UNION | INTERSECTION | COMPLEMENT
    object_refs: list[str] = field(default_factory=list)
    sets: list["SetDef"] = field(default_factory=list)
    filters: list[tuple[str, str]] = field(default_factory=list)   # (include|exclude, state id)


@dataclass
class ObjectDef:
    id: str
    type: str                            # element name, e.g. registry_object
    family: str = ""                     # windows | independent | unix | ...
    entities: list[Entity] = field(default_factory=list)
    behaviors: dict[str, str] = field(default_factory=dict)
    set: SetDef | None = None
    filters: list[tuple[str, str]] = field(default_factory=list)
    comment: str = ""

    @property
    def probe(self) -> str:
        return self.type[:-len("_object")] if self.type.endswith("_object") else self.type

    def entity(self, name: str) -> Entity | None:
        return next((e for e in self.entities if e.name == name), None)


@dataclass
class StateDef:
    id: str
    type: str
    family: str = ""
    entities: list[Entity] = field(default_factory=list)
    operator: str = "AND"
    comment: str = ""


@dataclass
class TestDef:
    id: str
    type: str                            # element name, e.g. registry_test
    family: str = ""
    object_ref: str | None = None
    state_refs: list[str] = field(default_factory=list)
    check: str = "all"
    check_existence: str = "at_least_one_exists"
    state_operator: str = "AND"
    comment: str = ""

    @property
    def probe(self) -> str:
        return self.type[:-len("_test")] if self.type.endswith("_test") else self.type


@dataclass
class Criterion:
    test_ref: str
    negate: bool = False
    comment: str = ""


@dataclass
class ExtendDefinition:
    definition_ref: str
    negate: bool = False
    comment: str = ""


@dataclass
class Criteria:
    operator: str = "AND"                # AND | OR | ONE | XOR
    negate: bool = False
    children: list["Criteria | Criterion | ExtendDefinition"] = field(default_factory=list)
    comment: str = ""


@dataclass
class Definition:
    id: str
    cls: str = "compliance"
    title: str = ""
    criteria: Criteria | None = None


@dataclass
class Component:
    """One node of a local_variable: literal_component, object_component, concat, regex_capture, ..."""
    kind: str
    attrs: dict[str, str] = field(default_factory=dict)
    text: str | None = None
    children: list["Component"] = field(default_factory=list)


@dataclass
class Variable:
    id: str
    kind: str                            # constant | local | external
    datatype: str = "string"
    values: list[str] = field(default_factory=list)       # constant_variable
    component: Component | None = None                     # local_variable
    comment: str = ""


@dataclass
class OvalDocument:
    definitions: dict[str, Definition] = field(default_factory=dict)
    tests: dict[str, TestDef] = field(default_factory=dict)
    objects: dict[str, ObjectDef] = field(default_factory=dict)
    states: dict[str, StateDef] = field(default_factory=dict)
    variables: dict[str, Variable] = field(default_factory=dict)

    def merge(self, other: "OvalDocument") -> None:
        for name in KINDS:
            getattr(self, name).update(getattr(other, name))

    def counts(self) -> dict[str, int]:
        return {name: len(getattr(self, name)) for name in KINDS}

    # -- reference walking ------------------------------------------------------------------------------
    def closure(self, definition_ids) -> dict[str, set[str]]:
        """Every definition, test, object, state and variable reachable from the given definitions."""
        out: dict[str, set[str]] = {k: set() for k in KINDS}
        todo = {k: [] for k in KINDS}
        todo["definitions"].extend(definition_ids)

        def crit_walk(c):
            if isinstance(c, Criteria):
                for ch in c.children:
                    crit_walk(ch)
            elif isinstance(c, Criterion):
                todo["tests"].append(c.test_ref)
            elif isinstance(c, ExtendDefinition):
                todo["definitions"].append(c.definition_ref)

        def ent_vars(entities):
            for e in entities:
                if e.var_ref:
                    todo["variables"].append(e.var_ref)
                ent_vars(e.fields)

        def set_walk(s: SetDef):
            todo["objects"].extend(s.object_refs)
            todo["states"].extend(sid for _, sid in s.filters)
            for sub in s.sets:
                set_walk(sub)

        def comp_walk(c: Component):
            if c.kind == "object_component" and c.attrs.get("object_ref"):
                todo["objects"].append(c.attrs["object_ref"])
            if c.kind == "variable_component" and c.attrs.get("var_ref"):
                todo["variables"].append(c.attrs["var_ref"])
            for ch in c.children:
                comp_walk(ch)

        while any(todo.values()):
            kind = next(k for k in KINDS if todo[k])
            ref = todo[kind].pop()
            if ref in out[kind]:
                continue
            out[kind].add(ref)
            if kind == "definitions":
                d = self.definitions.get(ref)
                if d and d.criteria:
                    crit_walk(d.criteria)
            elif kind == "tests":
                t = self.tests.get(ref)
                if t:
                    if t.object_ref:
                        todo["objects"].append(t.object_ref)
                    todo["states"].extend(t.state_refs)
            elif kind == "objects":
                o = self.objects.get(ref)
                if o:
                    ent_vars(o.entities)
                    if o.set:
                        set_walk(o.set)
                    todo["states"].extend(sid for _, sid in o.filters)
            elif kind == "states":
                s = self.states.get(ref)
                if s:
                    ent_vars(s.entities)
            else:
                v = self.variables.get(ref)
                if v and v.component:
                    comp_walk(v.component)
        return out

    def probes(self, definition_ids) -> set[str]:
        """Probe names (registry, userright, ...) whose items a set of definitions depends on: every object
        reached through a test, a set or a variable has to be collected by some probe."""
        c = self.closure(definition_ids)
        return {self.objects[o].probe for o in c["objects"] if o in self.objects}

    def missing(self, definition_ids) -> list[str]:
        """References that do not resolve inside this document."""
        c = self.closure(definition_ids)
        out = []
        for kind, ids in c.items():
            have = getattr(self, kind)
            out.extend(f"{kind[:-1]} {i}" for i in sorted(ids) if i not in have)
        return out
