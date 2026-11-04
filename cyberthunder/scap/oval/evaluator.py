"""OVAL 5.11 evaluation over collected items.

Results follow the OVAL result enumeration: true, false, unknown, error, not evaluated, not applicable.

  definition  criteria tree; operators AND, OR, ONE, XOR; negate on criteria, criterion and extend_definition
  test        check_existence over the collected items, then every item is compared with the test's states
              (combined with state_operator) and the per-item results are combined with `check`
  state       each entity compared with the item field of the same name (combined with the state's operator);
              several item values are combined with entity_check, several variable values with var_check

Items come from a collector: a callable taking (ObjectDef, {entity name: ResolvedEntity}) and returning
(collected flag, [item dict]). Item dicts map field names to a value or a list of values (multi-valued fields
such as reg_multi_sz values or wmi57 result rows). The Windows collector lives in windows_probes.py.

Pattern match uses Python's re with these translations from the Perl/ECMAScript syntax OVAL content uses:
inline flag groups such as (?i) anywhere in the pattern apply to the whole pattern (Python only accepts them at
the start), and named groups (?<name>...) become (?P<name>...). Look-behind, classes, anchors and quantifiers
are passed through unchanged. Matching is a search (unanchored), as OVAL specifies.
"""
from __future__ import annotations

import itertools
import json
import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Callable

from .model import (Component, Criteria, Criterion, Definition, Entity, ExtendDefinition, ObjectDef, OvalDocument,
                    SetDef, StateDef, TestDef)

log = logging.getLogger(__name__)

TRUE, FALSE, UNKNOWN, ERROR = "true", "false", "unknown", "error"
NOT_EVALUATED, NOT_APPLICABLE = "not evaluated", "not applicable"
RESULTS = (TRUE, FALSE, UNKNOWN, ERROR, NOT_EVALUATED, NOT_APPLICABLE)

# collected object flags
COMPLETE, INCOMPLETE, DOES_NOT_EXIST, FLAG_ERROR, NOT_COLLECTED = (
    "complete", "incomplete", "does not exist", "error", "not collected")

OPERATIONS = ("equals", "not equal", "case insensitive equals", "case insensitive not equal", "greater than",
              "greater than or equal", "less than", "less than or equal", "pattern match", "bitwise and",
              "bitwise or", "subset of", "superset of")
DATATYPES = ("string", "int", "float", "boolean", "version", "binary", "evr_string", "debian_evr_string",
             "fileset_revision", "ios_version", "record")


class EvalError(ValueError):
    """A comparison or variable could not be evaluated (bad datatype, bad pattern, unsupported construct)."""


class Unsupported(EvalError):
    """The object's probe is not implemented; the test evaluates to 'not evaluated'."""

    def __init__(self, what: str):
        super().__init__(f"{what} is not supported")
        self.what = what


# -- result algebra --------------------------------------------------------------------------------------
def negate(r: str) -> str:
    return FALSE if r == TRUE else TRUE if r == FALSE else r


def combine(operator: str, results: list[str]) -> str:
    """OVAL operator truth tables. 'not applicable' results are ignored unless all are."""
    rs = [r for r in results if r != NOT_APPLICABLE]
    if not rs:
        return NOT_APPLICABLE
    t, f = rs.count(TRUE), rs.count(FALSE)
    e, u, ne = rs.count(ERROR), rs.count(UNKNOWN), rs.count(NOT_EVALUATED)
    op = operator.upper()

    def uncertain(default: str) -> str:
        return ERROR if e else UNKNOWN if u else NOT_EVALUATED if ne else default

    if op == "AND":
        return FALSE if f else uncertain(TRUE)
    if op == "OR":
        return TRUE if t else uncertain(FALSE)
    if op == "ONE":
        if t >= 2:
            return FALSE
        if e or u or ne:
            return uncertain(FALSE)
        return TRUE if t == 1 else FALSE
    if op == "XOR":
        return uncertain(TRUE if t % 2 == 1 else FALSE)
    raise EvalError(f"unknown operator {operator!r}")


def combine_check(check: str, results: list[str]) -> str:
    """check / entity_check / var_check: all, at least one, none satisfy, only one."""
    c = check.lower().replace("_", " ")
    if c == "all":
        return combine("AND", results)
    if c == "at least one":
        return combine("OR", results)
    if c in ("none satisfy", "none exist"):
        return negate(combine("OR", results))
    if c == "only one":
        return combine("ONE", results)
    raise EvalError(f"unknown check {check!r}")


def existence(check_existence: str, exists: int, missing: int = 0, errors: int = 0) -> str:
    """check_existence over item statuses (exists / does not exist / error)."""
    c = check_existence.lower()
    if c == "all_exist":
        if errors:
            return ERROR
        return TRUE if exists and not missing else FALSE
    if c == "any_exist":
        return ERROR if errors and not exists else TRUE
    if c == "at_least_one_exists":
        if exists:
            return TRUE
        return ERROR if errors else FALSE
    if c == "none_exist":
        if exists:
            return FALSE
        return ERROR if errors else TRUE
    if c == "only_one_exists":
        if exists > 1:
            return FALSE
        if errors:
            return ERROR
        return TRUE if exists == 1 else FALSE
    raise EvalError(f"unknown check_existence {check_existence!r}")


# -- datatypes and operations --------------------------------------------------------------------------------
_FLAG_RE = re.compile(r"\(\?([aimsux]+)\)")
_NAMED_RE = re.compile(r"\(\?<(?![=!])([A-Za-z_][A-Za-z0-9_]*)>")


@lru_cache(maxsize=4096)
def compile_pattern(pattern: str) -> re.Pattern:
    flags = 0
    for m in _FLAG_RE.finditer(pattern):
        for ch in m.group(1):
            flags |= {"i": re.I, "m": re.M, "s": re.S, "x": re.X, "a": re.A, "u": 0}[ch]
    body = _NAMED_RE.sub(r"(?P<\1>", _FLAG_RE.sub("", pattern))
    try:
        return re.compile(body, flags)
    except re.error as e:
        raise EvalError(f"pattern {pattern!r} is not supported: {e}") from None


def _to_int(v) -> int:
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    s = str(v).strip()
    try:
        return int(s, 16) if s.lower().startswith(("0x", "-0x")) else int(s)
    except ValueError:
        try:
            f = float(s)
        except ValueError:
            raise EvalError(f"{v!r} is not an int") from None
        if f != int(f):
            raise EvalError(f"{v!r} is not an int") from None
        return int(f)


def _to_bool(v) -> bool:
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("1", "true"):
        return True
    if s in ("0", "false"):
        return False
    raise EvalError(f"{v!r} is not a boolean")


def _version_key(v) -> list:
    parts = [p for p in re.split(r"[.\-_:]", str(v).strip()) if p != ""]
    out = []
    for p in parts:
        out.append((0, int(p), "") if p.isdigit() else (1, 0, p))
    return out


def _cmp_version(a, b) -> int:
    ka, kb = _version_key(a), _version_key(b)
    n = max(len(ka), len(kb))
    ka += [(0, 0, "")] * (n - len(ka))
    kb += [(0, 0, "")] * (n - len(kb))
    return (ka > kb) - (ka < kb)


def _rpmvercmp(a: str, b: str) -> int:
    """The segment comparison rpm uses for version and release strings."""
    if a == b:
        return 0
    sa = re.findall(r"~|\^|[0-9]+|[A-Za-z]+", a)
    sb = re.findall(r"~|\^|[0-9]+|[A-Za-z]+", b)
    while sa or sb:
        x = sa.pop(0) if sa else None
        y = sb.pop(0) if sb else None
        if x == "~" or y == "~":
            if x != y:
                return -1 if x == "~" else 1
            continue
        if x is None:
            return -1
        if y is None:
            return 1
        if x.isdigit() and y.isdigit():
            c = (int(x) > int(y)) - (int(x) < int(y))
        elif x.isdigit():
            return 1
        elif y.isdigit():
            return -1
        else:
            c = (x > y) - (x < y)
        if c:
            return c
    return 0


def _split_evr(v: str) -> tuple[int, str, str]:
    s = str(v).strip()
    epoch = 0
    if ":" in s:
        e, s = s.split(":", 1)
        epoch = _to_int(e or "0")
    ver, _, rel = s.partition("-")
    return epoch, ver, rel


def _cmp_evr(a, b) -> int:
    ea, va, ra = _split_evr(a)
    eb, vb, rb = _split_evr(b)
    if ea != eb:
        return (ea > eb) - (ea < eb)
    return _rpmvercmp(va, vb) or _rpmvercmp(ra, rb)


def _norm_binary(v) -> str:
    return re.sub(r"[\s,]", "", str(v)).lower()


def _ordered(op: str, c: int) -> bool:
    return {"greater than": c > 0, "greater than or equal": c >= 0, "less than": c < 0,
            "less than or equal": c <= 0, "equals": c == 0, "not equal": c != 0}[op]


def compare(operation: str, datatype: str, item_value, state_value) -> bool:
    """item_value <operation> state_value under the datatype. Raises EvalError when not comparable."""
    op = operation.lower()
    dt = (datatype or "string").lower()
    if op not in OPERATIONS:
        raise EvalError(f"operation {operation!r} is not supported")
    if item_value is None or state_value is None:
        if op in ("equals", "case insensitive equals"):
            return item_value is None and state_value is None
        if op in ("not equal", "case insensitive not equal"):
            return not (item_value is None and state_value is None)
        return False
    if op == "pattern match":
        return compile_pattern(str(state_value)).search(str(item_value)) is not None
    if dt == "int":
        a, b = _to_int(item_value), _to_int(state_value)
        if op == "bitwise and":
            return (a & b) == b
        if op == "bitwise or":
            return (a | b) == b
        if op.startswith("case insensitive "):
            op = op[len("case insensitive "):]
        return _ordered(op, (a > b) - (a < b))
    if op in ("bitwise and", "bitwise or"):
        raise EvalError(f"{operation} needs datatype int, not {datatype}")
    if dt == "float":
        try:
            a, b = float(item_value), float(state_value)
        except ValueError:
            raise EvalError(f"{item_value!r} or {state_value!r} is not a float") from None
        return _ordered(op.replace("case insensitive ", ""), (a > b) - (a < b))
    if dt == "boolean":
        a, b = _to_bool(item_value), _to_bool(state_value)
        if op in ("equals", "case insensitive equals"):
            return a == b
        if op in ("not equal", "case insensitive not equal"):
            return a != b
        raise EvalError(f"{operation} is not defined for booleans")
    if dt in ("version", "ios_version"):
        return _ordered(op.replace("case insensitive ", ""), _cmp_version(item_value, state_value))
    if dt in ("evr_string", "debian_evr_string"):
        return _ordered(op.replace("case insensitive ", ""), _cmp_evr(item_value, state_value))
    if dt == "binary":
        a, b = _norm_binary(item_value), _norm_binary(state_value)
        if op in ("equals", "case insensitive equals"):
            return a == b
        if op in ("not equal", "case insensitive not equal"):
            return a != b
        raise EvalError(f"{operation} is not defined for binary")
    # string, fileset_revision and anything else compares as text
    a, b = str(item_value), str(state_value)
    if op == "equals":
        return a == b
    if op == "not equal":
        return a != b
    if op == "case insensitive equals":
        return a.casefold() == b.casefold()
    if op == "case insensitive not equal":
        return a.casefold() != b.casefold()
    return _ordered(op, (a > b) - (a < b))


def _as_list(v) -> list:
    return list(v) if isinstance(v, (list, tuple)) else [v]


@dataclass
class ResolvedEntity:
    """An object entity with its variable reference resolved to concrete values."""
    entity: Entity
    values: list = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.entity.name

    @property
    def operation(self) -> str:
        return self.entity.operation

    @property
    def nil(self) -> bool:
        return self.entity.nil

    def matches(self, item_value, *, case_insensitive: bool = False) -> bool:
        """True when the item value satisfies this object entity for at least one of its values."""
        op = self.entity.operation
        if case_insensitive and op in ("equals", "not equal"):
            op = "case insensitive " + op
        try:
            return any(compare(op, self.entity.datatype, item_value, v) for v in self.values)
        except EvalError:
            return False

    @property
    def literal(self) -> bool:
        """The entity names exactly one known value (no pattern, no inequality)."""
        return self.entity.operation in ("equals", "case insensitive equals") and len(self.values) == 1


Collector = Callable[[ObjectDef, dict], tuple[str, list[dict]]]


@dataclass
class TestTrace:
    test_id: str
    type: str
    comment: str
    result: str = NOT_EVALUATED
    flag: str = ""
    items: list[dict] = field(default_factory=list)
    item_results: list[str] = field(default_factory=list)
    note: str = ""


class Evaluator:
    """Evaluates definitions of one OvalDocument against one host's collected data. Caches everything, so
    each object is collected and each test evaluated once per evaluator."""

    def __init__(self, doc: OvalDocument, collector: Collector):
        self.doc = doc
        self.collector = collector
        self._items: dict[str, tuple[str, list[dict], str]] = {}
        self._vars: dict[str, tuple[list, str]] = {}
        self._tests: dict[str, str] = {}
        self._defs: dict[str, str] = {}
        self._defs_active: set[str] = set()
        self.traces: dict[str, TestTrace] = {}

    # -- definitions ----------------------------------------------------------------------------------
    def definition(self, def_id: str) -> str:
        if def_id in self._defs:
            return self._defs[def_id]
        d = self.doc.definitions.get(def_id)
        if d is None:
            return ERROR
        if def_id in self._defs_active:      # circular extend_definition
            return ERROR
        self._defs_active.add(def_id)
        try:
            r = self.criteria(d.criteria) if d.criteria else UNKNOWN
        finally:
            self._defs_active.discard(def_id)
        self._defs[def_id] = r
        return r

    def criteria(self, c: Criteria | Criterion | ExtendDefinition) -> str:
        if isinstance(c, Criterion):
            r = self.test(c.test_ref)
        elif isinstance(c, ExtendDefinition):
            r = self.definition(c.definition_ref)
        else:
            r = combine(c.operator, [self.criteria(ch) for ch in c.children]) if c.children else UNKNOWN
        return negate(r) if c.negate else r

    # -- tests ------------------------------------------------------------------------------------------
    def test(self, test_id: str) -> str:
        if test_id in self._tests:
            return self._tests[test_id]
        t = self.doc.tests.get(test_id)
        if t is None:
            self._tests[test_id] = ERROR
            return ERROR
        trace = TestTrace(test_id, t.type, t.comment)
        self.traces[test_id] = trace
        try:
            r = self._test(t, trace)
        except Unsupported as e:
            r, trace.note = NOT_EVALUATED, str(e)
        except EvalError as e:
            r, trace.note = ERROR, str(e)
        trace.result = r
        self._tests[test_id] = r
        return r

    def _test(self, t: TestDef, trace: TestTrace) -> str:
        if not t.object_ref:
            # tests without an object (unknown_test) are not decided
            return UNKNOWN
        flag, items, note = self.items(t.object_ref)
        trace.flag, trace.items, trace.note = flag, items, note
        if flag == NOT_COLLECTED:
            if note.startswith("unsupported:"):
                raise Unsupported(note.split(":", 1)[1].strip())
            return UNKNOWN
        if flag == FLAG_ERROR:
            return ERROR
        exists = len(items)
        ex = existence(t.check_existence, exists, 1 if flag == DOES_NOT_EXIST else 0)
        if flag == INCOMPLETE and ex == FALSE and t.check_existence in ("at_least_one_exists", "all_exist"):
            # more items may exist than were collected
            ex = UNKNOWN
        if ex != TRUE or not t.state_refs:
            return ex
        if not items:
            return TRUE
        states = []
        for sid in t.state_refs:
            s = self.doc.states.get(sid)
            if s is None:
                raise EvalError(f"state {sid} is not defined")
            states.append(s)
        item_results = []
        for it in items:
            item_results.append(combine(t.state_operator, [self.state(s, it) for s in states]))
        trace.item_results = item_results
        r = combine_check(t.check, item_results)
        if flag == INCOMPLETE and r == TRUE and t.check.lower() == "all":
            r = UNKNOWN
        return r

    # -- states -----------------------------------------------------------------------------------------
    def state(self, s: StateDef, item: dict) -> str:
        results = []
        for e in s.entities:
            try:
                results.append(self.state_entity(e, item))
            except EvalError:
                results.append(ERROR)
        return combine(s.operator, results) if results else TRUE

    def state_entity(self, e: Entity, item: dict) -> str:
        if e.name not in item:
            # the item has no such field: the state entity does not hold
            return FALSE
        item_values = _as_list(item[e.name])
        if e.var_ref:
            want, err = self.variable(e.var_ref)
            if err:
                return ERROR
            if not want:
                return ERROR
        else:
            want = [None if e.nil else e.value]
        op = e.operation.lower()
        if op in ("subset of", "superset of"):
            have = {str(v) for v in item_values}
            ref = {str(v) for v in want}
            return TRUE if (have <= ref if op == "subset of" else have >= ref) else FALSE
        if e.datatype == "record" or e.fields:
            per_value = [self._record(e, v) for v in item_values]
        else:
            per_value = []
            for v in item_values:
                per_var = [TRUE if compare(e.operation, e.datatype, v, w) else FALSE for w in want]
                per_value.append(combine_check(e.var_check, per_var) if len(per_var) > 1 else per_var[0])
        if not per_value:
            return FALSE
        return combine_check(e.entity_check, per_value)

    def _record(self, e: Entity, row) -> str:
        if not isinstance(row, dict):
            return ERROR
        row_l = {str(k).lower(): v for k, v in row.items()}
        results = []
        for f in e.fields:
            if f.name not in row_l:
                results.append(FALSE)
                continue
            vals = _as_list(row_l[f.name])
            per = [TRUE if compare(f.operation, f.datatype, v, None if f.nil else f.value) else FALSE for v in vals]
            results.append(combine_check(f.entity_check, per) if per else FALSE)
        return combine("AND", results) if results else TRUE

    # -- objects ----------------------------------------------------------------------------------------
    def items(self, object_id: str) -> tuple[str, list[dict], str]:
        """(flag, items, note) for one object; sets and filters applied."""
        if object_id in self._items:
            return self._items[object_id]
        self._items[object_id] = (FLAG_ERROR, [], "circular object reference")
        o = self.doc.objects.get(object_id)
        if o is None:
            res = (FLAG_ERROR, [], f"object {object_id} is not defined")
        else:
            try:
                res = self._collect(o)
            except Unsupported as e:
                res = (NOT_COLLECTED, [], f"unsupported: {e.what}")
            except EvalError as e:
                res = (FLAG_ERROR, [], str(e))
        self._items[object_id] = res
        return res

    def _collect(self, o: ObjectDef) -> tuple[str, list[dict], str]:
        if o.set is not None:
            flag, items = self._set(o.set)
            note = ""
        else:
            resolved: dict[str, ResolvedEntity] = {}
            for e in o.entities:
                if e.var_ref:
                    vals, err = self.variable(e.var_ref)
                    if err:
                        return FLAG_ERROR, [], f"variable {e.var_ref}: {err}"
                    if not vals:
                        return DOES_NOT_EXIST, [], f"variable {e.var_ref} has no values"
                    resolved[e.name] = ResolvedEntity(e, list(vals))
                else:
                    resolved[e.name] = ResolvedEntity(e, [None if e.nil else e.value])
            out = self.collector(o, resolved)
            flag, items = out[0], out[1]
            note = out[2] if len(out) > 2 else ""
        if o.filters and items:
            items = self._filter(items, o.filters)
        if flag == COMPLETE and not items:
            flag = DOES_NOT_EXIST
        return flag, items, note

    def _filter(self, items: list[dict], filters: list[tuple[str, str]]) -> list[dict]:
        out = []
        for it in items:
            keep = True
            for action, sid in filters:
                s = self.doc.states.get(sid)
                if s is None:
                    raise EvalError(f"filter state {sid} is not defined")
                hit = self.state(s, it) == TRUE
                if (action == "include" and not hit) or (action == "exclude" and hit):
                    keep = False
                    break
            if keep:
                out.append(it)
        return out

    @staticmethod
    def _key(item: dict) -> str:
        return json.dumps(item, sort_keys=True, default=str)

    def _set(self, s: SetDef) -> tuple[str, list[dict]]:
        groups: list[tuple[str, list[dict]]] = []
        for oid in s.object_refs:
            flag, items, _ = self.items(oid)
            if flag == NOT_COLLECTED:
                o = self.doc.objects.get(oid)
                raise Unsupported(o.type if o else oid)
            groups.append((flag, items))
        for sub in s.sets:
            groups.append(self._set(sub))
        if s.filters:
            groups = [(f, self._filter(items, s.filters)) for f, items in groups]
        flags = [g[0] for g in groups]
        if FLAG_ERROR in flags:
            return FLAG_ERROR, []
        op = s.operator.upper()
        if not groups:
            return DOES_NOT_EXIST, []
        if op == "UNION" or len(groups) == 1:
            seen, out = set(), []
            for _, items in groups:
                for it in items:
                    k = self._key(it)
                    if k not in seen:
                        seen.add(k)
                        out.append(it)
        elif op == "INTERSECTION":
            keys = set.intersection(*[{self._key(i) for i in items} for _, items in groups])
            out = [i for i in groups[0][1] if self._key(i) in keys]
        elif op == "COMPLEMENT":
            drop = {self._key(i) for i in groups[1][1]}
            out = [i for i in groups[0][1] if self._key(i) not in drop]
        else:
            raise EvalError(f"set_operator {s.operator!r} is not supported")
        flag = INCOMPLETE if INCOMPLETE in flags else COMPLETE
        return (flag if out else DOES_NOT_EXIST), out

    # -- variables --------------------------------------------------------------------------------------
    def variable(self, var_id: str) -> tuple[list, str]:
        """(values, error). error is '' when the variable resolved (possibly to no values)."""
        if var_id in self._vars:
            return self._vars[var_id]
        self._vars[var_id] = ([], "circular variable reference")
        v = self.doc.variables.get(var_id)
        if v is None:
            res = ([], f"variable {var_id} is not defined")
        elif v.kind == "constant":
            res = (list(v.values), "")
        elif v.kind == "external":
            res = ([], "external variables are not supported (no values are supplied with the benchmark)")
        elif v.component is None:
            res = ([], "local variable has no component")
        else:
            try:
                res = (self.component(v.component), "")
            except Unsupported as e:
                res = ([], f"{e.what} is not supported")
            except EvalError as e:
                res = ([], str(e))
        self._vars[var_id] = res
        return res

    def component(self, c: Component) -> list:
        k = c.kind
        if k == "literal_component":
            return [c.text or ""]
        if k == "object_component":
            flag, items, note = self.items(c.attrs.get("object_ref", ""))
            if flag == NOT_COLLECTED and note.startswith("unsupported:"):
                raise Unsupported(note.split(":", 1)[1].strip())
            if flag == FLAG_ERROR:
                raise EvalError(f"object {c.attrs.get('object_ref')}: {note or 'collection error'}")
            fname = c.attrs.get("item_field", "")
            rfield = (c.attrs.get("record_field") or "").lower()
            out = []
            for it in items:
                for v in _as_list(it.get(fname)):
                    if rfield and isinstance(v, dict):
                        v = {str(a).lower(): b for a, b in v.items()}.get(rfield)
                    if v is not None and not isinstance(v, dict):
                        out.append(v)
            return out
        if k == "variable_component":
            vals, err = self.variable(c.attrs.get("var_ref", ""))
            if err:
                raise EvalError(err)
            return vals
        kids = [self.component(ch) for ch in c.children]
        if k == "concat":
            return ["".join(str(x) for x in combo) for combo in itertools.product(*kids)] if kids else []
        if k == "arithmetic":
            op = (c.attrs.get("arithmetic_operation") or "add").lower()
            out = []
            for combo in itertools.product(*kids):
                nums = [float(x) if "." in str(x) else _to_int(x) for x in combo]
                acc = nums[0] if nums else 0
                for n in nums[1:]:
                    acc = acc + n if op == "add" else acc * n
                out.append(acc)
            return out
        flat = [x for group in kids for x in group]
        if k == "regex_capture":
            rx = compile_pattern(c.attrs.get("pattern", ""))
            out = []
            for x in flat:
                m = rx.search(str(x))
                if m:
                    out.append(m.group(1) if m.re.groups and m.group(1) is not None else m.group(0))
            return out
        if k == "substring":
            start = max(int(c.attrs.get("substring_start", "1")), 1) - 1
            length = int(c.attrs.get("substring_length", "-1"))
            return [str(x)[start:] if length < 0 else str(x)[start:start + length] for x in flat]
        if k == "begin":
            ch = c.attrs.get("character", "")
            return [str(x) if str(x).startswith(ch) else ch + str(x) for x in flat]
        if k == "end":
            ch = c.attrs.get("character", "")
            return [str(x) if str(x).endswith(ch) else str(x) + ch for x in flat]
        if k == "split":
            d = c.attrs.get("delimiter", "")
            return [p for x in flat for p in (str(x).split(d) if d else [str(x)])]
        if k == "unique":
            return list(dict.fromkeys(flat))
        if k == "count":
            return [len(flat)]
        if k == "escape_regex":
            return [re.escape(str(x)) for x in flat]
        raise Unsupported(f"variable component {k}")

    # -- helpers for callers ----------------------------------------------------------------------------
    def traces_for(self, def_id: str) -> list[TestTrace]:
        """Traces of every test the definition reached, in document order of first evaluation."""
        c = self.doc.closure([def_id])
        return [t for tid, t in self.traces.items() if tid in c["tests"]]


def evaluate_definition(doc: OvalDocument, def_id: str, collector: Collector) -> str:
    return Evaluator(doc, collector).definition(def_id)


def definition_title(d: Definition | None) -> str:
    return d.title if d else ""
