"""OVAL result algebra, comparisons per operation and datatype, criteria logic, existence and check semantics,
variables, sets and filters."""
import pytest

from cyberthunder.scap.oval.evaluator import (COMPLETE, DOES_NOT_EXIST, ERROR, FALSE, NOT_APPLICABLE, NOT_EVALUATED,
                                              TRUE, UNKNOWN, EvalError, Evaluator, combine, combine_check, compare,
                                              compile_pattern, existence, negate)
from cyberthunder.scap.oval.windows_probes import make_collector
from tests.scap.helpers import definition, oval, reg_data, reg_object, reg_state, reg_test

T, F, E, U, NE, NA = TRUE, FALSE, ERROR, UNKNOWN, NOT_EVALUATED, NOT_APPLICABLE


# -- operator truth tables ---------------------------------------------------------------------------------------
@pytest.mark.parametrize("results, expected", [
    ([T, T], T), ([T, F], F), ([F, E], F), ([T, E], E), ([T, U], U), ([T, NE], NE), ([T, NA], T), ([NA, NA], NA),
    ([E, U], E), ([U, NE], U), ([], NA),
])
def test_and(results, expected):
    assert combine("AND", results) == expected


@pytest.mark.parametrize("results, expected", [
    ([F, F], F), ([T, F], T), ([T, E], T), ([F, E], E), ([F, U], U), ([F, NE], NE), ([F, NA], F), ([NA], NA),
])
def test_or(results, expected):
    assert combine("OR", results) == expected


@pytest.mark.parametrize("results, expected", [
    ([T, F, F], T), ([T, T, F], F), ([F, F], F), ([T, E], E), ([F, U], U), ([T, T, E], F),
])
def test_one(results, expected):
    assert combine("ONE", results) == expected


@pytest.mark.parametrize("results, expected", [([T, F], T), ([T, T], F), ([T, T, T], T), ([F, F], F), ([T, E], E)])
def test_xor(results, expected):
    assert combine("XOR", results) == expected


def test_negate_only_flips_true_and_false():
    assert (negate(T), negate(F), negate(E), negate(U), negate(NE), negate(NA)) == (F, T, E, U, NE, NA)


@pytest.mark.parametrize("check, results, expected", [
    ("all", [T, T], T), ("all", [T, F], F), ("at least one", [F, T], T), ("at least one", [F, F], F),
    ("none satisfy", [F, F], T), ("none satisfy", [F, T], F), ("only one", [T, F], T), ("only one", [T, T], F),
    ("none exist", [F], T),
])
def test_check(check, results, expected):
    assert combine_check(check, results) == expected


@pytest.mark.parametrize("ce, exists, missing, errors, expected", [
    ("all_exist", 2, 0, 0, T), ("all_exist", 0, 0, 0, F), ("all_exist", 1, 1, 0, F), ("all_exist", 1, 0, 1, E),
    ("any_exist", 0, 0, 0, T), ("any_exist", 3, 0, 0, T), ("any_exist", 0, 0, 1, E),
    ("at_least_one_exists", 1, 0, 0, T), ("at_least_one_exists", 0, 1, 0, F), ("at_least_one_exists", 0, 0, 1, E),
    ("none_exist", 0, 0, 0, T), ("none_exist", 1, 0, 0, F), ("none_exist", 0, 0, 1, E),
    ("only_one_exists", 1, 0, 0, T), ("only_one_exists", 2, 0, 0, F), ("only_one_exists", 0, 0, 0, F),
])
def test_existence(ce, exists, missing, errors, expected):
    assert existence(ce, exists, missing, errors) == expected


# -- comparisons ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("op, dt, item, state, expected", [
    ("equals", "string", "abc", "abc", True), ("equals", "string", "abc", "ABC", False),
    ("not equal", "string", "abc", "abd", True), ("case insensitive equals", "string", "Administrators", "administrators", True),
    ("case insensitive not equal", "string", "ws01adm", "Administrator", True),
    ("case insensitive not equal", "string", "ADMINISTRATOR", "Administrator", False),
    ("equals", "int", 5, "5", True), ("equals", "int", "0x10", "16", True), ("greater than", "int", 10, "9", True),
    ("greater than or equal", "int", 14, "14", True), ("less than", "int", 3, "3", False),
    ("less than or equal", "int", -1, "0", True), ("not equal", "int", 1, "2", True),
    ("bitwise and", "int", 0b1011, "3", True), ("bitwise and", "int", 0b1001, "3", False),
    ("bitwise or", "int", 1, "3", True), ("bitwise or", "int", 4, "3", False),
    ("equals", "boolean", True, "1", True), ("equals", "boolean", "false", "0", True), ("not equal", "boolean", "1", "0", True),
    ("equals", "float", "1.50", "1.5", True), ("greater than", "float", "2.1", "2", True),
    ("equals", "version", "10.0.22631", "10.0.22631.0", True), ("greater than or equal", "version", "26100", "26100", True),
    ("less than", "version", "10.0.9", "10.0.10", True), ("greater than", "version", "1.10", "1.9", True),
    ("less than", "version", "22631", "26100", True),
    ("equals", "evr_string", "0:1.2-3.el9", "1.2-3.el9", True), ("less than", "evr_string", "1.2-3.el9", "1.10-1.el9", True),
    ("greater than", "evr_string", "1:0.1-1", "0:9.9-9", True), ("less than", "evr_string", "1.0~rc1-1", "1.0-1", True),
    ("equals", "binary", "0a FF", "0AFF", True), ("not equal", "binary", "00", "01", True),
    ("equals", "fileset_revision", "a1", "a1", True), ("equals", "ios_version", "15.2", "15.2.0", True),
    ("pattern match", "string", "WS-01\\Domain Admins", r"^(?i)(.+\\)?domain admins$", True),
    ("pattern match", "string", "NT Authority\\Local account", r"^(?i)(NT Authority\\)?Local account$", True),
    ("pattern match", "string", "S-1-5-21-1-2-3-501", r"^S-1-5-[0-9-]+-501$", True),
    ("pattern match", "string", "S-1-5-21-1-2-3-500", r"^S-1-5-[0-9-]+-501$", False),
    ("pattern match", "string", "abc123", r"(?<digits>\d+)$", True),
    ("pattern match", "string", "middle", "dd", True),
    ("equals", "string", None, None, True), ("equals", "string", "x", None, False), ("not equal", "string", None, "x", True),
])
def test_compare(op, dt, item, state, expected):
    assert compare(op, dt, item, state) is expected


@pytest.mark.parametrize("op, dt, item, state", [
    ("equals", "int", "abc", "1"), ("bitwise and", "string", "1", "1"), ("greater than", "boolean", "1", "0"),
    ("pattern match", "string", "x", "(unclosed"), ("frobnicate", "string", "a", "a"), ("equals", "boolean", "yes", "1"),
])
def test_compare_errors(op, dt, item, state):
    with pytest.raises(EvalError):
        compare(op, dt, item, state)


def test_pattern_translation_moves_inline_flags():
    assert compile_pattern(r"^(?i)abc$").search("ABC")
    assert compile_pattern(r"x(?i)y").flags & 2


# -- criteria, existence and check through real tests ---------------------------------------------------------------
KEY = r"SOFTWARE\Test"


def _doc(criteria: str, extra_defs: str = ""):
    tests = (reg_test("t:one", "o:one", ["s:one"]) + reg_test("t:zero", "o:zero", ["s:one"]) +
             reg_test("t:missing", "o:missing", ["s:one"]) +
             reg_test("t:missing_none", "o:missing", [], existence="none_exist"))
    objects = (reg_object("o:one", KEY, "One") + reg_object("o:zero", KEY, "Zero") + reg_object("o:missing", KEY, "Nope"))
    return oval(definition("d:main", criteria) + extra_defs, tests, objects, reg_state("s:one", "1"))


DATA = reg_data((KEY, {"One": ("DWord", 1), "Zero": ("DWord", 0)}))


@pytest.mark.parametrize("criteria, expected", [
    ('<criteria><criterion test_ref="t:one"/></criteria>', T),
    ('<criteria><criterion test_ref="t:zero"/></criteria>', F),
    ('<criteria><criterion test_ref="t:zero" negate="true"/></criteria>', T),
    ('<criteria operator="OR"><criterion test_ref="t:zero"/><criterion test_ref="t:one"/></criteria>', T),
    ('<criteria negate="true" operator="OR"><criterion test_ref="t:zero"/><criterion test_ref="t:one"/></criteria>', F),
    ('<criteria operator="ONE"><criterion test_ref="t:one"/><criterion test_ref="t:one"/></criteria>', F),
    ('<criteria><criterion test_ref="t:missing"/></criteria>', F),
    ('<criteria><criterion test_ref="t:missing_none"/></criteria>', T),
    ('<criteria><extend_definition definition_ref="d:inner"/></criteria>', T),
    ('<criteria><extend_definition definition_ref="d:inner" negate="true"/></criteria>', F),
    ('<criteria><criteria operator="OR"><criterion test_ref="t:zero"/>'
     '<extend_definition definition_ref="d:inner"/></criteria><criterion test_ref="t:one"/></criteria>', T),
    ('<criteria><extend_definition definition_ref="d:undefined"/></criteria>', E),
    ('<criteria><criterion test_ref="t:undefined"/></criteria>', E),
])
def test_criteria(criteria, expected):
    inner = definition("d:inner", '<criteria><criterion test_ref="t:one"/></criteria>')
    ev = Evaluator(_doc(criteria, inner), make_collector(DATA))
    assert ev.definition("d:main") == expected


def test_circular_extend_definition_is_an_error():
    doc = oval(definition("d:a", '<criteria><extend_definition definition_ref="d:b"/></criteria>') +
               definition("d:b", '<criteria><extend_definition definition_ref="d:a"/></criteria>'))
    assert Evaluator(doc, make_collector({})).definition("d:a") == ERROR


def _multi(check: str, existence_: str = "at_least_one_exists", state_op: str = "AND", states=("s:one",)):
    doc = oval(definition("d", '<criteria><criterion test_ref="t"/></criteria>'),
               reg_test("t", "o", list(states), check=check, existence=existence_, state_operator=state_op),
               reg_object("o", KEY, "^V", name_op="pattern match"),
               reg_state("s:one", "1") + reg_state("s:two", "2"))
    return doc


MULTI = reg_data((KEY, {"V1": ("DWord", 1), "V2": ("DWord", 2), "Other": ("DWord", 1)}))


@pytest.mark.parametrize("check, existence_, state_op, states, expected", [
    ("all", "at_least_one_exists", "AND", ("s:one",), F),
    ("at least one", "at_least_one_exists", "AND", ("s:one",), T),
    ("only one", "at_least_one_exists", "AND", ("s:one",), T),
    ("none satisfy", "at_least_one_exists", "AND", ("s:one",), F),
    ("all", "at_least_one_exists", "OR", ("s:one", "s:two"), T),
    ("all", "at_least_one_exists", "AND", ("s:one", "s:two"), F),
    ("all", "only_one_exists", "AND", ("s:one",), F),
    ("all", "none_exist", "AND", ("s:one",), F),
])
def test_check_and_existence_over_items(check, existence_, state_op, states, expected):
    ev = Evaluator(_multi(check, existence_, state_op, states), make_collector(MULTI))
    assert ev.definition("d") == expected
    assert len(ev.traces["t"].items) == 2


def test_any_exist_with_no_items_is_true():
    doc = _multi("all", "any_exist")
    assert Evaluator(doc, make_collector(reg_data((KEY, {})))).definition("d") == T


def test_not_collected_section_is_unknown():
    ev = Evaluator(_doc('<criteria><criterion test_ref="t:one"/></criteria>'), make_collector({}))
    assert ev.definition("d:main") == UNKNOWN


def test_missing_item_field_does_not_satisfy_state():
    doc = oval(definition("d", '<criteria><criterion test_ref="t"/></criteria>'),
               reg_test("t", "o", ["s"]), reg_object("o", KEY, None), reg_state("s", "1", type_=None))
    assert Evaluator(doc, make_collector(reg_data((KEY, {})))).definition("d") == F


# -- states: entity_check, var_check, subset and superset ------------------------------------------------------
def _multistring(state_xml: str, values, variables: str = ""):
    doc = oval(definition("d", '<criteria><criterion test_ref="t"/></criteria>'),
               reg_test("t", "o", ["s"]), reg_object("o", KEY, "Multi"), state_xml, variables)
    return Evaluator(doc, make_collector(reg_data((KEY, {"Multi": ("MultiString", values)})))).definition("d")


def test_entity_check_over_multi_string_values():
    s_all = '<win:registry_state id="s" version="1"><win:value operation="pattern match">^a</win:value></win:registry_state>'
    s_one = ('<win:registry_state id="s" version="1"><win:value operation="pattern match" entity_check="at least one">'
             '^a</win:value></win:registry_state>')
    assert _multistring(s_all, ["ab", "ac"]) == T
    assert _multistring(s_all, ["ab", "bc"]) == F
    assert _multistring(s_one, ["ab", "bc"]) == T


def test_var_check_and_set_operations():
    var = ('<constant_variable id="v" version="1" datatype="string" comment="c"><value>a</value><value>b</value>'
           '<value>c</value></constant_variable>')
    at_least = ('<win:registry_state id="s" version="1"><win:value var_ref="v" var_check="at least one"/>'
                '</win:registry_state>')
    all_ = '<win:registry_state id="s" version="1"><win:value var_ref="v" var_check="all"/></win:registry_state>'
    subset = '<win:registry_state id="s" version="1"><win:value var_ref="v" operation="subset of"/></win:registry_state>'
    superset = '<win:registry_state id="s" version="1"><win:value var_ref="v" operation="superset of"/></win:registry_state>'
    assert _multistring(at_least, ["a", "b"], var) == T
    assert _multistring(all_, ["a"], var) == F
    assert _multistring(subset, ["a", "c"], var) == T
    assert _multistring(subset, ["a", "z"], var) == F
    assert _multistring(superset, ["a", "b", "c", "d"], var) == T
    assert _multistring(superset, ["a"], var) == F


# -- variables ------------------------------------------------------------------------------------------------------
def test_local_variable_components():
    objects = reg_object("o:tenant", r"(?i)SYSTEM\\Tenant\\[0-9a-f]+", None, key_op="pattern match")
    variables = (
        '<local_variable id="v:concat" version="1" datatype="string" comment="c"><concat>'
        r'<literal_component>SOFTWARE\Policies\</literal_component>'
        '<regex_capture pattern="\\\\([0-9a-f]+)$"><object_component object_ref="o:tenant" item_field="key"/>'
        '</regex_capture><literal_component>\\PIN</literal_component></concat></local_variable>'
        '<local_variable id="v:arith" version="1" datatype="int" comment="c"><arithmetic arithmetic_operation="multiply">'
        '<literal_component>60</literal_component><literal_component>15</literal_component></arithmetic></local_variable>'
        '<local_variable id="v:sub" version="1" datatype="string" comment="c"><substring substring_start="2" '
        'substring_length="3"><literal_component>abcdef</literal_component></substring></local_variable>'
        '<local_variable id="v:split" version="1" datatype="string" comment="c"><unique><split delimiter=",">'
        '<literal_component>a,b,a</literal_component></split></unique></local_variable>'
        '<local_variable id="v:count" version="1" datatype="int" comment="c"><count>'
        '<variable_component var_ref="v:split"/></count></local_variable>'
        '<local_variable id="v:ends" version="1" datatype="string" comment="c"><begin character="\\"><end character="\\">'
        '<literal_component>x</literal_component></end></begin></local_variable>'
        '<local_variable id="v:esc" version="1" datatype="string" comment="c"><escape_regex>'
        '<literal_component>a.b</literal_component></escape_regex></local_variable>'
        '<external_variable id="v:ext" version="1" datatype="string" comment="c"/>'
        '<local_variable id="v:bad" version="1" datatype="string" comment="c"><time_difference>'
        '<literal_component>1</literal_component></time_difference></local_variable>'
    )
    doc = oval(objects=objects, variables=variables)
    data = reg_data((r"SYSTEM\Tenant\abc123", {}), (r"SYSTEM\Other", {}))
    ev = Evaluator(doc, make_collector(data))
    assert ev.variable("v:concat") == ([r"SOFTWARE\Policies\abc123\PIN"], "")
    assert ev.variable("v:arith") == ([900], "")
    assert ev.variable("v:sub") == (["bcd"], "")
    assert ev.variable("v:split") == (["a", "b"], "")
    assert ev.variable("v:count") == ([2], "")
    assert ev.variable("v:ends") == (["\\x\\"], "")
    assert ev.variable("v:esc") == ([r"a\.b"], "")
    assert ev.variable("v:ext")[1]
    assert "not supported" in ev.variable("v:bad")[1]


def test_object_entity_from_variable_and_empty_variable():
    variables = ('<constant_variable id="v" version="1" datatype="string" comment="c"><value>Two</value>'
                 '<value>One</value></constant_variable>'
                 '<local_variable id="v:none" version="1" datatype="string" comment="c"><regex_capture pattern="zzz(.)">'
                 '<literal_component>abc</literal_component></regex_capture></local_variable>')
    objects = ('<win:registry_object id="o" version="1"><win:hive>HKEY_LOCAL_MACHINE</win:hive>'
               f'<win:key>{KEY}</win:key><win:name var_ref="v"/></win:registry_object>'
               '<win:registry_object id="o:none" version="1"><win:hive>HKEY_LOCAL_MACHINE</win:hive>'
               f'<win:key>{KEY}</win:key><win:name var_ref="v:none"/></win:registry_object>')
    doc = oval(objects=objects, variables=variables)
    ev = Evaluator(doc, make_collector(DATA))
    flag, items, _ = ev.items("o")
    assert flag == COMPLETE and [i["name"] for i in items] == ["One"]
    assert ev.items("o:none")[0] == DOES_NOT_EXIST


# -- sets and filters -------------------------------------------------------------------------------------------
def test_sets_and_filters():
    objects = (reg_object("o:all", KEY, ".*", name_op="pattern match") +
               reg_object("o:v", KEY, "^V", name_op="pattern match") +
               '<win:registry_object id="o:union" version="1"><set><object_reference>o:all</object_reference>'
               '<filter action="include">s:one</filter></set></win:registry_object>'
               '<win:registry_object id="o:inter" version="1"><set set_operator="INTERSECTION">'
               '<object_reference>o:all</object_reference><object_reference>o:v</object_reference></set></win:registry_object>'
               '<win:registry_object id="o:comp" version="1"><set set_operator="COMPLEMENT">'
               '<object_reference>o:all</object_reference><object_reference>o:v</object_reference></set></win:registry_object>'
               '<win:registry_object id="o:nested" version="1"><set><set><object_reference>o:v</object_reference>'
               '<filter action="exclude">s:one</filter></set></set></win:registry_object>'
               '<win:registry_object id="o:objfilter" version="1"><win:hive>HKEY_LOCAL_MACHINE</win:hive>'
               f'<win:key>{KEY}</win:key><win:name operation="pattern match">.*</win:name>'
               '<filter action="exclude">s:one</filter></win:registry_object>')
    doc = oval(objects=objects, states=reg_state("s:one", "1"))
    ev = Evaluator(doc, make_collector(MULTI))
    names = lambda oid: sorted(i["name"] for i in ev.items(oid)[1])  # noqa: E731
    assert names("o:union") == ["Other", "V1"]
    assert names("o:inter") == ["V1", "V2"]
    assert names("o:comp") == ["Other"]
    assert names("o:nested") == ["V2"]
    assert names("o:objfilter") == ["V2"]
