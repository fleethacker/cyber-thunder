"""Each supported Windows test type against hand-made collected items; unsupported types are never a pass;
the collection planner, including the follow-up round for objects located through variables."""
import pytest

from cyberthunder.scap.oval.evaluator import ERROR, FALSE, NOT_EVALUATED, TRUE, Evaluator, EvalError
from cyberthunder.scap.oval.windows_probes import (SUPPORTED, audit_field, check_wql, key_pattern_prefix,
                                                   make_collector, trustee_name)
from tests.scap.helpers import definition, oval, reg_data, reg_object, reg_state, reg_test


def run(test_xml: str, objects: str, states: str, data: dict, variables: str = "", test_id: str = "t") -> str:
    doc = oval(definition("d", f'<criteria><criterion test_ref="{test_id}"/></criteria>'), test_xml, objects, states,
               variables)
    return Evaluator(doc, make_collector(data)).definition("d")


def simple_test(kind: str, states=("s",), check="all", existence="at_least_one_exists", state_operator="AND",
                ns="win") -> str:
    st = "".join(f'<{ns}:state state_ref="{s}"/>' for s in states)
    return (f'<{ns}:{kind}_test id="t" version="1" check="{check}" check_existence="{existence}" '
            f'state_operator="{state_operator}" comment="t"><{ns}:object object_ref="o"/>{st}</{ns}:{kind}_test>')


# -- registry ---------------------------------------------------------------------------------------------------
LSA = r"SYSTEM\CurrentControlSet\Control\Lsa"


@pytest.mark.parametrize("kind, value, state_value, datatype, type_, expected", [
    ("DWord", 5, "5", "int", "reg_dword", TRUE),
    ("DWord", 2, "5", "int", "reg_dword", FALSE),
    ("String", "5", "5", "int", "reg_dword", FALSE),           # right value, wrong registry type
    ("QWord", 2**40, str(2**40), "int", "reg_qword", TRUE),
    ("String", "Enterprise", "Enterprise", "string", "reg_sz", TRUE),
    ("ExpandString", "%SystemRoot%\\x", "%SystemRoot%\\x", "string", "reg_expand_sz", TRUE),
    ("Binary", "0aff", "0AFF", "binary", "reg_binary", TRUE),
    ("String", "22631", "26100", "version", "reg_sz", FALSE),
])
def test_registry_value_types(kind, value, state_value, datatype, type_, expected):
    data = reg_data((LSA, {"Val": (kind, value)}))
    op = "greater than or equal" if datatype == "version" else "equals"
    got = run(reg_test("t", "o", ["s"]), reg_object("o", LSA, "Val"),
              reg_state("s", state_value, datatype=datatype, op=op, type_=type_), data)
    assert got == expected


def test_registry_multi_string_and_case_insensitive_key():
    data = reg_data((LSA.upper(), {"Multi": ("MultiString", ["System", "Netlogon"])}))
    state = ('<win:registry_state id="s" version="1"><win:type>reg_multi_sz</win:type>'
             '<win:value entity_check="at least one">Netlogon</win:value></win:registry_state>')
    assert run(reg_test("t", "o", ["s"]), reg_object("o", LSA, "Multi"), state, data) == TRUE


def test_registry_key_only_object_and_missing_value():
    data = reg_data((LSA, {}))
    assert run(reg_test("t", "o"), reg_object("o", LSA, None), "", data) == TRUE
    assert run(reg_test("t", "o"), reg_object("o", LSA + r"\Absent", None), "", data) == FALSE
    assert run(reg_test("t", "o", ["s"]), reg_object("o", LSA, "Absent"), reg_state("s", "1"), data) == FALSE


def test_registry_key_pattern_enumerates_subkeys():
    base = r"SOFTWARE\Microsoft\Cryptography\Calais\Readers"
    data = reg_data((base, {}), (base + r"\Reader A", {}), (base + r"\Reader B", {}))
    obj = reg_object("o", r"SOFTWARE\\Microsoft\\Cryptography\\Calais\\Readers\\\S+", None, key_op="pattern match")
    doc = oval(definition("d", '<criteria><criterion test_ref="t"/></criteria>'), reg_test("t", "o"), obj)
    ev = Evaluator(doc, make_collector(data))
    assert ev.definition("d") == TRUE
    assert sorted(i["key"].rsplit("\\", 1)[1] for i in ev.traces["t"].items) == ["Reader A", "Reader B"]


def test_key_pattern_prefix():
    assert key_pattern_prefix(r"(?i)SYSTEM\\CurrentControlSet\\Control\\CloudDomainJoin\\TenantInfo\\[0-9a-f]{8}") == \
        (r"SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo", 1)
    assert key_pattern_prefix(r"^SOFTWARE\\A\\[^\\]+\\B$") == (r"SOFTWARE\A", 2)
    assert key_pattern_prefix(r"SOFTWARE\\A\\.*\\.*\\.*\\.*\\.*") == (r"SOFTWARE\A", 3)
    assert key_pattern_prefix(r"SOFTWARE\\A\\.*\\.*", max_depth=1) == (r"SOFTWARE\A", 1)


# -- account and audit policy -----------------------------------------------------------------------------------
SA = {"system_access": {"MinimumPasswordLength": "14", "PasswordHistorySize": "24", "MaximumPasswordAge": "60",
                        "MinimumPasswordAge": "1", "PasswordComplexity": "1", "ClearTextPassword": "0",
                        "LSAAnonymousNameLookup": "0", "LockoutBadCount": "3", "LockoutDuration": "-1",
                        "ResetLockoutCount": "15"}}
POLICY_OBJ = '<win:{k}_object id="o" version="1"/>'


@pytest.mark.parametrize("kind, field, op, datatype, value, expected", [
    ("passwordpolicy", "min_passwd_len", "greater than or equal", "int", "14", TRUE),
    ("passwordpolicy", "min_passwd_len", "greater than or equal", "int", "15", FALSE),
    ("passwordpolicy", "max_passwd_age", "less than or equal", "int", "15552000", TRUE),
    ("passwordpolicy", "min_passwd_age", "greater than or equal", "int", "86400", TRUE),
    ("passwordpolicy", "password_hist_len", "greater than or equal", "int", "24", TRUE),
    ("passwordpolicy", "password_complexity", "equals", "boolean", "1", TRUE),
    ("passwordpolicy", "reversible_encryption", "equals", "boolean", "0", TRUE),
    ("passwordpolicy", "anonymous_name_lookup", "equals", "boolean", "1", FALSE),
    ("lockoutpolicy", "lockout_threshold", "less than or equal", "int", "3", TRUE),
    ("lockoutpolicy", "lockout_duration", "less than or equal", "int", "0", TRUE),
    ("lockoutpolicy", "lockout_observation_window", "greater than or equal", "int", "900", TRUE),
])
def test_policy_tests(kind, field, op, datatype, value, expected):
    state = (f'<win:{kind}_state id="s" version="1"><win:{field} datatype="{datatype}" operation="{op}">{value}'
             f'</win:{field}></win:{kind}_state>')
    assert run(simple_test(kind), POLICY_OBJ.format(k=kind), state, SA) == expected


def test_policy_falls_back_to_net_accounts():
    data = {"net_accounts": {"Minimum password length": "8", "Lockout threshold": "Never",
                             "Maximum password age (days)": "Unlimited"}}
    state = ('<win:passwordpolicy_state id="s" version="1"><win:min_passwd_len datatype="int" operation="equals">8'
             '</win:min_passwd_len></win:passwordpolicy_state>')
    assert run(simple_test("passwordpolicy"), POLICY_OBJ.format(k="passwordpolicy"), state, data) == TRUE


AUDIT = {"audit": [{"subcategory": "Credential Validation", "setting": "Success and Failure"},
                   {"subcategory": "Logon", "setting": "Failure"}, {"subcategory": "Plug and Play Events", "setting": "Success"},
                   {"subcategory": "Other Logon/Logoff Events", "setting": "No Auditing"}]}


@pytest.mark.parametrize("field, value, expected", [
    ("credential_validation", "AUDIT_SUCCESS_FAILURE", TRUE), ("logon", "AUDIT_SUCCESS", FALSE),
    ("logon", "AUDIT_FAILURE", TRUE), ("pnp_activity", "AUDIT_SUCCESS", TRUE),
    ("other_logon_logoff_events", "AUDIT_NONE", TRUE), ("process_creation", "AUDIT_SUCCESS", FALSE),
])
def test_audit_subcategories(field, value, expected):
    state = (f'<win:auditeventpolicysubcategories_state id="s" version="1"><win:{field}>{value}</win:{field}>'
             f'</win:auditeventpolicysubcategories_state>')
    assert run(simple_test("auditeventpolicysubcategories"),
               POLICY_OBJ.format(k="auditeventpolicysubcategories"), state, AUDIT) == expected


def test_audit_categories_derived_from_subcategories():
    state = ('<win:auditeventpolicy_state id="s" version="1"><win:account_logon>AUDIT_SUCCESS_FAILURE</win:account_logon>'
             '<win:logon>AUDIT_FAILURE</win:logon></win:auditeventpolicy_state>')
    assert run(simple_test("auditeventpolicy"), POLICY_OBJ.format(k="auditeventpolicy"), state, AUDIT) == TRUE


def test_audit_field_names():
    assert audit_field("MPSSVC Rule-Level Policy Change") == "mpssvc_rule_level_policy_change"
    assert audit_field("Other Logon/Logoff Events") == "other_logon_logoff_events"
    assert audit_field("Plug and Play Events") == "pnp_activity"


# -- user rights ------------------------------------------------------------------------------------------------
RIGHTS = {"rights": {
    "SeNetworkLogonRight": [{"sid": "S-1-5-32-544", "name": "BUILTIN\\Administrators"},
                            {"sid": "S-1-5-32-555", "name": "BUILTIN\\Remote Desktop Users"}],
    "SeTcbPrivilege": [],
    "SeDebugPrivilege": [{"sid": "S-1-5-21-1-2-3-1003", "name": "WS-01\\svc_backup"}],
}}
UR_STATES = ('<win:userright_state id="s:none" version="1"><win:trustee_name/></win:userright_state>'
             '<win:userright_state id="s:admins" version="1"><win:trustee_name operation="case insensitive equals">'
             'Administrators</win:trustee_name></win:userright_state>'
             '<win:userright_state id="s:rdu" version="1"><win:trustee_name operation="case insensitive equals">'
             'Remote Desktop Users</win:trustee_name></win:userright_state>')


@pytest.mark.parametrize("right, states, expected", [
    ("SE_NETWORK_LOGON_NAME", ("s:none", "s:admins", "s:rdu"), TRUE),
    ("SE_NETWORK_LOGON_NAME", ("s:none", "s:admins"), FALSE),
    ("SE_TCB_NAME", ("s:none",), TRUE),                      # assigned to nobody
    ("SE_TRUSTED_CREDMAN_ACCESS_NAME", ("s:none",), TRUE),   # not in the export at all
    ("SE_DEBUG_NAME", ("s:admins",), FALSE),
])
def test_userright(right, states, expected):
    obj = f'<win:userright_object id="o" version="1"><win:userright>{right}</win:userright></win:userright_object>'
    assert run(simple_test("userright", states, state_operator="OR"), obj, UR_STATES, RIGHTS) == expected


def test_accesstoken():
    obj = ('<win:accesstoken_object id="o" version="1"><win:security_principle>svc_backup</win:security_principle>'
           '</win:accesstoken_object>')
    state = ('<win:accesstoken_state id="s" version="1"><win:sedebugprivilege datatype="boolean">0</win:sedebugprivilege>'
             '</win:accesstoken_state>')
    assert run(simple_test("accesstoken"), obj, state, RIGHTS) == FALSE
    obj2 = obj.replace("svc_backup", "Administrators")
    state2 = state.replace("sedebugprivilege", "senetworklogonright").replace(">0<", ">1<")
    assert run(simple_test("accesstoken"), obj2, state2, RIGHTS) == TRUE


def test_trustee_name():
    assert trustee_name("BUILTIN\\Administrators") == "Administrators"
    assert trustee_name("NT AUTHORITY\\LOCAL SERVICE") == "LOCAL SERVICE"
    assert trustee_name("RESTRICTED SERVICES\\PrintSpoolerService") == "RESTRICTED SERVICES\\PrintSpoolerService"


# -- accounts ---------------------------------------------------------------------------------------------------
ACCOUNTS = {"accounts": {"computer": "WS-01", "users": [
    {"name": "ws01adm", "sid": "S-1-5-21-1-2-3-500", "enabled": False},
    {"name": "Guest", "sid": "S-1-5-21-1-2-3-501", "enabled": True},
    {"name": "itadmin", "sid": "S-1-5-21-1-2-3-1001", "enabled": True}],
    "groups": [{"name": "Administrators", "sid": "S-1-5-32-544", "members": [{"name": "WS-01\\itadmin",
                                                                            "sid": "S-1-5-21-1-2-3-1001"}]}]}}


def test_sid_sid_with_variable_state():
    obj = ('<win:sid_sid_object id="o" version="1"><win:trustee_sid operation="pattern match">^S-1-5-[0-9-]+-500$'
           '</win:trustee_sid></win:sid_sid_object>')
    states = ('<win:sid_sid_state id="s1" version="1"><win:trustee_name operation="case insensitive not equal">'
              'Administrator</win:trustee_name></win:sid_sid_state>'
              '<win:sid_sid_state id="s2" version="1"><win:trustee_name operation="case insensitive not equal" var_ref="v"/>'
              '</win:sid_sid_state>')
    var = ('<local_variable id="v" version="1" datatype="string" comment="c"><concat>'
           '<object_component object_ref="o" item_field="trustee_domain"/>'
           '<literal_component>\\Administrator</literal_component></concat></local_variable>')
    assert run(simple_test("sid_sid", ("s1", "s2"), existence="any_exist"), obj, states, ACCOUNTS, var) == TRUE
    renamed_back = {"accounts": {**ACCOUNTS["accounts"], "users": [{"name": "Administrator", "sid": "S-1-5-21-1-2-3-500",
                                                                     "enabled": False}]}}
    assert run(simple_test("sid_sid", ("s1", "s2"), existence="any_exist"), obj, states, renamed_back, var) == FALSE


@pytest.mark.parametrize("kind", ["user_sid55", "user_sid"])
def test_user_sid_enabled_and_groups(kind):
    obj = (f'<win:{kind}_object id="o" version="1"><win:user_sid operation="pattern match">-501$</win:user_sid>'
           f'</win:{kind}_object>')
    state = f'<win:{kind}_state id="s" version="1"><win:enabled datatype="boolean">0</win:enabled></win:{kind}_state>'
    assert run(simple_test(kind), obj, state, ACCOUNTS) == FALSE
    obj2 = obj.replace("-501$", "-1001$")
    state2 = f'<win:{kind}_state id="s" version="1"><win:group_sid>S-1-5-32-544</win:group_sid></win:{kind}_state>'
    assert run(simple_test(kind), obj2, state2, ACCOUNTS) == TRUE


# -- files and services -----------------------------------------------------------------------------------------
FILES = {"files": [{"path": "C:\\Windows\\System32\\ntoskrnl.exe", "exists": True, "size": 100,
                    "version": "10.0.22621.2506 (WinBuild.160101.0800)", "product_version": "10.0.22621.2506"},
                   {"path": "C:\\Windows\\System32\\absent.dll", "exists": False}]}


def test_file_existence_and_version():
    obj = ('<win:file_object id="o" version="1"><win:filepath>C:\\Windows\\System32\\ntoskrnl.exe</win:filepath>'
           '</win:file_object>')
    state = ('<win:file_state id="s" version="1"><win:version datatype="version" operation="greater than or equal">'
             '10.0.22621.1</win:version></win:file_state>')
    assert run(simple_test("file"), obj, state, FILES) == TRUE
    obj2 = ('<win:file_object id="o" version="1"><win:path>C:\\Windows\\System32</win:path>'
            '<win:filename>absent.dll</win:filename></win:file_object>')
    assert run(simple_test("file", (), existence="none_exist"), obj2, "", FILES) == TRUE


SERVICES = {"services": [{"name": "RemoteRegistry", "start_type": "Disabled", "status": "Stopped"},
                         {"name": "WinRM", "start_type": "Auto", "status": "Running"}]}


@pytest.mark.parametrize("name, start, state_, expected", [
    ("RemoteRegistry", "SERVICE_DISABLED", "SERVICE_STOPPED", TRUE),
    ("WinRM", "SERVICE_DISABLED", "SERVICE_RUNNING", FALSE),
    ("WinRM", "SERVICE_AUTO_START", "SERVICE_RUNNING", TRUE),
])
def test_service(name, start, state_, expected):
    obj = f'<win:service_object id="o" version="1"><win:service_name>{name}</win:service_name></win:service_object>'
    state = (f'<win:service_state id="s" version="1"><win:start_type>{start}</win:start_type>'
             f'<win:current_state>{state_}</win:current_state></win:service_state>')
    assert run(simple_test("service"), obj, state, SERVICES) == expected


# -- WMI and family ---------------------------------------------------------------------------------------------
def _wmi_obj(kind="wmi57", wql="SELECT DomainRole FROM win32_computersystem"):
    return (f'<win:{kind}_object id="o" version="1"><win:namespace>root\\cimv2</win:namespace>'
            f'<win:wql>{wql}</win:wql></win:{kind}_object>')


def test_wmi57_record_state():
    data = {"wmi": [{"namespace": "root\\cimv2", "wql": "SELECT DomainRole FROM win32_computersystem",
                     "rows": [{"DomainRole": 1}], "error": None}]}
    state = ('<win:wmi57_state id="s" version="1"><win:result datatype="record" operation="equals">'
             '<field xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" name="DomainRole">1</field>'
             '</win:result></win:wmi57_state>')
    assert run(simple_test("wmi57"), _wmi_obj(), state, data) == TRUE
    data["wmi"][0]["rows"] = [{"DomainRole": 0}]
    assert run(simple_test("wmi57"), _wmi_obj(), state, data) == FALSE
    data["wmi"][0]["error"] = "Invalid namespace"
    assert run(simple_test("wmi57"), _wmi_obj(), state, data) == ERROR


def test_wmi_booleans_and_legacy_wmi_test():
    data = {"wmi": [{"namespace": "root\\cimv2", "wql": "SELECT IsEnabled FROM Win32_Tpm", "rows": [{"IsEnabled": True}],
                     "error": None}]}
    state = '<win:wmi_state id="s" version="1"><win:result>1</win:result></win:wmi_state>'
    assert run(simple_test("wmi"), _wmi_obj("wmi", "SELECT IsEnabled FROM Win32_Tpm"), state, data) == TRUE


def test_wql_validation():
    check_wql("root\\cimv2", "SELECT Name FROM Win32_Service WHERE Name = 'x'")
    for ns, wql in [("root\\cimv2", "SELECT * FROM x; del"), ("C:\\", "SELECT a FROM b"),
                    ("root\\cimv2", "ASSOCIATORS OF {x}"), ("root\\cimv2", "SELECT a FROM b WHERE $(x)")]:
        with pytest.raises(EvalError):
            check_wql(ns, wql)


def test_family():
    obj = '<ind:family_object id="o" version="1"/>'
    state = '<ind:family_state id="s" version="1"><ind:family>windows</ind:family></ind:family_state>'
    assert run(simple_test("family", ns="ind"), obj, state, {}) == TRUE


# -- unsupported test types -------------------------------------------------------------------------------------
def test_unsupported_test_type_is_not_evaluated_never_true():
    test = ('<win:fileeffectiverights53_test id="t" version="1" check="all" check_existence="none_exist" comment="t">'
            '<win:object object_ref="o"/></win:fileeffectiverights53_test>')
    obj = ('<win:fileeffectiverights53_object id="o" version="1"><win:filepath>C:\\x</win:filepath>'
           '<win:trustee_sid operation="pattern match">.*</win:trustee_sid></win:fileeffectiverights53_object>')
    doc = oval(definition("d", '<criteria><criterion test_ref="t"/></criteria>'), test, obj)
    ev = Evaluator(doc, make_collector({}))
    assert ev.definition("d") == NOT_EVALUATED
    assert "fileeffectiverights53_test" in ev.traces["t"].note
    assert "fileeffectiverights53" not in SUPPORTED and "registry" in SUPPORTED


def test_unreadable_audit_policy_is_an_error_not_a_failure():
    state = ('<win:auditeventpolicysubcategories_state id="s" version="1"><win:logon>AUDIT_SUCCESS</win:logon>'
             '</win:auditeventpolicysubcategories_state>')
    obj = POLICY_OBJ.format(k="auditeventpolicysubcategories")
    assert run(simple_test("auditeventpolicysubcategories"), obj, state, {"audit": []}) == ERROR
    from cyberthunder.scap.oval.evaluator import UNKNOWN
    assert run(simple_test("auditeventpolicysubcategories"), obj, state, {}) == UNKNOWN
