"""Small OVAL documents for the evaluator tests, written as XML so the parser is exercised too."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from cyberthunder.scap.oval import parse_oval_element

DEF_NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
WIN_NS = DEF_NS + "#windows"
IND_NS = DEF_NS + "#independent"


def oval(definitions: str = "", tests: str = "", objects: str = "", states: str = "", variables: str = ""):
    """Parse an OVAL document. Windows elements go in the win: prefix, independent ones in ind:."""
    xml = (f'<oval_definitions xmlns="{DEF_NS}" xmlns:win="{WIN_NS}" xmlns:ind="{IND_NS}" '
           f'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
           f"<definitions>{definitions}</definitions><tests>{tests}</tests><objects>{objects}</objects>"
           f"<states>{states}</states><variables>{variables}</variables></oval_definitions>")
    return parse_oval_element(ET.fromstring(xml))


def definition(def_id: str, criteria: str, cls: str = "compliance") -> str:
    return (f'<definition id="{def_id}" version="1" class="{cls}"><metadata><title>{def_id}</title></metadata>'
            f"{criteria}</definition>")


def reg_object(oid: str, key: str, name: str | None, key_op: str = "equals", name_op: str = "equals") -> str:
    n = '<win:name xsi:nil="true"/>' if name is None else f'<win:name operation="{name_op}">{name}</win:name>'
    return (f'<win:registry_object id="{oid}" version="1"><win:hive>HKEY_LOCAL_MACHINE</win:hive>'
            f'<win:key operation="{key_op}">{key}</win:key>{n}</win:registry_object>')


def reg_state(sid: str, value: str, datatype: str = "int", op: str = "equals", type_: str | None = "reg_dword") -> str:
    t = f"<win:type>{type_}</win:type>" if type_ else ""
    return (f'<win:registry_state id="{sid}" version="1">{t}'
            f'<win:value datatype="{datatype}" operation="{op}">{value}</win:value></win:registry_state>')


def reg_test(tid: str, oid: str, states: list[str] = (), check: str = "all",
             existence: str = "at_least_one_exists", state_operator: str = "AND") -> str:
    st = "".join(f'<win:state state_ref="{s}"/>' for s in states)
    return (f'<win:registry_test id="{tid}" version="1" check="{check}" check_existence="{existence}" '
            f'state_operator="{state_operator}" comment="{tid}"><win:object object_ref="{oid}"/>{st}'
            f"</win:registry_test>")


def reg_data(*entries) -> dict:
    """Collected registry data: entries are (key, {name: (kind, value)})."""
    return {"registry": [{"hive": "HKLM", "key": k,
                          "values": [{"name": n, "kind": kv[0], "value": kv[1]} for n, kv in vals.items()]}
                         for k, vals in entries]}
