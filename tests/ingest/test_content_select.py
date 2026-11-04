from __future__ import annotations

from cyberthunder.ingest.content import index as ix
from cyberthunder.ingest.content.select import products_for, select
from cyberthunder.inventory.targets import Target
from tests.ingest.content_helpers import SNAPSHOT


def T(tid, asset_type, **kw):
    return Target(id=tid, name=tid, asset_type=asset_type, transport=kw.pop("transport", "fixture"), **kw)


def facts(**f):
    return {"facts": f}


INVENTORY = [
    T("ws01", "windows", transport="winrm"),
    T("dc01", "windows", transport="winrm", tags=["dc"]),
    T("rhel9", "linux"),
    T("rocky9", "linux"),
    T("sw01", "cisco_ios", tags=["switch"]),
    T("k8s", "kubernetes", transport="kubeconfig"),
    T("docker", "containers"),
    T("mystery", "linux"),
    T("nofacts", "windows", transport="winrm", options={"stig_products": ["MS_Windows_Server_2025"]}),
]
COLLECTED = {
    "ws01": facts(os_name="Microsoft Windows 11 Enterprise", os_version="10.0.22631"),
    "dc01": facts(os_name="Microsoft Windows Server 2022 Datacenter", os_version="10.0.20348"),
    "rhel9": facts(os_name="Red Hat Enterprise Linux", os_version="9.4", model="rhel"),
    "rocky9": facts(os_name="Rocky Linux", os_version="9.4", model="rocky"),
    "sw01": facts(os_name="Cisco IOS", os_version="15.2(7)E8"),
    "mystery": facts(os_name="Plan 9", os_version="4"),
}


def entries():
    return ix.load_snapshot(SNAPSHOT)


def test_product_rules():
    got = {t.id: products_for(t, COLLECTED.get(t.id))[0] for t in INVENTORY}
    assert got["ws01"] == ["MS_Windows_11"]
    assert got["dc01"] == ["MS_Windows_Server_2022", "Active_Directory_Domain", "Active_Directory_Forest"]
    assert got["rhel9"] == ["RHEL_9"] and got["rocky9"] == ["RHEL_9"]
    assert got["sw01"] == ["Cisco_IOS_Switch"]
    assert got["k8s"] == ["Kubernetes"] and got["docker"] == ["Container_Platform"]
    assert got["mystery"] == [] and got["nofacts"] == ["MS_Windows_Server_2025"]


def test_more_platforms():
    cases = [
        ("linux", dict(os_name="AlmaLinux", os_version="8.10", model="almalinux"), ["RHEL_8"]),
        ("linux", dict(os_name="Oracle Linux Server", os_version="9.3", model="ol"), ["Oracle_Linux_9"]),
        ("linux", dict(os_name="Ubuntu", os_version="24.04", model="ubuntu"), ["CAN_Ubuntu_24-04"]),
        ("linux", dict(os_name="Ubuntu", os_version="20.04", model="ubuntu"), ["CAN_Ubuntu_20-04"]),
        ("linux", dict(os_name="SLES", os_version="15-SP5", model="sles"), ["SLES_15"]),
        ("windows", dict(os_name="Microsoft Windows 10 Enterprise"), ["MS_Windows_10"]),
        ("windows", dict(os_name="Microsoft Windows Server 2019 Standard"), ["MS_Windows_Server_2019"]),
        ("windows", dict(os_name="Microsoft Windows 11 Pro", part_of_domain=True),
         ["MS_Windows_11", "Active_Directory_Domain", "Active_Directory_Forest"]),
        ("cisco_ios", dict(os_name="Cisco IOS XE"), ["Cisco_IOS-XE_Switch"]),
    ]
    for asset_type, f, want in cases:
        assert products_for(T("x", asset_type), facts(**f))[0] == want, (asset_type, f)
    router = T("r1", "cisco_ios", options={"role": "router"})
    assert products_for(router, facts(os_name="Cisco IOS XE Software"))[0] == ["Cisco_IOS-XE_Router"]
    assert products_for(T("r2", "cisco_ios", tags=["router"]), facts(os_name="Cisco IOS"))[0] == ["Cisco_IOS_Router"]
    keys, _, why = products_for(T("w", "windows"), None)
    assert keys == [] and "stig_products" in why


def test_selection_from_the_sample_inventory():
    sel = select(entries(), INVENTORY, COLLECTED)
    wanted = {r["filename"] for r in sel.wanted}
    assert {"U_MS_Windows_11_V2R11_STIG.zip", "U_MS_Windows_11_V2R11_STIG_SCAP_1-3_Benchmark.zip",
            "U_MS_Windows_Server_2022_V2R11_STIG.zip", "U_MS_Windows_Server_2022_V2R11_STIG_SCAP_1-3_Benchmark.zip",
            "U_Active_Directory_Domain_V3R8_STIG.zip", "U_Active_Directory_Forest_V3R2_STIG.zip",
            "U_RHEL_9_V2R10_STIG.zip", "U_RHEL_9_V2R10_STIG_SCAP_1-3_Benchmark.zip",
            "U_Cisco_IOS_Switch_Y26M10_STIG.zip", "U_Kubernetes_V2R6_STIG.zip", "U_Container_Platform_V2R5_SRG.zip",
            "U_MS_Windows_Server_2025_V1R4_STIG.zip", "U_MS_Windows_Server_2025_V1R2_STIG_SCAP_1-3_Benchmark.zip",
            } == wanted
    # RHEL 9 is wanted once, for both hosts
    rhel = [r for r in sel.wanted if r["filename"] == "U_RHEL_9_V2R10_STIG.zip"][0]
    assert rhel["targets"] == ["rhel9", "rocky9"]
    # no SCAP benchmark for platforms whose scanner here does not execute SCAP; no automation by default
    assert not any(r["kind"] == "scap_benchmark" and r["product_key"] in ("Kubernetes", "Cisco_IOS_Switch")
                   for r in sel.wanted)
    assert not any(r["kind"] in ("automation", "compilation") for r in sel.wanted)
    reasons = {s.get("target_id"): s["reason"] for s in sel.skipped if s.get("target_id")}
    assert "Plan 9" in reasons["mystery"] and reasons["mystery"].startswith("unsupported host")
    sunset = {s["filename"] for s in sel.skipped if s.get("reason", "").startswith("sunset")}
    assert "U_RHEL_9_V2R10_STIG.zip" not in sunset
    assert sel.updates == [dict(r, held_version=None) for r in sel.wanted] and sel.current == []


def test_newest_non_sunset_wins_and_sunset_only_products_are_skipped():
    def e(name, sunset=False, host="dl.dod.cyber.mil"):
        rec = {"DownloadLink": f"https://{host}/stigs/zip/{name}", "FileName": name, "UploadDate": "2026-01-01",
               "RawDownloadType": "STIGs;Sunset" if sunset else "STIGs"}
        return ix.entry_from_record(rec)

    es = [e("U_RHEL_9_V2R8_STIG.zip"), e("U_RHEL_9_V2R10_STIG.zip"), e("U_RHEL_9_V2R11_STIG.zip", sunset=True),
          e("U_RHEL_9_V2R12_STIG.zip", host="mirror.example.com")]
    sel = select(es, [T("h", "linux", options={"stig_products": ["RHEL_9"]})], {})
    assert [r["filename"] for r in sel.wanted] == ["U_RHEL_9_V2R10_STIG.zip"]
    why = {s["filename"]: s["reason"] for s in sel.skipped if s.get("filename")}
    assert why["U_RHEL_9_V2R11_STIG.zip"].startswith("sunset")
    assert why["U_RHEL_9_V2R12_STIG.zip"].startswith("external host mirror.example.com")
    assert why["U_RHEL_9_V2R8_STIG.zip"].startswith("superseded")
    sel8 = select(entries(), [T("old", "linux")], {"old": facts(os_name="Red Hat Enterprise Linux", os_version="8.9")})
    assert sel8.wanted == [] and any(s["reason"].startswith("sunset") for s in sel8.skipped)


def test_held_and_current_detection():
    held = [{"filename": "U_RHEL_9_V2R10_STIG.zip", "product_key": "RHEL_9", "kind": "manual_stig", "version": [2, 10]},
            {"filename": "U_RHEL_9_V2R9_STIG_SCAP_1-3_Benchmark.zip", "product_key": "RHEL_9",
             "kind": "scap_benchmark", "version": [2, 9]}]
    sel = select(entries(), [T("rhel9", "linux")], COLLECTED, held)
    assert [r["filename"] for r in sel.current] == ["U_RHEL_9_V2R10_STIG.zip"]
    assert [(r["filename"], r["held_version"]) for r in sel.updates] == \
        [("U_RHEL_9_V2R10_STIG_SCAP_1-3_Benchmark.zip", [2, 9])]


def test_automation_and_compilation_only_on_request():
    sel = select(entries(), [T("rhel9", "linux")], COLLECTED, include_automation=True, include_compilation=True)
    names = {r["filename"] for r in sel.wanted}
    assert "U_RHEL_9_V2R10_STIG_Ansible.zip" in names or "U_RHEL_9_V2R10_STIG_Chef.zip" in names
    assert "U_SRG-STIG_Library_October_2026.zip" in names


def test_out_of_scope_targets_select_nothing():
    t = T("rhel9", "linux", in_scope=False)
    sel = select(entries(), [t], COLLECTED)
    assert sel.wanted == [] and sel.skipped == [{"target_id": "rhel9", "reason": "target is out of scope"}]
