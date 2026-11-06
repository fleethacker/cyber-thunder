"""Focused standard-library tests; run directly with unittest (no app initialization)."""
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import unquote
import zipfile

MODULE = Path(__file__).resolve().parents[1] / "scripts" / "release_inventory.py"
SPEC = importlib.util.spec_from_file_location("release_inventory", MODULE)
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


def properties(component):
    return {p["name"].removeprefix("release-inventory:"): p["value"] for p in component["properties"]}


def make_wheel(members=None, compression=zipfile.ZIP_STORED):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=compression) as archive:
        for name, value in (members or {
            "sample/__init__.py": "raise RuntimeError('must never execute')\n",
            "sample-1.2.3.dist-info/METADATA": (
                "Metadata-Version: 2.3\nName: sample\nVersion: 1.2.3\n"
                "Requires-Python: >=3.12\nRequires-Dist: child>=2; python_version >= '3.12'\n"
                "License-Expression: MIT\n\nA fixture wheel.\n"),
            "sample-1.2.3.dist-info/WHEEL": "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
            "sample-1.2.3.dist-info/RECORD": "",
        }).items():
            member = name if isinstance(name, zipfile.ZipInfo) else zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            member.compress_type = compression
            archive.writestr(member, value)
    return stream.getvalue()


class ReleaseInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        self.write("pyproject.toml", '[project]\nname="sample-app"\nversion="0.1.0"\ndependencies=["sample>=1"]\n')
        self.write("requirements.txt", "sample>=1\nmissing-package==7\n")
        self.write("requirements-dev.txt", "pytest>=8\n")
        self.write("vendor/sample-1.2.3-py3-none-any.whl", make_wheel())
        self.write("cyberthunder/ui/package.json", json.dumps({"name": "ui", "version": "1.0.0",
                   "dependencies": {"runtime": "^2"}, "devDependencies": {"builder": "^3"}}))
        self.integrity = "sha512-" + base64.b64encode(hashlib.sha512(b"fixture package").digest()).decode()
        self.lock = {"lockfileVersion": 3, "packages": {
            "": {"name": "ui", "version": "1.0.0"},
            "node_modules/runtime": {"version": "2.1.0", "resolved": "https://registry.npmjs.org/runtime/-/runtime-2.1.0.tgz",
                                     "integrity": self.integrity},
            "node_modules/builder": {"version": "3.0.0", "dev": True, "integrity": self.integrity},
            "node_modules/optional": {"version": "1.0.0", "devOptional": True, "optional": True},
            "node_modules/linked": {"link": True, "resolved": "packages/linked"},
        }}
        self.write_lock()
        self.write("cyberthunder/ui/dist/index.html", '<script src="assets/app.js"></script>')
        self.write("cyberthunder/ui/dist/assets/app.js", 'console.log("fixture bundle");')
        self.write("Dockerfile", "FROM python:3.12\nARG TOOL_VERSION=v1.2.3\n")
        self.write("Containerfile", "FROM registry.example/scanner@sha256:" + "a" * 64 + "\n")
        self.write("deploy/app.yaml", "containers:\n  - image: example/app:1.0\n")
        self.write("packages/demo/zarf.yaml", "components:\n  - name: demo\n    images:\n      - example/demo@sha256:" + "b" * 64 + "\n")
        self.write(".gitignore", "cyberthunder/ui/dist/\n")
        for args in (("init", "-q"), ("add", "."),
                     ("-c", "user.name=Joshua Ott", "-c", "user.email=Joshua.ott@outlook.com", "commit", "-qm", "Inventory fixture")):
            subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True)

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode())

    def write_lock(self):
        self.write("cyberthunder/ui/package-lock.json", json.dumps(self.lock))

    def generate(self):
        return inventory.Inventory(self.root).generate()

    def test_observed_wheel_lock_and_bundle(self):
        result = self.generate()
        components = result["components"]
        wheel = next(c for c in components if c["name"] == "sample")
        self.assertEqual(wheel["version"], "1.2.3")
        self.assertEqual(wheel["purl"], "pkg:pypi/sample@1.2.3")
        runtime = next(c for c in components if c["name"] == "runtime")
        self.assertEqual(runtime["purl"], "pkg:npm/runtime@2.1.0")
        self.assertEqual(properties(runtime)["purl-evidence"], "registry-lock-identifier-claim")
        self.assertEqual(properties(wheel)["installation"], "unknown")
        self.assertEqual(wheel["hashes"][0]["content"], hashlib.sha256(make_wheel()).hexdigest())
        self.assertEqual(properties(wheel)["zip-integrity"], "all-members-crc-checked")
        self.assertIn("child>=2", properties(wheel)["declared-metadata"])
        by_name = {c["name"]: properties(c) for c in components}
        self.assertEqual(by_name["runtime"]["dependency-role"], "runtime-eligible")
        self.assertEqual(by_name["runtime"]["integrity"], self.integrity)
        self.assertEqual(by_name["builder"]["dependency-role"], "development")
        self.assertEqual(by_name["optional"]["dependency-role"], "development-or-optional-runtime")
        self.assertEqual(by_name["builder"]["ui-bundle-membership"], "unknown")
        asset = next(c for c in components if c["name"].endswith("assets/app.js"))
        self.assertEqual(asset["hashes"][0]["content"], hashlib.sha256(b'console.log("fixture bundle");').hexdigest())
        self.assertEqual(result["compositions"], [{"aggregate": "incomplete"}])
        self.assertNotIn("vulnerabilities", result)
        self.assertNotIn("dependencies", result)
        self.assertTrue(all("licenses" not in c for c in components))

    def test_determinism_and_provenance(self):
        first, second = self.generate(), self.generate()
        self.assertEqual(inventory.encoded(first), inventory.encoded(second))
        metadata = properties(first["metadata"])
        self.assertEqual(metadata["source-dirty"], "false")
        self.assertEqual(metadata["source-commit"], inventory.git(self.root, "rev-parse", "HEAD").decode().strip())
        self.assertEqual(metadata["source-head-tree"], inventory.git(self.root, "rev-parse", "HEAD^{tree}").decode().strip())
        sources = json.loads(metadata["sources"])
        self.assertEqual(metadata["source-set-sha256"], inventory.digest(inventory.encoded(sources)))
        self.write("requirements.txt", "sample==1.2.3\n")
        changed = self.generate()
        self.assertEqual(properties(changed["metadata"])["source-dirty"], "true")
        self.assertNotEqual(first, changed)

    def test_identifier_omissions_preserve_evidence_and_partial_coverage(self):
        self.write("vendor/sample-1.2.3-py3-none-any.whl", make_wheel({
            "sample-1.2.3.dist-info/METADATA": "Name: another\nVersion: 1.2.3\n"}))
        self.lock["packages"][""]["dependencies"] = {"runtime": "npm:runtime@2.1.0"}
        self.write_lock()
        result = self.generate()
        self.assertFalse(any("purl" in c for c in result["components"]))
        self.assertTrue(any("hashes" in c for c in result["components"] if c["name"] == "another"))
        self.assertIn("PURL omitted", properties(result["metadata"])["unresolved"])
        self.assertEqual(result["compositions"], [{"aggregate": "incomplete"}])
        self.assertEqual(properties(result["metadata"])["coverage"], "partial")

    def test_scoped_and_nested_registry_claims_are_reproducible(self):
        self.lock["packages"]["node_modules/parent/node_modules/@scope/tool"] = {
            "version": "1.2.3-beta.1+Build.4", "resolved":
            "https://registry.npmjs.org/@scope/tool/-/tool-1.2.3-beta.1%2BBuild.4.tgz"}
        self.write_lock()
        first = self.generate()
        self.assertEqual(inventory.encoded(first), inventory.encoded(self.generate()))
        tool = next(c for c in first["components"] if c["name"] == "@scope/tool")
        self.assertEqual(tool["purl"], "pkg:npm/%40scope/tool@1.2.3-beta.1%2BBuild.4")
        self.assertNotIn("hashes", tool)
        self.assertNotIn("purl", first["metadata"]["component"])
        for c in first["components"]:
            if c["type"] != "library":
                self.assertNotIn("purl", c)

    def test_missing_inputs_remain_explicit(self):
        (self.root / "vendor/sample-1.2.3-py3-none-any.whl").unlink()
        (self.root / "cyberthunder/ui/package-lock.json").unlink()
        result = self.generate()
        unresolved = properties(result["metadata"])["unresolved"]
        for expected in ("no wheels observed", "package-lock.json", "external-models-and-runtimes", "python-dependency-closure"):
            self.assertIn(expected, unresolved)

    def test_image_references_are_not_approvals(self):
        images = [c for c in self.generate()["components"] if c["type"] == "container"]
        self.assertEqual(len(images), 4)
        self.assertEqual(sum(properties(c)["digest-pinned"] == "true" for c in images), 2)
        self.assertTrue(all(properties(c)["approval"] == "unknown" for c in images))

    def test_no_network_or_package_execution(self):
        original = subprocess.Popen
        commands = []

        def bounded_git(command, *args, **kwargs):
            self.assertEqual(command[0], "git")
            self.assertFalse(kwargs.get("shell"))
            self.assertNotIn("GIT_DIR", kwargs["env"])
            commands.append(command)
            return original(command, *args, **kwargs)

        with patch.object(socket, "socket", side_effect=AssertionError("network forbidden")), \
                patch.object(subprocess, "Popen", side_effect=bounded_git), \
                patch.dict("os.environ", {"GIT_DIR": "malicious", "PRIVATE_TOKEN": "not-in-output"}):
            result = self.generate()
        self.assertTrue(commands)
        self.assertNotIn(b"not-in-output", inventory.encoded(result))

    def test_archive_paths_and_metadata(self):
        for name in ("../escape", "/absolute", "C:/absolute", "a\\b", "a/../b"):
            with self.subTest(name=name), self.assertRaises(inventory.InventoryError):
                inventory.wheel(make_wheel({name: "bad"}))
        for data in (b"not a zip", make_wheel({"sample.dist-info/METADATA": "Name: bad\n"})):
            with self.assertRaises((inventory.InventoryError, zipfile.BadZipFile)):
                inventory.wheel(data)

    def test_archive_crc_failure(self):
        data = make_wheel()
        data = data.replace(b"must never execute", b"must never executX", 1)
        with self.assertRaises(zipfile.BadZipFile):
            inventory.wheel(data)

    def test_archive_bomb_and_metadata_limits(self):
        data = make_wheel({"sample.dist-info/METADATA": "x" * 100000}, zipfile.ZIP_DEFLATED)
        with self.assertRaises(inventory.InventoryError):
            inventory.wheel(data)
        with patch.object(inventory, "MAX_METADATA", 20), self.assertRaises(inventory.InventoryError):
            inventory.wheel(make_wheel())
        with patch.object(inventory, "MAX_EXPANDED", 20), self.assertRaises(inventory.InventoryError):
            inventory.wheel(make_wheel())
        with patch.object(inventory, "MAX_FILES", 2), self.assertRaises(inventory.InventoryError):
            inventory.wheel(make_wheel())

    def test_archive_duplicate_and_link(self):
        with self.assertRaises(inventory.InventoryError):
            inventory.wheel(make_wheel({"same": "one", "SAME": "two"}))
        member = zipfile.ZipInfo("link")
        member.create_system = 3
        member.external_attr = (0o120777 << 16)
        with self.assertRaises(inventory.InventoryError):
            inventory.wheel(make_wheel({member: "outside"}))

    def test_path_escape_and_file_budgets(self):
        reader = inventory.Reader(self.root)
        for name in ("../outside", "/etc/passwd", "C:/Windows/file", "vendor/../../outside"):
            with self.subTest(name=name), self.assertRaises(inventory.InventoryError):
                reader.read(name)
        with self.assertRaises(inventory.InventoryError):
            reader.read("pyproject.toml", 10)
        with patch.object(inventory, "MAX_TOTAL", 1), self.assertRaises(inventory.InventoryError):
            reader.read("pyproject.toml")
        with patch.object(inventory, "MAX_FILES", 1), self.assertRaises(inventory.InventoryError):
            reader.files("cyberthunder/ui", recursive=True)

    def test_linked_source_rejected(self):
        linked = self.root / "linked"
        try:
            linked.symlink_to(self.root / "vendor", target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaises(inventory.InventoryError):
            inventory.Reader(self.root).files("linked")

    def test_malformed_lock(self):
        for data in ('{"lockfileVersion":3,"packages":[],"packages":{}}',
                     '{"lockfileVersion":1}', '{"lockfileVersion":3,"packages":{"../bad":{}}}',
                     '{"lockfileVersion":3,"packages":{"node_modules/a":{"dev":"false"}}}'):
            self.write("cyberthunder/ui/package-lock.json", data)
            with self.subTest(data=data), self.assertRaises(inventory.InventoryError):
                self.generate()

    def test_sensitive_references_rejected_without_echo(self):
        for ref in ("https://user:password@registry.example/a", "https://registry.example/a?token=private"):
            self.lock["packages"]["node_modules/runtime"]["resolved"] = ref
            self.write_lock()
            with self.assertRaises(inventory.InventoryError):
                self.generate()

    def test_zip_directory_count_tampering(self):
        data = bytearray(make_wheel())
        end = data.rfind(b"PK\x05\x06")
        data[end + 8:end + 12] = b"\x01\x00\x01\x00"
        with self.assertRaises(inventory.InventoryError):
            inventory.wheel(bytes(data))

    def test_external_claims_are_not_verified_hashes(self):
        self.write("external.json", json.dumps({"components": [{"kind": "model", "name": "test-model",
                    "version": "v1", "sha256": "c" * 64, "reference": "local-model"}]}))
        result = inventory.Inventory(self.root).generate("external.json")
        model = next(c for c in result["components"] if c["type"] == "machine-learning-model")
        self.assertNotIn("hashes", model)
        self.assertNotIn("purl", model)
        self.assertEqual(properties(model)["deployment"], "unknown")
        with self.assertRaises(inventory.InventoryError):
            inventory.Inventory(self.root).generate("../external.json")
        self.write("external.json", '{"components":[{"kind":"model","name":"test","unexpected":"value"}]}')
        with self.assertRaises(inventory.InventoryError):
            inventory.Inventory(self.root).generate("external.json")

    def test_mid_run_change_rejected(self):
        original = inventory.Inventory.npm

        def change(instance):
            original(instance)
            self.write("requirements.txt", "changed\n")

        with patch.object(inventory.Inventory, "npm", change), self.assertRaises(inventory.InventoryError):
            self.generate()

    def test_cli_receipt_and_no_overwrites(self):
        output, receipt = Path(self.temp.name) / "bom.json", Path(self.temp.name) / "receipt.json"
        args = ["--repo", str(self.root), "--output", str(output), "--receipt", str(receipt)]
        self.assertEqual(inventory.main(args), 0)
        record = json.loads(receipt.read_bytes())
        self.assertEqual(record["artifact_sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
        self.assertIn("generated_at", record)
        self.assertEqual(inventory.main(args), 2)
        self.assertEqual(inventory.main(["--repo", str(self.root), "--output", str(self.root / "new.json"),
                                        "--receipt", str(Path(self.temp.name) / "new.json")]), 2)

    def test_invalid_input_emits_no_artifact(self):
        self.write("vendor/sample-1.2.3-py3-none-any.whl", b"broken")
        output, receipt = Path(self.temp.name) / "bom.json", Path(self.temp.name) / "receipt.json"
        self.assertEqual(inventory.main(["--repo", str(self.root), "--output", str(output), "--receipt", str(receipt)]), 2)
        self.assertFalse(output.exists())
        self.assertFalse(receipt.exists())

    def test_root_application_identity(self):
        result = self.generate()
        root = result["metadata"]["component"]
        self.assertEqual((root["name"], root["version"]), ("sample-app", "0.1.0"))
        self.assertNotIn(root["bom-ref"], [c["bom-ref"] for c in result["components"]])

    def test_json_depth_bound_before_parser(self):
        data = b'{"unused":' + b'[' * 65 + b'0' + b']' * 65 + b'}'
        with patch.object(inventory.json, "loads", side_effect=AssertionError("decoder reached")), \
                self.assertRaises(inventory.InventoryError):
            inventory.json_object(data)

    def test_json_depth_boundary_and_escaped_strings(self):
        data = '{"unused":' + '[' * 63 + '0' + ']' * 63 + '}'
        self.assertIsInstance(inventory.json_object(data), dict)
        value = '[{"quoted": "\\\\\\\""}]' * 100
        self.assertEqual(inventory.json_object(json.dumps({"value": value})), {"value": value})
        for data in ('{"unused":NaN}', '{"a":1,"a":2}', '{"a":[}'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                inventory.json_object(data)

    def test_schema_version_length(self):
        self.lock["packages"]["node_modules/runtime"]["version"] = "v" * 1025
        self.write_lock()
        with self.assertRaises(inventory.InventoryError):
            self.generate()
        self.lock["packages"]["node_modules/runtime"]["version"] = "v" * 1024
        self.write_lock()
        self.assertEqual(len(next(c for c in self.generate()["components"] if c["name"] == "runtime")["version"]), 1024)

    def test_executed_generator_provenance(self):
        self.write("scripts/release_inventory.py", "# different repository copy\n")
        result = properties(self.generate()["metadata"])
        self.assertEqual(result["generator-sha256"], hashlib.sha256(MODULE.read_bytes()).hexdigest())
        sources = json.loads(result["sources"])
        repo_copy = next(s for s in sources if s["path"] == "scripts/release_inventory.py")
        self.assertNotEqual(repo_copy["sha256"], result["generator-sha256"])

    def test_missing_root_identity_is_explicit(self):
        self.write("pyproject.toml", "[project]\n")
        self.assertIn("identity incomplete", properties(self.generate()["metadata"])["unresolved"])
        (self.root / "pyproject.toml").unlink()
        result = self.generate()
        self.assertNotIn("component", result["metadata"])
        self.assertIn("pyproject.toml", properties(result["metadata"])["unresolved"])

    def test_dirty_bytes_do_not_masquerade_as_head(self):
        clean = properties(self.generate()["metadata"])
        self.write("requirements.txt", "sample==9\n")
        first = properties(self.generate()["metadata"])
        self.write("requirements.txt", "sample==10\n")
        second = properties(self.generate()["metadata"])
        self.assertEqual(clean["source-commit"], second["source-commit"])
        self.assertEqual(clean["source-head-tree"], second["source-head-tree"])
        self.assertEqual(first["source-status-sha256"], second["source-status-sha256"])
        self.assertNotEqual(first["source-set-sha256"], second["source-set-sha256"])
        self.assertEqual(second["source-dirty"], "true")

    def test_hard_linked_asset_rejected(self):
        linked = self.root / "cyberthunder/ui/dist/hardlink.js"
        linked.hardlink_to(self.root / "cyberthunder/ui/dist/assets/app.js")
        with self.assertRaises(inventory.InventoryError):
            self.generate()

    def test_deep_json_cli_emits_no_artifact(self):
        self.write("cyberthunder/ui/package-lock.json", '{"unused":' + '[' * 1000 + '0' + ']' * 1000 + '}')
        output, receipt = Path(self.temp.name) / "deep.json", Path(self.temp.name) / "deep.receipt.json"
        self.assertEqual(inventory.main(["--repo", str(self.root), "--output", str(output),
                                        "--receipt", str(receipt)]), 2)
        self.assertFalse(output.exists())
        self.assertFalse(receipt.exists())


class PackageUrlTests(unittest.TestCase):
    def test_python_name_normalization(self):
        for name in ("Friendly-Bard", "friendly_bard", "friendly.bard", "FrIeNdLy-._--bArD"):
            with self.subTest(name=name):
                self.assertEqual(inventory.wheel_purl(name, "1.2.3", "friendly_bard-1.2.3-py3-none-any.whl",
                                                     "friendly.bard-1.2.3.dist-info/METADATA"),
                                 "pkg:pypi/friendly-bard@1.2.3")

    def test_wheel_exact_versions_and_encoding(self):
        for version in ("0", "1.2", "1.0a1", "1.0b2", "1.0rc1", "1.0.post2.dev3", "1!2.0+linux.1"):
            with self.subTest(version=version):
                purl = inventory.wheel_purl("Sample", version, f"sample-{version}-1-py2.py3-none-any.whl",
                                            f"sample-{version}.dist-info/METADATA")
                self.assertEqual(unquote(purl), "pkg:pypi/sample@" + version)
                self.assertNotIn("!", purl)
                self.assertNotIn("+", purl)
        self.assertEqual(inventory.wheel_purl("sample", "1!2.0+cpu.1", "sample-1!2.0+cpu.1-py3-none-any.whl",
                                             "sample-1!2.0+cpu.1.dist-info/METADATA"),
                         "pkg:pypi/sample@1%212.0%2Bcpu.1")

    def test_wheel_ambiguous_or_malicious_identity_has_no_purl(self):
        baseline = ["sample", "1.2.3", "sample-1.2.3-py3-none-any.whl", "sample-1.2.3.dist-info/METADATA"]
        for index, value in [(0, "bad/name"), (0, "sam%70le"), (0, "sämple"), (0, "sample-"),
                             (0, "@sample"), (0, "sample\n"), (1, "1.2.3#payload"), (1, "1.2.3?x=1"),
                             (1, "1.2.3/../../x"), (1, "1.2.3%2Bcpu"), (1, "1.2.3;exec"),
                             (1, "1.*"), (1, ">=1"), (1, "v1.2.3"), (1, "01.2.3"), (1, "1.2.3RC1"),
                             (2, "other-1.2.3-py3-none-any.whl"), (2, "sample-2-py3-none-any.whl"),
                             (2, "sample-1.2.3-invalid-py3-none-any.whl"), (2, "sample-1.2.3.whl"),
                             (3, "other-1.2.3.dist-info/METADATA"), (3, "sample-2.dist-info/METADATA"),
                             (3, "sample-1.2.3.dist-info/other/METADATA")]:
            arguments = baseline.copy()
            arguments[index] = value
            with self.subTest(index=index, value=value):
                self.assertIsNone(inventory.wheel_purl(*arguments))

    @staticmethod
    def npm_entry(name="example", version="1.2.3"):
        return {"version": version, "resolved": f"https://registry.npmjs.org/{name}/-/{name.rsplit('/', 1)[-1]}-{version}.tgz"}

    def test_npm_scope_namespace_case_and_encoding(self):
        for name, expected in [("example", "example"), ("@angular/core", "%40angular/core"),
                               ("@node_modules/tool", "%40node_modules/tool"),
                               ("@customnode_modules/tool", "%40customnode_modules/tool"),
                               ("Legacy_Name", "Legacy_Name"), ("@Old.Scope/Legacy_Name", "%40Old.Scope/Legacy_Name")]:
            entry = self.npm_entry(name, "1.2.3-alpha.0+Build.01")
            for prefix in ("node_modules/", "node_modules/parent/node_modules/", "node_modules/@other/parent/node_modules/"):
                with self.subTest(name=name, prefix=prefix):
                    self.assertEqual(inventory.npm_purl(prefix + name, entry, set()),
                                     "pkg:npm/" + expected + "@1.2.3-alpha.0%2BBuild.01")

    def test_npm_scoped_encoded_registry_path(self):
        entry = self.npm_entry("@scope/pkg")
        for path in ("@scope/pkg", "%40scope/pkg", "@scope%2Fpkg", "%40scope%2fpkg"):
            entry["resolved"] = "https://registry.npmjs.org/" + path + "/-/pkg-1.2.3.tgz"
            self.assertEqual(inventory.npm_purl("node_modules/@scope/pkg", entry, set()), "pkg:npm/%40scope/pkg@1.2.3")

    def test_npm_ambiguous_locations_and_names(self):
        self.assertIsNone(inventory.npm_purl("node_modules/@node_modules/example", self.npm_entry(), set()))
        for name in ("../example", "@scope", "@scope/extra/example", "%40scope/example", "_example", ".example",
                     "example@payload", "example?x=1", "exämple", "example;payload", "a" * 215):
            with self.subTest(name=name):
                self.assertIsNone(inventory.npm_purl("node_modules/" + name, self.npm_entry(name), set()))
        for location in ("packages/example", "workspace/node_modules/example", "node_modules/example/extra", "../node_modules/example"):
            self.assertIsNone(inventory.npm_purl(location, self.npm_entry(), set()))
        for name in ("alias-target", "Example", "", None):
            entry = {**self.npm_entry(), "name": name}
            self.assertIsNone(inventory.npm_purl("node_modules/example", entry, set()))

    def test_npm_versions_are_exact_semver_not_requirements_or_sources(self):
        for version in (None, 123, "", "1", "1.2", "v1.2.3", "01.2.3", "1.2.3-01", "1.2.3-alpha.01",
                        "^1.2.3", "~1.2.3", "1.2.x", "latest", "npm:example@1.2.3", "file:example",
                        "workspace:*", "git+https://example/repo", "1.2.3+../x", "1.2.3?x=1", "1.2.3%00"):
            with self.subTest(version=version):
                self.assertIsNone(inventory.npm_purl("node_modules/example", self.npm_entry(version=version), set()))

    def test_npm_registry_url_must_corroborate_identity(self):
        for resolved in (None, "", "git+https://registry.npmjs.org/example", "file:example", "workspace:*",
                         "http://registry.npmjs.org/example/-/example-1.2.3.tgz",
                         "https://registry.npmjs.org.evil/example/-/example-1.2.3.tgz",
                         "https://registry.npmjs.org@evil/example/-/example-1.2.3.tgz",
                         "https://user:secret@registry.npmjs.org/example/-/example-1.2.3.tgz",
                         "https://registry.npmjs.org:443/example/-/example-1.2.3.tgz",
                         "https://registry.npmjs.org/other/-/example-1.2.3.tgz",
                         "https://registry.npmjs.org/example/-/example-2.0.0.tgz",
                         "https://registry.npmjs.org/example/-/example-1.2.3.tgz?token=private",
                         "https://registry.npmjs.org/example/-/example-1.2.3.tgz#payload",
                         "https://registry.npmjs.org/example/-/example-1.2.3.tgz#",
                         "https://registry.npmjs.org/example/-/example-1.2.3.tgz?",
                         " https://registry.npmjs.org/example/-/example-1.2.3.tgz",
                         "https://registry.npmjs.org/exam\nple/-/example-1.2.3.tgz",
                         "https://registry.npmjs.org/%2565xample/-/example-1.2.3.tgz",
                         "https://registry.npmjs.org/ex%GGample/-/example-1.2.3.tgz",
                         "https://registry.npmjs.org/ex%FFample/-/example-1.2.3.tgz"):
            with self.subTest(resolved=resolved):
                self.assertIsNone(inventory.npm_purl("node_modules/example", {**self.npm_entry(), "resolved": resolved}, set()))
        self.assertIsNone(inventory.npm_purl("node_modules/example", {**self.npm_entry(), "link": True}, set()))

    def test_nonregistry_declarations_exclude_even_same_name_aliases(self):
        for field in ("dependencies", "optionalDependencies", "devDependencies", "peerDependencies"):
            for spec in ("npm:example@1.2.3", "file:../example", "link:example", "workspace:*", "owner/repo", "git@host:repo", "https://host/file", None):
                with self.subTest(field=field, spec=spec):
                    excluded = inventory.npm_exclusions([{field: {"example": spec}}])
                    self.assertIsNone(inventory.npm_purl("node_modules/example", self.npm_entry(), excluded))
        self.assertEqual(inventory.npm_exclusions([{"dependencies": {"example": "^1.2.3", "other": "latest"}}]), set())
        with self.assertRaises(inventory.InventoryError):
            inventory.npm_exclusions([{"dependencies": []}])


if __name__ == "__main__":
    unittest.main()
