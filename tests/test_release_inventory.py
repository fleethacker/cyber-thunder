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


if __name__ == "__main__":
    unittest.main()
