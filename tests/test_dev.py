import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[1]
REAL_UDS = shutil.which("uds")
FAKE_COMMAND = '''#!/usr/bin/python3
import base64
import json
import os
from pathlib import Path
import subprocess
import sys

name = Path(sys.argv[0]).name
arguments = sys.argv[1:]
with open("calls.jsonl", "a") as calls:
    calls.write(json.dumps({"command": name, "arguments": arguments}) + "\\n")
if name == "docker":
    if arguments[:2] == ["context", "show"]:
        print("test")
    elif arguments[:2] == ["context", "inspect"]:
        print("unix:///test.sock")
    else:
        print("linux/arm64")
elif name == "k3d":
    if arguments[:2] == ["cluster", "list"]:
        print('[{"name":"cyber-thunder"}]' if os.environ.get("TEST_EXISTING_CLUSTER") else "[]")
    else:
        print("test kubeconfig")
elif name == "uds":
    if arguments[:3] == ["zarf", "tools", "yq"]:
        os.execv(os.environ["REAL_UDS"], [os.environ["REAL_UDS"], *arguments])
    elif arguments == ["run", "build"]:
        Path(".build/uds-bundle-cyber-thunder-arm64-0.0.1.tar.zst").write_text("test archive")
    elif arguments[:1] == ["deploy"]:
        config = subprocess.check_output([os.environ["REAL_UDS"], "zarf", "tools", "yq", "-o=json", os.environ["UDS_CONFIG"]], text=True)
        Path("runtime-config.json").write_text(config)
    elif "current-context" in arguments:
        print(os.environ.get("TEST_CONTEXT", "k3d-cyber-thunder"))
    elif "secret" in arguments:
        print(json.dumps({"data": {"username":"YWRtaW4=", "password":base64.b64encode(b"master-secret").decode()}}))
elif name == "verify.sh":
    sys.exit(int(os.environ.get("TEST_VERIFY_FAILURE", "0")))
elif name == "curl":
    output = arguments[arguments.index("-o") + 1]
    if os.environ.get("TEST_INVALID_MASTER"):
        Path(output).write_text(json.dumps({"error":"invalid_grant", "error_description":"Invalid user credentials"}))
        print("400", end="")
    else:
        Path(output).write_text(json.dumps({"access_token":"test-master-token"}))
        print("200", end="")
'''


@unittest.skipUnless(REAL_UDS, "UDS CLI is required for configuration and payload rendering.")
class DevelopmentModeTests(unittest.TestCase):
    def run_script(self, arguments=(), script="scripts/deploy-bundle.sh", repeat=1, **settings):
        with tempfile.TemporaryDirectory() as temporary_directory:
            working_dir = Path(temporary_directory)
            (working_dir / "scripts").mkdir()
            shutil.copytree(REPOSITORY / "bundles", working_dir / "bundles")
            shutil.copytree(REPOSITORY / "packages/identity-bootstrap", working_dir / "packages/identity-bootstrap")
            shutil.copy(REPOSITORY / "scripts/deploy-bundle.sh", working_dir / "scripts/deploy-bundle.sh")
            executable_dir = working_dir / "bin"
            executable_dir.mkdir()
            for command in ("docker", "k3d", "uds", "curl"):
                command_file = executable_dir / command
                command_file.write_text(FAKE_COMMAND.replace("#!/usr/bin/python3", "#!" + sys.executable, 1))
                command_file.chmod(0o755)
            for command in ("verify.sh", "cleanup-clusters.sh"):
                command_file = working_dir / "scripts" / command
                command_file.write_text(FAKE_COMMAND.replace("#!/usr/bin/python3", "#!" + sys.executable, 1))
                command_file.chmod(0o755)
            environment = os.environ.copy()
            for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "UDS_CONFIG", "DEV_MODE", "ADMIN_PASSWORD", "BOOTSTRAP_DRY_RUN"):
                environment.pop(key, None)
            environment.update(settings)
            environment["REAL_UDS"] = REAL_UDS
            environment["PATH"] = str(executable_dir) + os.pathsep + environment["PATH"]
            passwords = []
            for _ in range(repeat):
                result = subprocess.run(["bash", script, *arguments], cwd=working_dir, env=environment, text=True, capture_output=True, check=False)
                password_file = working_dir / ".build/identity/admin-password"
                if password_file.exists():
                    passwords.append(password_file.read_text())
                    self.assertEqual(password_file.stat().st_mode & 0o777, 0o600)
            calls_file = working_dir / "calls.jsonl"
            calls = [json.loads(line) for line in calls_file.read_text().splitlines()] if calls_file.exists() else []
            runtime_config = working_dir / "runtime-config.json"
            config = json.loads(runtime_config.read_text()) if runtime_config.exists() else {}
            temporary_requests = list(working_dir.glob(".build/deploy/**/request.*"))
        return result, calls, config, passwords, temporary_requests

    def test_normal_deployment_excludes_identity_and_credentials(self):
        result, calls, config, passwords, _ = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        deployment = next(call for call in calls if call["arguments"][:1] == ["deploy"])
        self.assertIn("uds-k3d-dev,init,core,podinfo", deployment["arguments"])
        self.assertNotIn("identity-bootstrap", config.get("variables", {}))
        self.assertNotIn("UDS password:", result.stdout)
        self.assertEqual(passwords, [])

    def test_dev_deployment_selects_bootstrap_and_prints_credentials(self):
        result, calls, config, passwords, _ = self.run_script(arguments=("dev",))
        self.assertEqual(result.returncode, 0, result.stderr)
        deployment = next(call for call in calls if call["arguments"][:1] == ["deploy"])
        self.assertIn("uds-k3d-dev,init,core,identity-bootstrap,podinfo", deployment["arguments"])
        self.assertTrue(config["variables"]["core"]["INSECURE_ADMIN_PASSWORD_GENERATION"])
        self.assertEqual(config["variables"]["identity-bootstrap"]["DEV_MODE"], "true")
        self.assertEqual(config["variables"]["identity-bootstrap"]["ADMIN_PASSWORD"], passwords[0])
        self.assertGreaterEqual(sum(character in '!@' for character in passwords[0]), 2)
        self.assertTrue(any(character.isupper() for character in passwords[0]))
        self.assertTrue(any(character.islower() for character in passwords[0]))
        self.assertTrue(any(character.isdigit() for character in passwords[0]))
        self.assertIn("UDS username: admin", result.stdout)
        self.assertIn("UDS password: " + passwords[0], result.stdout)
        self.assertNotIn(passwords[0], json.dumps(calls))

    def test_dev_retry_reuses_password(self):
        result, _, _, passwords, _ = self.run_script(arguments=("dev",), repeat=2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(passwords[0], passwords[1])

    def test_dev_existing_cluster_preserves_cluster_and_core(self):
        result, calls, _, _, _ = self.run_script(arguments=("dev",), TEST_EXISTING_CLUSTER="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        deployment = next(call for call in calls if call["arguments"][:1] == ["deploy"])
        self.assertIn("identity-bootstrap,podinfo", deployment["arguments"])
        self.assertTrue(any(call["arguments"][:2] == ["kubeconfig", "get"] for call in calls))

    def test_failed_verification_does_not_print_credentials(self):
        result, _, _, _, _ = self.run_script(arguments=("dev",), TEST_VERIFY_FAILURE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("UDS username:", result.stdout)
        self.assertNotIn("UDS password:", result.stdout)

    def test_identity_script_requires_dev_opt_in(self):
        result, calls, _, _, _ = self.run_script(script="packages/identity-bootstrap/scripts/ensure-user.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires ./deploy.sh dev", result.stderr)
        self.assertEqual(calls, [])

    def test_identity_payload_accepts_special_characters_without_output(self):
        password = 'test "quoted" password $ with ! punctuation'
        result, calls, _, _, _ = self.run_script(
            script="packages/identity-bootstrap/scripts/ensure-user.sh",
            DEV_MODE="true", ADMIN_PASSWORD=password, BOOTSTRAP_DRY_RUN="true",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(password, result.stdout + result.stderr + json.dumps(calls))

    def test_identity_script_rejects_other_contexts(self):
        result, calls, _, _, _ = self.run_script(
            script="packages/identity-bootstrap/scripts/ensure-user.sh",
            DEV_MODE="true", ADMIN_PASSWORD="test-password", TEST_CONTEXT="other-cluster",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call["command"] == "curl" for call in calls))

    def test_master_bootstrap_preserves_valid_existing_admin(self):
        result, calls, _, _, requests = self.run_script(script="packages/identity-bootstrap/scripts/ensure-admin.sh", DEV_MODE="true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any("POST" in call["arguments"] or "create" in call["arguments"] for call in calls))
        self.assertNotIn("master-secret", json.dumps(calls) + result.stdout)
        self.assertNotIn("test-master-token", json.dumps(calls) + result.stdout)
        self.assertEqual(requests, [])

    def test_master_bootstrap_refuses_to_reset_invalid_existing_admin(self):
        result, calls, _, _, requests = self.run_script(
            script="packages/identity-bootstrap/scripts/ensure-admin.sh", DEV_MODE="true", TEST_INVALID_MASTER="1",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid", result.stderr)
        self.assertFalse(any("POST" in call["arguments"] or "create" in call["arguments"] for call in calls))
        self.assertEqual(requests, [])


if __name__ == "__main__":
    unittest.main()
