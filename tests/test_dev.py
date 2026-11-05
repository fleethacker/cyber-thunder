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
import urllib.parse

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
        if any(argument.startswith("jsonpath=") for argument in arguments):
            print(base64.b64encode(b"master-secret").decode())
        else:
            print(json.dumps({"data": {"username":"YWRtaW4=", "password":base64.b64encode(b"master-secret").decode()}}))
elif name == "verify.sh":
    sys.exit(int(os.environ.get("TEST_VERIFY_FAILURE", "0")))
elif name == "curl":
    if os.environ.get("TEST_IDENTITY_FLOW"):
        state_file = Path("account-state.json")
        state = json.loads(state_file.read_text()) if state_file.exists() else {"enabled": False, "locked": True}
        url = next(argument for argument in arguments if argument.startswith("https://"))
        path = urllib.parse.urlsplit(url).path
        method = arguments[arguments.index("-X") + 1] if "-X" in arguments else "GET"
        response = {}
        status = "200"
        if path == "/realms/master/protocol/openid-connect/token":
            response = {"access_token": "test-master-token"}
        elif path == "/realms/uds/protocol/openid-connect/token":
            if state["locked"] or not state["enabled"]:
                status = "400"
                response = {"error": "invalid_grant", "error_description": "Invalid user credentials"}
            else:
                response = {"access_token": "test-user-token"}
        elif "/attack-detection/brute-force/users/" in path:
            if method != "DELETE":
                sys.exit("Expected account-specific lockout reset")
            if os.environ.get("TEST_UNLOCK_FAILURE"):
                status = "500"
            else:
                state["locked"] = False
                status = "204"
        elif path.endswith("/authentication/flows/Authentication/executions"):
            response = []
        elif path == "/admin/realms/uds/users":
            response = [{"id": "test-user", "username": "admin", "enabled": state["enabled"]}]
        elif path == "/admin/realms/uds/users/test-user":
            if method == "PUT":
                state["enabled"] = json.loads(arguments[arguments.index("--data-raw") + 1])["enabled"]
                status = "204"
            else:
                response = {"enabled": False if os.environ.get("TEST_ACCOUNT_REDISABLED") else state["enabled"]}
        elif path.endswith("/reset-password"):
            sys.exit("The saved password must not be reset to repair a lockout")
        elif path == "/admin/realms/uds/groups":
            response = [{"id": "uds-core"}]
        elif path == "/admin/realms/uds/groups/uds-core/children":
            response = [{"id": "admin-group", "name": "Admin"}]
        elif path == "/admin/realms/uds/users/test-user/groups/admin-group":
            status = "204"
        elif path not in ("/realms/master", "/admin/realms/master"):
            sys.exit("Unexpected identity endpoint: " + path)
        state_file.write_text(json.dumps(state))
        body = json.dumps(response)
        if "-o" in arguments:
            Path(arguments[arguments.index("-o") + 1]).write_text(body)
        else:
            print(body, end="")
        if "-w" in arguments:
            print(status, end="")
        sys.exit(22 if status == "500" else 0)
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
    def run_script(self, arguments=(), script="scripts/deploy-bundle.sh", repeat=1,
                   create_kubeconfig=True, saved_password=None, **settings):
        with tempfile.TemporaryDirectory() as temporary_directory:
            working_dir = Path(temporary_directory)
            (working_dir / "scripts").mkdir()
            shutil.copytree(REPOSITORY / "bundles", working_dir / "bundles")
            shutil.copytree(REPOSITORY / "packages/identity-bootstrap", working_dir / "packages/identity-bootstrap")
            shutil.copy(REPOSITORY / "scripts/deploy-bundle.sh", working_dir / "scripts/deploy-bundle.sh")
            shutil.copy(REPOSITORY / "setup-dev-user.sh", working_dir / "setup-dev-user.sh")
            (working_dir / ".build").mkdir()
            if create_kubeconfig:
                (working_dir / ".build/kubeconfig").write_text("test kubeconfig")
            if saved_password is not None:
                (working_dir / ".build/identity").mkdir()
                (working_dir / ".build/identity/admin-password").write_text(saved_password)
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
            for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "UDS_CONFIG", "DEV_MODE", "ADMIN_PASSWORD", "BOOTSTRAP_DRY_RUN", "KUBECONFIG"):
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
        self.assertIn("uds-k3d-dev,init,core,podinfo,nginx-bad", deployment["arguments"])
        self.assertNotIn("identity-bootstrap", config.get("variables", {}))
        self.assertNotIn("UDS password:", result.stdout)
        self.assertEqual(passwords, [])

    def test_dev_deployment_selects_bootstrap_and_prints_credentials(self):
        result, calls, config, passwords, _ = self.run_script(arguments=("dev",))
        self.assertEqual(result.returncode, 0, result.stderr)
        deployment = next(call for call in calls if call["arguments"][:1] == ["deploy"])
        self.assertIn("uds-k3d-dev,init,core,identity-bootstrap,podinfo,nginx-bad", deployment["arguments"])
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
        self.assertIn("identity-bootstrap,podinfo,nginx-bad", deployment["arguments"])
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

    def test_identity_bootstrap_unlocks_disabled_user_without_resetting_password(self):
        result, calls, _, _, requests = self.run_script(
            script="packages/identity-bootstrap/scripts/ensure-user.sh",
            DEV_MODE="true", ADMIN_PASSWORD="test-password", TEST_IDENTITY_FLOW="1",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        urls = [call["arguments"] for call in calls if call["command"] == "curl"]
        unlock = next(index for index, arguments in enumerate(urls) if any("/attack-detection/" in argument for argument in arguments))
        login = next(index for index, arguments in enumerate(urls) if any("sso.uds.dev" in argument for argument in arguments))
        self.assertIn("DELETE", urls[unlock])
        self.assertIn("https://keycloak.admin.uds.dev/admin/realms/uds/attack-detection/brute-force/users/test-user", urls[unlock])
        self.assertLess(unlock, login)
        self.assertFalse(any("reset-password" in argument for arguments in urls for argument in arguments))
        self.assertFalse(any(argument == "https://keycloak.admin.uds.dev/admin/realms/uds" for arguments in urls for argument in arguments))
        self.assertEqual(requests, [])

    def test_identity_bootstrap_stops_when_unlock_fails(self):
        result, calls, _, _, requests = self.run_script(
            script="packages/identity-bootstrap/scripts/ensure-user.sh",
            DEV_MODE="true", ADMIN_PASSWORD="test-password", TEST_IDENTITY_FLOW="1", TEST_UNLOCK_FAILURE="1",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any("sso.uds.dev" in argument for call in calls for argument in call["arguments"]))
        self.assertNotIn("identity reconciled", result.stdout)
        self.assertEqual(requests, [])

    def test_identity_bootstrap_rejects_disabled_account_after_login(self):
        result, _, _, _, requests = self.run_script(
            script="packages/identity-bootstrap/scripts/ensure-user.sh",
            DEV_MODE="true", ADMIN_PASSWORD="test-password", TEST_IDENTITY_FLOW="1", TEST_ACCOUNT_REDISABLED="1",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("still disabled after login", result.stderr)
        self.assertNotIn("identity reconciled", result.stdout)
        self.assertEqual(requests, [])

    def test_standalone_setup_creates_credentials_without_deployment(self):
        result, calls, _, passwords, requests = self.run_script(
            script="setup-dev-user.sh", TEST_IDENTITY_FLOW="1", BOOTSTRAP_DRY_RUN="true",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(passwords[0].endswith("Aa1!@"))
        self.assertIn("UDS username: admin", result.stdout)
        self.assertIn("UDS password: " + passwords[0], result.stdout)
        self.assertNotIn(passwords[0], json.dumps(calls))
        self.assertNotIn("test-master-token", result.stdout + json.dumps(calls))
        self.assertNotIn("test-user-token", result.stdout + json.dumps(calls))
        self.assertTrue(any(call["command"] == "curl" for call in calls))
        self.assertTrue(all(call["command"] in ("uds", "curl") for call in calls))
        self.assertTrue(all(call["arguments"][:2] == ["zarf", "tools"] for call in calls if call["command"] == "uds"))
        self.assertEqual(requests, [])

    def test_standalone_setup_reuses_saved_password(self):
        saved = "existing-development-credential!@"
        result, _, _, passwords, _ = self.run_script(
            script="setup-dev-user.sh", repeat=2, saved_password=saved, TEST_IDENTITY_FLOW="1",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(passwords, [saved, saved])

    def test_standalone_setup_does_not_print_credentials_on_failure(self):
        result, _, _, passwords, requests = self.run_script(
            script="setup-dev-user.sh", TEST_IDENTITY_FLOW="1", TEST_UNLOCK_FAILURE="1",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("UDS username:", result.stdout)
        self.assertNotIn(passwords[0], result.stdout + result.stderr)
        self.assertEqual(requests, [])

    def test_standalone_setup_requires_deployment_kubeconfig(self):
        result, calls, _, passwords, _ = self.run_script(script="setup-dev-user.sh", create_kubeconfig=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Deployment kubeconfig not found", result.stderr)
        self.assertEqual(calls, [])
        self.assertEqual(passwords, [])

    def test_standalone_setup_rejects_other_contexts_before_creating_password(self):
        result, calls, _, passwords, _ = self.run_script(script="setup-dev-user.sh", TEST_CONTEXT="other-cluster")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires context k3d-cyber-thunder", result.stderr)
        self.assertFalse(any(call["command"] == "curl" for call in calls))
        self.assertEqual(passwords, [])

    def test_standalone_setup_rejects_arguments(self):
        result, calls, _, passwords, _ = self.run_script(script="setup-dev-user.sh", arguments=("unexpected",))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Usage: ./setup-dev-user.sh", result.stderr)
        self.assertEqual(calls, [])
        self.assertEqual(passwords, [])


if __name__ == "__main__":
    unittest.main()
