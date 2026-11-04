import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[1]
REQUIRED_VALUES = (
    "KEYCLOAK_DB_HOST", "KEYCLOAK_DB_USERNAME", "KEYCLOAK_DB_DATABASE", "KEYCLOAK_DB_PASSWORD",
    "LOKI_CHUNKS_BUCKET", "LOKI_ADMIN_BUCKET", "LOKI_S3_ENDPOINT", "LOKI_S3_REGION",
    "LOKI_ACCESS_KEY_ID", "LOKI_SECRET_ACCESS_KEY", "VELERO_BUCKET", "VELERO_REGION",
    "VELERO_S3_ENDPOINT", "VELERO_CLOUD_CREDENTIALS", "ADMIN_TLS_CERT", "ADMIN_TLS_KEY",
    "TENANT_TLS_CERT", "TENANT_TLS_KEY",
)
FAKE_COMMAND = '''#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys

name = Path(sys.argv[0]).name
arguments = sys.argv[1:]
with open(os.environ["TEST_COMMAND_LOG"], "a") as command_log:
    command_log.write(json.dumps({"command": name, "arguments": arguments,
        "kubeconfig": os.environ.get("KUBECONFIG"),
        "architecture": os.environ.get("UDS_ARCHITECTURE")}) + "\\n")
if name == "uds":
    if arguments[:3] == ["zarf", "tools", "yq"]:
        if ".variables.core" in arguments:
            print(os.environ["TEST_CONFIG_VALUES"])
        elif ".shared.domain" in arguments:
            print(os.environ.get("TEST_DOMAIN", "example.test"))
        else:
            print("0.0.1")
    elif arguments[:3] == ["zarf", "tools", "kubectl"]:
        request = arguments[3:]
        if request[:1] == ["--context"]:
            request = request[2:]
        if request[:2] == ["config", "view"]:
            print("apiVersion: v1")
        elif request[:2] == ["get", "nodes"]:
            if os.environ.get("TEST_NODES_FAILURE"):
                sys.exit(1)
            nodes = [{"status": {"nodeInfo": {
                "operatingSystem": os.environ.get("TEST_NODE_OS", "linux"),
                "architecture": os.environ.get("TEST_NODE_ARCH", "amd64"),
            }}}]
            if os.environ.get("TEST_MIXED_NODES"):
                nodes.append({"status": {"nodeInfo": {"operatingSystem": "linux", "architecture": "arm64"}}})
            print(json.dumps({"items": nodes}))
        elif request[:2] == ["get", "storageclasses"]:
            classes = [] if os.environ.get("TEST_NO_DEFAULT_STORAGE") else [{
                "metadata": {"annotations": {"storageclass.kubernetes.io/is-default-class": "true"}}
            }]
            print(json.dumps({"items": classes}))
        elif request[:2] == ["get", "namespace"]:
            print("namespace/zarf" if os.environ.get("TEST_INITIALIZED") else "")
        elif request[:2] == ["get", "secret"]:
            print("secret/zarf-state" if os.environ.get("TEST_INITIALIZED") else "")
    elif arguments == ["run", "build-existing"]:
        if os.environ.get("TEST_BUILD_FAILURE"):
            sys.exit(1)
        architecture = os.environ["UDS_ARCHITECTURE"]
        Path(".build/uds-bundle-cyber-thunder-existing-" + architecture + "-0.0.1.tar.zst").write_text("test archive")
    elif arguments[:1] != ["deploy"]:
        sys.exit("Unexpected UDS invocation: " + repr(arguments))
elif name == "curl":
    Path(".build/podinfo-headers").write_text("HTTP/2 302 \\nlocation: https://wrong.example/\\n")
elif name in ("docker", "k3d", "podman"):
    sys.exit("Existing-cluster deployment must not access container engines.")
'''


class ExistingClusterTests(unittest.TestCase):
    def run_deployment(self, verify=False, missing_value=None, **settings):
        with tempfile.TemporaryDirectory() as temporary_directory:
            working_dir = Path(temporary_directory)
            (working_dir / "scripts").mkdir()
            shutil.copy(REPOSITORY / "scripts/deploy-existing.sh", working_dir / "scripts/deploy-existing.sh")
            executable_dir = working_dir / "bin"
            executable_dir.mkdir()
            for command_name in ("uds", "curl", "docker", "k3d", "podman"):
                command_file = executable_dir / command_name
                command_file.write_text(FAKE_COMMAND.replace("#!/usr/bin/python3", "#!" + sys.executable, 1))
                command_file.chmod(0o755)
            verification = working_dir / "scripts/verify.sh"
            if verify:
                shutil.copy(REPOSITORY / "scripts/verify.sh", verification)
                (working_dir / ".build").mkdir()
                (working_dir / ".build/kubeconfig").write_text("test config")
            else:
                verification.write_text(FAKE_COMMAND.replace("#!/usr/bin/python3", "#!" + sys.executable, 1))
            verification.chmod(0o755)
            config_file = working_dir / "config.yaml"
            config_file.write_text("shared: {}")
            values = {name: "configured" for name in REQUIRED_VALUES}
            if missing_value:
                values[missing_value] = ""
            command_log = working_dir / "commands.jsonl"
            environment = os.environ.copy()
            environment.pop("KUBECONFIG", None)
            environment.update(settings)
            environment.update({
                "TEST_COMMAND_LOG": str(command_log),
                "TEST_CONFIG_VALUES": json.dumps(values),
                "PATH": str(executable_dir) + os.pathsep + environment["PATH"],
            })
            command = ["bash", "scripts/verify.sh", "linux-cluster", "example.test"] if verify else [
                "bash", "scripts/deploy-existing.sh", "linux-cluster", str(config_file),
            ]
            result = subprocess.run(command, cwd=working_dir, env=environment, text=True, capture_output=True, check=False)
            commands = [json.loads(line) for line in command_log.read_text().splitlines()]
        self.assertFalse(any(command["command"] in ("docker", "k3d", "podman") for command in commands))
        return result, commands

    def test_fresh_cluster_deploys_init_core_and_podinfo(self):
        result, commands = self.run_deployment()
        self.assertEqual(result.returncode, 0, result.stderr)
        deployment = next(command for command in commands if command["arguments"][:1] == ["deploy"])
        self.assertIn("init,core,podinfo", deployment["arguments"])
        self.assertEqual(deployment["architecture"], "amd64")
        self.assertTrue(deployment["kubeconfig"].endswith(".build/existing/kubeconfig"))
        verification = next(command for command in commands if command["command"] == "verify.sh")
        self.assertEqual(verification["arguments"], ["linux-cluster", "example.test"])

    def test_initialized_cluster_skips_init(self):
        result, commands = self.run_deployment(TEST_INITIALIZED="1", TEST_NODE_ARCH="arm64")
        self.assertEqual(result.returncode, 0, result.stderr)
        deployment = next(command for command in commands if command["arguments"][:1] == ["deploy"])
        self.assertIn("core,podinfo", deployment["arguments"])
        self.assertNotIn("init,core,podinfo", deployment["arguments"])
        self.assertEqual(deployment["architecture"], "arm64")

    def test_missing_credentials_stops_before_cluster_access(self):
        result, commands = self.run_deployment(missing_value="KEYCLOAK_DB_PASSWORD")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("KEYCLOAK_DB_PASSWORD", result.stderr)
        self.assertFalse(any(command["arguments"][:3] == ["zarf", "tools", "kubectl"] for command in commands))

    def test_placeholder_domain_stops_before_cluster_access(self):
        result, commands = self.run_deployment(TEST_DOMAIN="example.invalid")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("shared.domain", result.stderr)
        self.assertFalse(any(command["arguments"][:3] == ["zarf", "tools", "kubectl"] for command in commands))

    def test_mixed_architecture_stops_before_build(self):
        result, commands = self.run_deployment(TEST_MIXED_NODES="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("one supported Linux architecture", result.stderr)
        self.assertFalse(any(command["arguments"] == ["run", "build-existing"] for command in commands))

    def test_missing_default_storage_stops_before_build(self):
        result, commands = self.run_deployment(TEST_NO_DEFAULT_STORAGE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("default storage class", result.stderr)
        self.assertFalse(any(command["arguments"] == ["run", "build-existing"] for command in commands))

    def test_node_inventory_failure_stops_before_deployment(self):
        result, commands = self.run_deployment(TEST_NODES_FAILURE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(command["arguments"][:1] == ["deploy"] for command in commands))

    def test_build_failure_stops_before_deployment(self):
        result, commands = self.run_deployment(TEST_BUILD_FAILURE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(command["arguments"][:1] == ["deploy"] for command in commands))

    def test_existing_cluster_verification_keeps_tls_validation(self):
        result, commands = self.run_deployment(verify=True)
        self.assertNotEqual(result.returncode, 0)
        request = next(command for command in commands if command["command"] == "curl")
        self.assertIn("https://podinfo.example.test/", request["arguments"])
        self.assertNotIn("--insecure", request["arguments"])
        self.assertNotIn("--resolve", request["arguments"])


if __name__ == "__main__":
    unittest.main()
