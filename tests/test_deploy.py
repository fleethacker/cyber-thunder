import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[1]
FAKE_COMMAND = '''#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys

name = Path(sys.argv[0]).name
arguments = sys.argv[1:]
with open(os.environ["TEST_COMMAND_LOG"], "a") as command_log:
    command_log.write(json.dumps({
        "command": name,
        "arguments": arguments,
        "host": os.environ.get("DOCKER_HOST"),
        "architecture": os.environ.get("UDS_ARCHITECTURE"),
        "guest_socket": os.environ.get("DOCKER_SOCK"),
        "uds_config": os.environ.get("UDS_CONFIG"),
    }) + "\\n")

if name == "brew":
    print(Path(os.environ["TEST_COMMAND_LOG"]).parent)
elif name == "docker":
    if arguments[:2] == ["context", "show"]:
        print("test-engine")
    elif arguments[:2] == ["context", "inspect"]:
        print("unix:///test-engine.sock")
    elif arguments[0] == "info":
        if os.environ.get("TEST_ENGINE_DOWN"):
            sys.exit(1)
        print(os.environ.get("TEST_ENGINE_PLATFORM", "linux/aarch64"))
elif name == "k3d":
    if arguments[:2] == ["cluster", "list"]:
        if os.environ.get("TEST_INVENTORY_FAILURE"):
            sys.exit(1)
        exists = os.environ.get("TEST_CLUSTER_EXISTS") or (
            os.environ.get("TEST_CLUSTER_DURING_BUILD") and Path(".build/finished").exists()
        )
        clusters = [{"name": "cyber-thunder"}] if exists else []
        clusters = json.loads(os.environ.get("TEST_CLUSTER_NAMES", json.dumps(clusters)))
        deleted_file = Path(".build/deleted-clusters.json")
        deleted = json.loads(deleted_file.read_text()) if deleted_file.exists() else []
        print(json.dumps([cluster for cluster in clusters if cluster["name"] not in deleted]))
    elif arguments[:2] == ["cluster", "delete"]:
        if not os.environ.get("TEST_DELETE_NO_EFFECT"):
            deleted_file = Path(".build/deleted-clusters.json")
            deleted = json.loads(deleted_file.read_text()) if deleted_file.exists() else []
            deleted_file.write_text(json.dumps([*deleted, arguments[2]]))
        sys.exit(int(os.environ.get("TEST_DELETE_EXIT", "0")))
    else:
        print("k3d version v5.9.0")
elif name == "uname":
    print(os.environ.get("TEST_HOST_OS", "Darwin"))
elif name == "podman":
    if arguments[:2] == ["machine", "list"]:
        if os.environ.get("TEST_MACHINE_INVENTORY_FAILURE"):
            sys.exit(125)
        print("[]" if os.environ.get("TEST_NEW_MACHINE") else '[{"Name":"podman-machine-default"}]')
    elif arguments[:2] == ["machine", "init"]:
        sys.exit(int(os.environ.get("TEST_MACHINE_INIT_EXIT", "0")))
    elif arguments[:2] == ["machine", "start"]:
        sys.exit(int(os.environ.get("TEST_MACHINE_START_EXIT", "0")))
    elif arguments[:2] == ["machine", "inspect"]:
        if "--format" not in arguments:
            print(json.dumps([{
                "Rootful": not bool(os.environ.get("TEST_ROOTLESS_MACHINE")),
                "Resources": {"CPUs": 6, "Memory": int(os.environ.get("TEST_MACHINE_MEMORY", "16384")), "DiskSize": 100},
            }]))
        elif arguments[-1] == "{{.State}}":
            print("running" if os.environ.get("TEST_MACHINE_RUNNING") else "stopped")
        else:
            print("/test-podman.sock")
    elif arguments[0] == "--url" and arguments[2] == "info":
        print("true" if os.environ.get("TEST_ROOTLESS_SERVICE") else "false")
    elif arguments[0] == "--url" and arguments[2] == "network":
        if arguments[3] == "exists":
            sys.exit(int(os.environ.get("TEST_NETWORK_EXISTS_EXIT", "0")))
        elif arguments[3] == "inspect":
            print("false" if os.environ.get("TEST_NETWORK_NO_DNS") else "true")
    else:
        sys.exit("Unexpected Podman invocation: " + repr(arguments))
elif name == "uds":
    if arguments == ["version"]:
        print("v0.39.0")
    elif arguments == ["run", "build"]:
        Path(".build/finished").touch()
        sys.exit(int(os.environ.get("TEST_BUILD_EXIT", "0")))
    elif arguments[:3] == ["zarf", "tools", "yq"]:
        print("0.0.1")
    else:
        sys.exit("Unexpected UDS invocation: " + repr(arguments))
'''


class DeploymentGuardTests(unittest.TestCase):
    def run_deployment(self, script_name="scripts/deploy-bundle.sh", expected_success=False, arguments=(), **settings):
        with tempfile.TemporaryDirectory() as temporary_directory:
            working_dir = Path(temporary_directory)
            target_script = working_dir / script_name
            target_script.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(REPOSITORY / script_name, target_script)
            (working_dir / "scripts").mkdir(exist_ok=True)
            if script_name in ("deploy-mac.sh", "deploy-linux.sh"):
                deployment_script = working_dir / "scripts/deploy-bundle.sh"
                deployment_script.write_text(FAKE_COMMAND.replace("#!/usr/bin/python3", "#!" + sys.executable, 1))
                deployment_script.chmod(0o755)
                shutil.copy(REPOSITORY / "scripts/prepare-podman.sh", working_dir / "scripts/prepare-podman.sh")
            if script_name == "deploy.sh":
                for platform_script in ("deploy-mac.sh", "deploy-linux.sh"):
                    script = working_dir / platform_script
                    script.write_text(FAKE_COMMAND.replace("#!/usr/bin/python3", "#!" + sys.executable, 1))
                    script.chmod(0o755)
            executable_dir = working_dir / "bin"
            executable_dir.mkdir()
            for command_name in ("brew", "docker", "k3d", "uds", "uname", "podman"):
                command_file = executable_dir / command_name
                command_file.write_text(FAKE_COMMAND.replace("#!/usr/bin/python3", "#!" + sys.executable, 1))
                command_file.chmod(0o755)
            command_log = working_dir / "commands.jsonl"
            environment = os.environ.copy()
            environment.pop("DOCKER_HOST", None)
            environment.pop("DOCKER_CONTEXT", None)
            environment.pop("PODMAN_MACHINE_IMAGE", None)
            environment.pop("UDS_CONFIG", None)
            environment.pop("DOCKER_SOCK", None)
            environment.pop("CONTAINER_RUNTIME", None)
            environment.update(settings)
            environment["TEST_COMMAND_LOG"] = str(command_log)
            environment["PATH"] = str(executable_dir) + os.pathsep + environment["PATH"]
            result = subprocess.run(
                ["bash", script_name, *arguments], cwd=working_dir, env=environment,
                text=True, capture_output=True, check=False,
            )
            commands = [json.loads(line) for line in command_log.read_text().splitlines()] if command_log.exists() else []
        if expected_success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(command["arguments"][:1] == ["deploy"] for command in commands))
        return result, commands

    def test_existing_cluster_stops_before_build(self):
        result, commands = self.run_deployment(TEST_CLUSTER_EXISTS="1")
        self.assertIn("already exists", result.stderr)
        self.assertFalse(any(command["arguments"] == ["run", "build"] for command in commands))

    def test_unavailable_engine_stops_before_cluster_access(self):
        result, commands = self.run_deployment(TEST_ENGINE_DOWN="1")
        self.assertIn("Start the selected container engine", result.stderr)
        self.assertFalse(any(command["command"] == "k3d" for command in commands))

    def test_failed_cluster_inventory_stops_before_build(self):
        _, commands = self.run_deployment(TEST_INVENTORY_FAILURE="1")
        self.assertFalse(any(command["arguments"] == ["run", "build"] for command in commands))

    def test_unsupported_engine_platform_stops_before_build(self):
        result, _ = self.run_deployment(TEST_ENGINE_PLATFORM="windows/amd64")
        self.assertIn("Unsupported container engine platform", result.stderr)

    def test_failed_build_uses_selected_engine_and_its_architecture(self):
        _, commands = self.run_deployment(TEST_BUILD_EXIT="1", TEST_ENGINE_PLATFORM="linux/x86_64")
        build = next(command for command in commands if command["arguments"] == ["run", "build"])
        self.assertEqual(build["host"], "unix:///test-engine.sock")
        self.assertEqual(build["architecture"], "amd64")

    def test_cluster_created_during_build_stops_deployment(self):
        result, _ = self.run_deployment(TEST_CLUSTER_DURING_BUILD="1")
        self.assertIn("already exists", result.stderr)

    def test_missing_bundle_stops_deployment(self):
        result, _ = self.run_deployment()
        self.assertIn("Built bundle not found", result.stderr)

    def test_cleanup_preserves_target_cluster(self):
        _, commands = self.run_deployment(
            script_name="scripts/cleanup-clusters.sh", expected_success=True,
            DOCKER_HOST="unix:///test-podman.sock", DOCKER_SOCK="/run/podman/podman.sock",
            TEST_CLUSTER_NAMES=json.dumps([
                {"name": "old-demo"}, {"name": "cyber-thunder"}, {"name": "other-test"},
            ]),
        )
        deletions = [command for command in commands if command["arguments"][:2] == ["cluster", "delete"]]
        self.assertEqual([command["arguments"][2] for command in deletions], ["old-demo", "other-test"])
        self.assertTrue(all(command["host"] == "unix:///test-podman.sock" for command in deletions))
        self.assertTrue(all(command["guest_socket"] == "/run/podman/podman.sock" for command in deletions))

    def test_cleanup_stops_if_inventory_fails(self):
        _, commands = self.run_deployment(script_name="scripts/cleanup-clusters.sh", TEST_INVENTORY_FAILURE="1")
        self.assertFalse(any(command["arguments"][:2] == ["cluster", "delete"] for command in commands))

    def test_cleanup_detects_cluster_left_after_successful_delete(self):
        result, _ = self.run_deployment(
            script_name="scripts/cleanup-clusters.sh", TEST_DELETE_NO_EFFECT="1",
            TEST_CLUSTER_NAMES='[{"name":"old-demo"}]',
        )
        self.assertIn("Cluster cleanup incomplete: old-demo", result.stderr)

    def test_mac_cleanup_stops_if_engine_cannot_start(self):
        _, commands = self.run_deployment(script_name="deploy-mac.sh", TEST_ENGINE_DOWN="1")
        self.assertFalse(any(command["command"] == "k3d" for command in commands))

    def test_mac_initializes_rootful_machine_from_local_image(self):
        _, commands = self.run_deployment(
            script_name="deploy-mac.sh", expected_success=True,
            TEST_NEW_MACHINE="1", PODMAN_MACHINE_IMAGE="/test-machine.raw.zst",
        )
        initialization = next(command for command in commands if command["arguments"][:2] == ["machine", "init"])
        self.assertIn("--rootful", initialization["arguments"])
        self.assertIn("16384", initialization["arguments"])
        self.assertIn("/test-machine.raw.zst", initialization["arguments"])
        startup = next(command for command in commands if command["arguments"][:2] == ["machine", "start"])
        self.assertIn("--update-connection=false", startup["arguments"])

    def test_mac_machine_inventory_failure_does_not_initialize_or_delete(self):
        _, commands = self.run_deployment(script_name="deploy-mac.sh", TEST_MACHINE_INVENTORY_FAILURE="1")
        self.assertFalse(any(command["arguments"][:2] == ["machine", "init"] for command in commands))
        self.assertFalse(any(command["command"] == "k3d" for command in commands))

    def test_mac_machine_initialization_failure_stops_cleanup(self):
        _, commands = self.run_deployment(script_name="deploy-mac.sh", TEST_NEW_MACHINE="1", TEST_MACHINE_INIT_EXIT="125")
        self.assertFalse(any(command["command"] == "k3d" for command in commands))

    def test_mac_machine_start_failure_stops_cleanup(self):
        _, commands = self.run_deployment(script_name="deploy-mac.sh", TEST_MACHINE_START_EXIT="125")
        self.assertFalse(any(command["command"] == "k3d" for command in commands))

    def test_mac_rejects_rootless_machine_before_start(self):
        result, commands = self.run_deployment(script_name="deploy-mac.sh", TEST_ROOTLESS_MACHINE="1")
        self.assertIn("must use rootful", result.stderr)
        self.assertFalse(any(command["arguments"][:2] == ["machine", "start"] for command in commands))

    def test_mac_rejects_insufficient_memory_before_start(self):
        result, commands = self.run_deployment(script_name="deploy-mac.sh", TEST_MACHINE_MEMORY="2048")
        self.assertIn("10240 MiB", result.stderr)
        self.assertFalse(any(command["arguments"][:2] == ["machine", "start"] for command in commands))

    def test_mac_creates_missing_podman_network(self):
        _, commands = self.run_deployment(script_name="deploy-mac.sh", expected_success=True, TEST_NETWORK_EXISTS_EXIT="1")
        self.assertTrue(any(command["arguments"] == ["--url", "unix:///test-podman.sock", "network", "create", "cyber-thunder"] for command in commands))

    def test_mac_network_inspection_error_does_not_create_network(self):
        _, commands = self.run_deployment(script_name="deploy-mac.sh", TEST_NETWORK_EXISTS_EXIT="125")
        self.assertFalse(any(command["arguments"][:4] == ["--url", "unix:///test-podman.sock", "network", "create"] for command in commands))

    def test_mac_rejects_network_without_dns(self):
        result, _ = self.run_deployment(script_name="deploy-mac.sh", TEST_NETWORK_NO_DNS="1")
        self.assertIn("must have DNS enabled", result.stderr)

    def test_cluster_deletion_failure_stops_cleanup(self):
        _, commands = self.run_deployment(
            script_name="scripts/cleanup-clusters.sh", TEST_DELETE_EXIT="1",
            TEST_CLUSTER_NAMES=json.dumps([{"name": "old-demo"}, {"name": "other-test"}]),
        )
        deletions = [command for command in commands if command["arguments"][:2] == ["cluster", "delete"]]
        self.assertEqual(len(deletions), 1)

    def test_entrypoint_selects_macos(self):
        _, commands = self.run_deployment(script_name="deploy.sh", expected_success=True, TEST_HOST_OS="Darwin")
        self.assertTrue(any(command["command"] == "deploy-mac.sh" for command in commands))

    def test_entrypoint_selects_linux(self):
        _, commands = self.run_deployment(script_name="deploy.sh", expected_success=True, TEST_HOST_OS="Linux")
        self.assertTrue(any(command["command"] == "deploy-linux.sh" for command in commands))

    def test_entrypoint_passes_dev_mode_to_platform_launcher(self):
        _, commands = self.run_deployment(script_name="deploy.sh", expected_success=True, arguments=("dev",), TEST_HOST_OS="Linux")
        launcher = next(command for command in commands if command["command"] == "deploy-linux.sh")
        self.assertEqual(launcher["arguments"], ["dev"])

    def test_entrypoint_rejects_unknown_mode_before_launch(self):
        result, commands = self.run_deployment(script_name="deploy.sh", arguments=("unknown",))
        self.assertIn("Usage:", result.stderr)
        self.assertEqual(commands, [])

    def test_entrypoint_rejects_unsupported_host(self):
        result, _ = self.run_deployment(script_name="deploy.sh", TEST_HOST_OS="FreeBSD")
        self.assertIn("Supported hosts", result.stderr)

    def test_linux_docker_does_not_use_podman_machine(self):
        _, commands = self.run_deployment(script_name="deploy-linux.sh", expected_success=True, TEST_HOST_OS="Linux")
        self.assertTrue(any(command["command"] == "deploy-bundle.sh" for command in commands))
        self.assertFalse(any(command["command"] == "podman" for command in commands))

    def test_linux_podman_uses_native_rootful_socket(self):
        _, commands = self.run_deployment(
            script_name="deploy-linux.sh", expected_success=True,
            TEST_HOST_OS="Linux", CONTAINER_RUNTIME="podman",
        )
        deployment = next(command for command in commands if command["command"] == "deploy-bundle.sh")
        self.assertEqual(deployment["host"], "unix:///run/podman/podman.sock")
        self.assertEqual(deployment["guest_socket"], "/run/podman/podman.sock")
        self.assertTrue(deployment["uds_config"].endswith("uds-podman-config.yaml"))
        self.assertFalse(any(command["arguments"][:1] == ["machine"] for command in commands))

    def test_linux_podman_rejects_rootless_service(self):
        result, commands = self.run_deployment(
            script_name="deploy-linux.sh", TEST_HOST_OS="Linux",
            CONTAINER_RUNTIME="podman", TEST_ROOTLESS_SERVICE="1",
        )
        self.assertIn("requires a rootful", result.stderr)
        self.assertFalse(any(command["command"] == "deploy-bundle.sh" for command in commands))

    def test_linux_rejects_unknown_runtime(self):
        result, _ = self.run_deployment(script_name="deploy-linux.sh", TEST_HOST_OS="Linux", CONTAINER_RUNTIME="unknown")
        self.assertIn("Set CONTAINER_RUNTIME", result.stderr)

    def test_arm64_build_uses_engine_architecture(self):
        _, commands = self.run_deployment(TEST_BUILD_EXIT="1", TEST_ENGINE_PLATFORM="linux/aarch64")
        build = next(command for command in commands if command["arguments"] == ["run", "build"])
        self.assertEqual(build["architecture"], "arm64")


if __name__ == "__main__":
    unittest.main()
