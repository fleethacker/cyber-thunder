"""Run the full regression suite with the reviewed CI skip policy (docs/CI.md)."""
from __future__ import annotations

from collections import Counter, defaultdict
import json
import os
from pathlib import Path
import sys
import tempfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
BACKENDS = ("json", "sqlite")
WINDOWS_IGNORED = frozenset({
    "tests/test_deploy.py", "tests/test_dev.py", "tests/test_existing.py",
})
MODEL_REASON = "set CT_TEST_LLM=1 to test against a local model server"
SHARING_REASON = "requires Windows file sharing semantics"
UDS_REASON = "UDS CLI is required for configuration and payload rendering."
# Exact names: a new test in this class must not silently inherit an allowance.
UDS_TESTS = (
    "test_normal_deployment_excludes_identity_and_credentials",
    "test_dev_deployment_selects_bootstrap_and_prints_credentials",
    "test_dev_retry_reuses_password",
    "test_dev_existing_cluster_preserves_cluster_and_core",
    "test_failed_verification_does_not_print_credentials",
    "test_identity_script_requires_dev_opt_in",
    "test_identity_payload_accepts_special_characters_without_output",
    "test_identity_script_rejects_other_contexts",
    "test_master_bootstrap_preserves_valid_existing_admin",
    "test_master_bootstrap_refuses_to_reset_invalid_existing_admin",
    "test_identity_bootstrap_unlocks_disabled_user_without_resetting_password",
    "test_identity_bootstrap_stops_when_unlock_fails",
    "test_identity_bootstrap_rejects_disabled_account_after_login",
    "test_standalone_setup_creates_credentials_without_deployment",
    "test_standalone_setup_reuses_saved_password",
    "test_standalone_setup_does_not_print_credentials_on_failure",
    "test_standalone_setup_requires_deployment_kubeconfig",
    "test_standalone_setup_rejects_other_contexts_before_creating_password",
    "test_standalone_setup_rejects_arguments",
)


# Native ACL tests execute on Windows; each Linux skip is named explicitly.
WINDOWS_FILE_TRUST_TESTS = (
    "test_cache_integrity_allows_readers_and_rejects_writer_or_replacement",
    "test_child_creation_is_safe_for_existing_reads_but_not_cache_creation",
    "test_dacl_change_after_read_invalidates_the_operation",
    "test_deny_ace_does_not_make_a_dangerous_allow_acceptable",
    "test_external_kube_public_certificates_and_private_key_have_distinct_rules",
    "test_file_mutation_granted_to_everyone_is_rejected[1073741824]",
    "test_file_mutation_granted_to_everyone_is_rejected[16]",
    "test_file_mutation_granted_to_everyone_is_rejected[256]",
    "test_file_mutation_granted_to_everyone_is_rejected[262144]",
    "test_file_mutation_granted_to_everyone_is_rejected[268435456]",
    "test_file_mutation_granted_to_everyone_is_rejected[2]",
    "test_file_mutation_granted_to_everyone_is_rejected[4]",
    "test_file_mutation_granted_to_everyone_is_rejected[524288]",
    "test_file_mutation_granted_to_everyone_is_rejected[65536]",
    "test_fixture_is_genuinely_protected_and_checks_private_bytes",
    "test_group_membership_or_unknown_sid_cannot_grant_file_mutation[S-1-5-11]",
    "test_group_membership_or_unknown_sid_cannot_grant_file_mutation[S-1-5-21-100-200-300-4444]",
    "test_group_membership_or_unknown_sid_cannot_grant_file_mutation[S-1-5-32-545]",
    "test_handles_prevent_file_and_parent_replacement_and_data_writes",
    "test_inherit_only_grant_is_checked_on_new_cache_file_before_write",
    "test_junction_created_between_checks_and_open_is_rejected",
    "test_kubeconfig_confidentiality_and_guard_recheck",
    "test_native_api_unavailable_fails_closed_for_policy_and_cache",
    "test_null_dacl_and_unsupported_object_ace_are_rejected",
    "test_owner_must_be_in_the_trusted_sid_set",
    "test_owner_rights_is_only_accepted_for_a_checked_trusted_owner",
    "test_parent_mutation_including_delete_child_is_rejected[grandparent-16]",
    "test_parent_mutation_including_delete_child_is_rejected[grandparent-256]",
    "test_parent_mutation_including_delete_child_is_rejected[grandparent-262144]",
    "test_parent_mutation_including_delete_child_is_rejected[grandparent-2]",
    "test_parent_mutation_including_delete_child_is_rejected[grandparent-524288]",
    "test_parent_mutation_including_delete_child_is_rejected[grandparent-64]",
    "test_parent_mutation_including_delete_child_is_rejected[grandparent-65536]",
    "test_parent_mutation_including_delete_child_is_rejected[parent-16]",
    "test_parent_mutation_including_delete_child_is_rejected[parent-256]",
    "test_parent_mutation_including_delete_child_is_rejected[parent-262144]",
    "test_parent_mutation_including_delete_child_is_rejected[parent-2]",
    "test_parent_mutation_including_delete_child_is_rejected[parent-524288]",
    "test_parent_mutation_including_delete_child_is_rejected[parent-64]",
    "test_parent_mutation_including_delete_child_is_rejected[parent-65536]",
    "test_policy_dacl_change_during_parse_invalidates_decision",
    "test_public_read_is_allowed_but_private_data_read_is_not",
    "test_replacement_between_policy_lstat_and_native_open_is_rejected",
    "test_windows_path_aliases_are_rejected[ ]",
    "test_windows_path_aliases_are_rejected[.]",
    "test_windows_path_aliases_are_rejected[:stream]",
)


WINDOWS_FILE_TRUST_REVIEW_TESTS = (
    "test_acl_fixture_refuses_hardlink_aliases",
    "test_add_file_can_set_reparse_data_while_directory_is_pinned",
    "test_cache_final_destination_read_cannot_ignore_revocation[purge]",
    "test_cache_final_destination_read_cannot_ignore_revocation[replace]",
    "test_cache_reopens_and_validates_published_file[bytes]",
    "test_cache_reopens_and_validates_published_file[dacl]",
    "test_conditional_allow_ace_is_refused_for_any_trustee[False]",
    "test_conditional_allow_ace_is_refused_for_any_trustee[True]",
    "test_kubernetes_protection_failure_stops_before_ambient_fallback[json-native-unavailable]",
    "test_kubernetes_protection_failure_stops_before_ambient_fallback[json-parent-add-file]",
    "test_kubernetes_protection_failure_stops_before_ambient_fallback[json-private-read]",
    "test_kubernetes_protection_failure_stops_before_ambient_fallback[sqlite-native-unavailable]",
    "test_kubernetes_protection_failure_stops_before_ambient_fallback[sqlite-parent-add-file]",
    "test_kubernetes_protection_failure_stops_before_ambient_fallback[sqlite-private-read]",
    "test_live_oidc_dacl_revocation_latches_without_reusing_memory_keys",
    "test_private_file_refuses_individual_read_and_execute_grants[1]",
    "test_private_file_refuses_individual_read_and_execute_grants[32]",
)


# Exact cases independently exercised on their native platform; no module allowance.
NODE_HARDENING_SKIPS = {
    "linux": {
        "tests/security/test_node_hardening.py::test_windows_directory_read_inheritance_and_mutation_are_not_a_pass[(A;;GR;;;S-1-1-0)]": "native Windows DACL/handle checks",
        "tests/security/test_node_hardening.py::test_windows_directory_read_inheritance_and_mutation_are_not_a_pass[(A;OICIIO;GR;;;S-1-1-0)]": "native Windows DACL/handle checks",
        "tests/security/test_node_hardening.py::test_windows_directory_read_inheritance_and_mutation_are_not_a_pass[(A;;GW;;;S-1-1-0)]": "native Windows DACL/handle checks",
        "tests/security/test_node_hardening.py::test_windows_protected_file_does_not_certify_the_state_directory": "native Windows selected-file versus state protection",
        "tests/security/test_node_hardening.py::test_windows_shared_validator_failure_and_junction_are_unknown_or_unsafe": "native Windows DACL/handle checks",
        "tests/security/test_node_hardening_review.py::test_windows_unknown_inherit_only_rights_are_not_protected": "native Windows inherited DACL masks",
        "tests/security/test_node_hardening_review.py::test_windows_midwalk_acl_change_is_not_protected_and_closes_handles": "native Windows SID, held handles and DACL revocation",
        "tests/security/test_node_hardening_review.py::test_windows_cli_does_not_expand_ambiguous_drive_paths[C:state]": "native Windows drive-relative path syntax",
        "tests/security/test_node_hardening_review.py::test_windows_cli_does_not_expand_ambiguous_drive_paths[\\\\state]": "native Windows drive-relative path syntax"
    },
    "win32": {
        "tests/security/test_node_hardening.py::test_linux_unsafe_metadata_is_not_a_pass[symlink]": "native Linux descriptor/permission checks",
        "tests/security/test_node_hardening.py::test_linux_unsafe_metadata_is_not_a_pass[fifo]": "native Linux descriptor/permission checks",
        "tests/security/test_node_hardening.py::test_linux_unsafe_metadata_is_not_a_pass[foreign_mode]": "native Linux descriptor/permission checks",
        "tests/security/test_node_hardening.py::test_linux_unsafe_metadata_is_not_a_pass[parent_mode]": "native Linux descriptor/permission checks",
        "tests/security/test_node_hardening.py::test_linux_unsafe_metadata_is_not_a_pass[owner]": "native Linux descriptor/permission checks",
        "tests/security/test_node_hardening.py::test_linux_acl_unknown_and_midwalk_change_are_not_silently_passed": "native Linux xattr/descriptor checks",
        "tests/security/test_node_hardening.py::test_linux_parent_symlink_and_unavailable_permission_metadata": "native Linux no-follow traversal",
        "tests/security/test_node_hardening_review.py::test_linux_descriptor_traversal_closes_every_handle_on_failure[depth]": "native Linux descriptor lifetime and no-follow races",
        "tests/security/test_node_hardening_review.py::test_linux_descriptor_traversal_closes_every_handle_on_failure[entries]": "native Linux descriptor lifetime and no-follow races",
        "tests/security/test_node_hardening_review.py::test_linux_descriptor_traversal_closes_every_handle_on_failure[swap]": "native Linux descriptor lifetime and no-follow races",
        "tests/security/test_node_hardening_review.py::test_linux_descriptor_traversal_closes_every_handle_on_failure[rename]": "native Linux descriptor lifetime and no-follow races",
        "tests/security/test_node_hardening_review.py::test_linux_descriptor_traversal_closes_every_handle_on_failure[metadata]": "native Linux descriptor lifetime and no-follow races",
        "tests/security/test_node_hardening_review.py::test_linux_different_device_is_not_enumerated": "native Linux descriptor filesystem boundary"
    }
}


# Exact native-platform cases; opposite-platform receipts exercised each case.
CREDENTIAL_RESOLVER_SKIPS = {
    "win32": {
        "tests/security/test_secret_mounts_posix.py::test_midread_identity_changes_are_refused[json-replace_file]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_midread_identity_changes_are_refused[json-replace_parent]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_midread_identity_changes_are_refused[json-rotate_projection]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_midread_identity_changes_are_refused[json-write_file]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_midread_identity_changes_are_refused[sqlite-replace_file]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_midread_identity_changes_are_refused[sqlite-replace_parent]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_midread_identity_changes_are_refused[sqlite-rotate_projection]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_midread_identity_changes_are_refused[sqlite-write_file]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_only_root_owned_readonly_projection_can_relax_directory_write_bits[False-True-0-False]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_only_root_owned_readonly_projection_can_relax_directory_write_bits[True-False-0-False]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_only_root_owned_readonly_projection_can_relax_directory_write_bits[True-True-0-True]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_only_root_owned_readonly_projection_can_relax_directory_write_bits[True-True-99999-False]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[json-absolute_data]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[json-escaping_data]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[json-escaping_key]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[json-generation_redirect]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[json-hardlink]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[json-public_value]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[sqlite-absolute_data]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[sqlite-escaping_data]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[sqlite-escaping_key]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[sqlite-generation_redirect]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[sqlite-hardlink]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_projection_rejects_redirects_and_exposed_values[sqlite-public_value]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_projection_requires_explicit_layout_and_accepts_atomic_rotation[json]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_projection_requires_explicit_layout_and_accepts_atomic_rotation[sqlite]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_reader_group_requires_explicit_matching_dedicated_gid[json]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_reader_group_requires_explicit_matching_dedicated_gid[sqlite]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_regular_secret_rejects_group_or_public_permissions[json-385]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_regular_secret_rejects_group_or_public_permissions[json-388]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_regular_secret_rejects_group_or_public_permissions[json-416]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_regular_secret_rejects_group_or_public_permissions[json-420]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_regular_secret_rejects_group_or_public_permissions[json-438]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_regular_secret_rejects_group_or_public_permissions[sqlite-385]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_regular_secret_rejects_group_or_public_permissions[sqlite-388]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_regular_secret_rejects_group_or_public_permissions[sqlite-416]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_regular_secret_rejects_group_or_public_permissions[sqlite-420]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_regular_secret_rejects_group_or_public_permissions[sqlite-438]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_untrusted_nodes_fail_before_read[json-fifo]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_untrusted_nodes_fail_before_read[json-foreign_owner]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_untrusted_nodes_fail_before_read[json-writable_parent]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_untrusted_nodes_fail_before_read[sqlite-fifo]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_untrusted_nodes_fail_before_read[sqlite-foreign_owner]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout",
        "tests/security/test_secret_mounts_posix.py::test_untrusted_nodes_fail_before_read[sqlite-writable_parent]": "POSIX dir_fd, ownership, modes and Kubernetes projection layout"
    },
    "linux": {
        "tests/security/test_secret_resolver.py::test_windows_world_readable_secret_fails_closed[json]": "native Windows private-file DACL enforcement",
        "tests/security/test_secret_resolver.py::test_windows_world_readable_secret_fails_closed[sqlite]": "native Windows private-file DACL enforcement",
        "tests/security/test_wincred_resolver.py::test_native_windows_abi_and_current_logon_with_mocked_credread[json]": "native Windows token and CredReadW ABI with mocked credential data",
        "tests/security/test_wincred_resolver.py::test_native_windows_abi_and_current_logon_with_mocked_credread[sqlite]": "native Windows token and CredReadW ABI with mocked credential data",
        "tests/security/test_wincred_resolver.py::test_native_windows_rejects_thread_impersonation_before_credread[json]": "native Windows thread impersonation with mocked credential data",
        "tests/security/test_wincred_resolver.py::test_native_windows_rejects_thread_impersonation_before_credread[sqlite]": "native Windows thread impersonation with mocked credential data"
    }
}


NATIVE_OPERATOR_SKIPS = {
    "win32": {
        "tests/audit/test_anchor_review.py::test_native_posix_file_protection[fifo]": "requires native POSIX mode and inode protection",
        "tests/audit/test_anchor_review.py::test_native_posix_file_protection[key_symlink]": "requires native POSIX mode and inode protection",
        "tests/audit/test_anchor_review.py::test_native_posix_file_protection[lock_symlink]": "requires native POSIX mode and inode protection",
        "tests/audit/test_anchor_review.py::test_native_posix_file_protection[unsafe_parent]": "requires native POSIX mode and inode protection",
        "tests/client/test_storage_config.py::test_linux_symlink_and_unsafe_parent": "native Linux symlink and mode checks"
    },
    "linux": {
        "tests/client/test_storage_config.py::test_windows_inherited_public_read_never_receives_token_bytes": "native Windows inherited DACL privacy"
    }
}


def expected_skips(platform: str) -> dict[str, str]:
    if platform not in {"linux", "win32"}:
        raise ValueError(f"Unsupported CI platform: {platform}")
    allowed = {
        f"tests/explain/test_service.py::test_real_local_model[{backend}]": MODEL_REASON
        for backend in BACKENDS
    }
    if platform == "win32":
        allowed.update({
            "tests/security/test_access.py::test_fifo_is_rejected_without_opening_or_waiting":
                "requires POSIX FIFO",
            "tests/security/test_oidc.py::test_posix_private_permissions":
                "POSIX ownership/mode enforcement; Windows requires deployment ACLs",
            "tests/security/test_oidc.py::test_symlink_cache_and_directory_rejected":
                "POSIX symlinks; Windows reparse handling has a separate fixture",
        })
        # Reviewed node IDs, including each parameter: never allow a whole module.
        for name in (
            "test_posix_policy_write_permissions_denied[400]",
            "test_posix_policy_write_permissions_denied[386]",
            "test_posix_policy_write_permissions_denied[438]",
            "test_posix_policy_write_permissions_denied[950]",
            "test_posix_writable_parent_denied[504]",
            "test_posix_writable_parent_denied[455]",
            "test_posix_untrusted_owner_denied[file]",
            "test_posix_untrusted_owner_denied[parent]",
            "test_posix_permission_change_during_parse_denied",
            "test_posix_root_sticky_directory_exception_never_applies_to_file",
            "test_posix_parent_swap_to_symlink_before_open_denied_and_fds_closed",
        ):
            allowed[f"tests/security/test_access_file_trust.py::{name}"] = (
                "requires POSIX owner/mode and descriptor-relative filesystem semantics"
            )
        for mode in (420, 416, 438):
            allowed[f"tests/security/test_kube_credentials.py::test_real_posix_config_permission_failure[{mode}]"] = (
                "real POSIX file permissions"
            )
        for replacement in ("existing_fifo", "fifo_at_open", "symlink_at_open"):
            allowed[f"tests/engine/test_inventory_guard.py::test_fifo_or_link_replacement_refuses_promptly_and_releases_target_lock[{replacement}]"] = (
                "POSIX FIFO and O_NOFOLLOW semantics"
            )
    if platform == "linux":
        allowed.update({
            f"tests/security/test_windows_file_trust_review.py::{name}":
                "native Windows security descriptors and file sharing"
            for name in WINDOWS_FILE_TRUST_REVIEW_TESTS
        })
        allowed.update({
            f"tests/security/test_windows_file_trust.py::{name}":
                "native Windows security descriptors and file sharing"
            for name in WINDOWS_FILE_TRUST_TESTS
        })
        allowed["tests/security/test_oidc.py::test_windows_junction_cache_path_rejected"] = (
            "Windows directory junction fixture"
        )
        allowed["tests/security/test_access_file_trust.py::test_actual_windows_junction_parent_denied"] = (
            "requires Windows NTFS junction support"
        )
        allowed.update({
            f"tests/test_dev.py::DevelopmentModeTests::{name}": UDS_REASON
            for name in UDS_TESTS
        })
        allowed["tests/report/test_reports.py::test_commander_reproduce_command_runs_in_cmd"] = (
            "runs the command through cmd.exe"
        )
        for node in (
            "tests/test_approval_io.py::test_deny_survives_windows_delete_handle",
            "tests/state/test_file_read_sharing.py::test_deny_response_survives_windows_inventory_sharing",
            "tests/state/test_file_read_sharing.py::test_windows_scope_retry_observes_revocation",
        ):
            allowed.update({f"{node}[{backend}]": SHARING_REASON for backend in BACKENDS})
        for name in (
            "test_json_run_read_survives_windows_sharing",
            "test_audit_checkpoint_survives_windows_sharing",
        ):
            allowed[f"tests/state/test_file_read_sharing.py::{name}"] = SHARING_REASON
    allowed.update(NODE_HARDENING_SKIPS[platform])
    allowed.update(CREDENTIAL_RESOLVER_SKIPS[platform])
    allowed.update(NATIVE_OPERATOR_SKIPS[platform])
    if platform == "linux":
        # The native Windows command boundary runs on the Windows matrix leg.
        allowed["tests/ops/test_wsl_keepalive.py::test_keepalive_operator_and_task_boundaries"] = "native Windows PowerShell task-boundary fixture"
    return allowed


class RegressionPolicy:
    def __init__(self, root: Path, platform: str):
        self.root = root.resolve()
        self.platform = platform
        self.allowed = expected_skips(platform)
        self.errors: list[str] = []
        self.skips: list[dict] = []
        self.outcomes: Counter = Counter()
        self.collected: list[str] = []
        self.ignored: list[str] = []
        self.seen_skips: set[str] = set()

    def pytest_collectreport(self, report):
        if report.skipped:
            self.errors.append(f"Collection skipped: {report.nodeid}")

    def pytest_deselected(self, items):
        self.errors.extend(f"Deselected: {item.nodeid}" for item in items)

    def pytest_collection_finish(self, session):
        self.collected = [item.nodeid for item in session.items]
        modules = {node.split("::", 1)[0] for node in self.collected}
        expected = {
            path.relative_to(self.root).as_posix()
            for path in (self.root / "tests").rglob("*.py")
            if path.name.startswith("test_") or path.name.endswith("_test.py")
        }
        omitted = expected - modules
        allowed_omissions = WINDOWS_IGNORED if self.platform == "win32" else frozenset()
        self.ignored = sorted(omitted & allowed_omissions)
        self.errors.extend(f"Module not collected: {name}" for name in sorted(omitted - allowed_omissions))

        # Check every state fixture test, including each combination of other parameters.
        state_cases = defaultdict(Counter)
        for item in session.items:
            if "state_dir" not in item.fixturenames:
                continue
            spec = getattr(item, "callspec", None)
            if spec is None or "state_dir" not in spec.params:
                self.errors.append(f"State backend not parametrized: {item.nodeid}")
                continue
            # Pytest may number other parameter indices across the entire Cartesian product,
            # so their indices differ between backends. Compare the actual parameter values
            # within this collection and retain multiplicity for duplicate values.
            other = tuple(sorted((key, type(value).__module__, type(value).__qualname__, repr(value))
                                 for key, value in spec.params.items() if key != "state_dir"))
            key = (item.nodeid.split("[", 1)[0], other)
            state_cases[key][spec.params["state_dir"]] += 1
        if not state_cases:
            self.errors.append("No state backend cases collected")
        for (node, other), backends in state_cases.items():
            if set(backends) != set(BACKENDS) or len(set(backends.values())) != 1:
                self.errors.append(f"Incomplete state backends: {node}: {dict(backends)}")

    def pytest_runtest_logreport(self, report):
        self.outcomes[f"{report.when}:{report.outcome}"] += 1
        if hasattr(report, "wasxfail"):
            self.errors.append(f"Unexpected xfail/xpass: {report.nodeid}")
        if not report.skipped:
            return
        reason = str(report.longrepr[2]) if isinstance(report.longrepr, tuple) else str(report.longrepr)
        reason = reason.removeprefix("Skipped: ")
        accepted = (
            not hasattr(report, "wasxfail")
            and report.when in {"setup", "call"}
            and self.allowed.get(report.nodeid) == reason
            and report.nodeid not in self.seen_skips
        )
        self.skips.append({"nodeid": report.nodeid, "phase": report.when, "reason": reason, "allowed": accepted})
        self.seen_skips.add(report.nodeid)
        if not accepted:
            self.errors.append(f"Unexpected skip: {report.nodeid} ({report.when}): {reason}")

    def pytest_sessionfinish(self, session, exitstatus):
        if self.errors and exitstatus == pytest.ExitCode.OK:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED
        output = self.root / ".build" / "ci"
        output.mkdir(parents=True, exist_ok=True)
        (output / "policy.json").write_text(json.dumps({
            "platform": self.platform,
            "backends": list(BACKENDS),
            "collected": self.collected,
            "ignored_modules": self.ignored,
            "skip_allowances": self.allowed,
            "skips": self.skips,
            "outcomes": dict(self.outcomes),
            "errors": self.errors,
            "exit_code": int(session.exitstatus),
        }, indent=2) + "\n", encoding="utf-8")

    def pytest_terminal_summary(self, terminalreporter):
        terminalreporter.section("CI regression policy")
        terminalreporter.write_line(f"Collected {len(self.collected)} cases; {len(self.skips)} skips")
        for module in self.ignored:
            terminalreporter.write_line(f"Known Windows collection omission: {module}")
        for error in self.errors:
            terminalreporter.write_line(error, red=True)
        terminalreporter.write_line("CI POLICY FAIL" if self.errors else "CI POLICY PASS")


def main() -> int:
    os.chdir(ROOT)
    # A developer's local selection or installed plugin must not narrow the CI run.
    os.environ["PYTEST_ADDOPTS"] = ""
    os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    os.environ["CT_STATE_BACKENDS"] = ",".join(BACKENDS)
    os.environ["CT_STATE_BACKEND"] = "json"
    os.environ["CT_TEST_LLM"] = "0"
    output = ROOT / ".build" / "ci"
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ct-ci-") as state:
        os.environ["CT_STATE_DIR"] = state
        return int(pytest.main(
            ["tests", "-ra", "--strict-markers", "-W", "error::pytest.PytestUnhandledThreadExceptionWarning",
             f"--junitxml={output / 'pytest.xml'}"],
            plugins=[RegressionPolicy(ROOT, sys.platform)],
        ))


if __name__ == "__main__":
    if len(sys.argv) != 1:
        sys.exit("CI requires the full suite; test selectors and extra options are not accepted")
    sys.exit(main())
