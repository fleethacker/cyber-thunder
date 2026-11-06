# Register a host and choose discovery ranges

A container can reach an authorized host through the existing SSH or WinRM transport when that service, credentials and network path are already provisioned. Local transport runs in the application's own environment. Inside a container or Kubernetes pod, it addresses that container, not the physical host.

Runtime context reports local markers as native, container, Kubernetes or unknown. Native means that no known container marker was seen; it does not prove bare metal. A Linux container cannot identify whether its underlying machine is Windows, WSL, a Linux node or another virtualization layer. The application does not guess a host IP or resolve a suggested gateway.

## Register the intended host

1. Supply the actual intended host OS, address and account. Use Linux with SSH or Windows with WinRM. The OS is an operator declaration until an explicit connection test obtains facts.
2. Supply a named credential reference for already provisioned access. The guided form accepts reference names, not passwords or tokens. Existing generic target configuration remains available for key-file and other supported access arrangements.
3. Choose **in scope** or **out of scope** explicitly and provide a reason. Registration and that decision are audited. Out-of-scope registration is valid; connection testing stays blocked.
4. Review static readiness. It checks declarations, current scope and kill state without DNS, transport creation or remote commands. It does not prove connectivity, credentials or effective privilege.
5. Choose the explicit connection test when authorized. It reuses adapter discovery, rechecks persisted scope and the kill switch, and audits the outcome. This does not start a scan. Start an authorized scan separately through the existing scan flow.

The default ports are 22 for SSH and 5986 for WinRM; an operator may supply another valid port. Loopback addresses refer to the runtime's network environment and must not be presented as detected physical-host addresses. Existing transport trust behavior is unchanged; this flow does not add host-key pinning or verified application identity.

This workflow does not install services, change firewall rules, grant container privilege, mount the host root or access a container-engine socket. If the host cannot be reached through existing authorized access, readiness and connection errors remain visible for the operator to resolve outside this workflow.

## Preview and save discovery ranges

Includes and exclusions accept single IPv4/IPv6 addresses, CIDRs, and inclusive `start-end` ranges. For example:

```json
{
  "include": ["192.168.56.10-192.168.56.30", "fd00::1-fd00::4"],
  "exclude": ["192.168.56.20", "fd00::2"],
  "allow_public": false,
  "reason": "Approved lab discovery window"
}
```

Preview merges overlaps, subtracts exclusions and returns normalized effective CIDRs. It uses interval arithmetic, including for huge IPv6 inputs; it never enumerates hosts or sends probes. Address counts are decimal strings so browsers retain exact IPv6 values. Counts describe address space, including IPv4 network and broadcast addresses.

A CIDR containing host bits must be acknowledged explicitly. For example, `192.168.1.20/24` means the wider `192.168.1.0/24` network. Preview lists each such include/exclude normalization and blocks save until `acknowledge_normalization=true` is supplied. Save recomputes the exact submitted inputs on the server. Input edits must invalidate the UI preview and clear its acknowledgment. The existing CIDR save API applies the same rule; CLI callers can submit the intended canonical network explicitly.

The range editor accepts at most 128 combined entries, 256 characters per entry, 256 normalized output CIDRs and 65,536 total effective addresses. Oversized previews return exact counts with `can_save=false` and bounded output. Existing per-CIDR limits still apply: `/16` or smaller for IPv4, `/112` or smaller for IPv6. Public space requires explicit permission and a save reason. Empty includes and exclusions explicitly clear search scopes; excluding an entire nonempty include is refused to avoid an accidental clear.

Saving recomputes the preview and stores ordinary effective CIDRs through the existing discovery service. The submitted include/exclude decision and reason are audited. On reload, the editor reads those effective CIDRs; original exclusions are retained in audit rather than as a second authorization layer. The existing CIDR API and CLI still work. Existing sweeps run each scope separately, with IPv6 commands using nmap's IPv6 flag.

**Discovery search scope and inventory target scope are separate.** Saving a range never sets a target's `in_scope`, accepts a discovered asset, starts a sweep or grants permission to scan a target. Existing explicit sweeps and human acceptance remain separate actions. Inventory sources retain their existing in-scope target checks.

## API

All paths are under `/api/v1`. In verified mode, authentication supplies the acting
principal; role and node/target grants control saves, registration and connection
tests. A connection also needs an explicit current account binding and an in-scope
target. `X-Actor` supplies unverified attribution only in loopback development mode.
See [account access](ACCOUNT_ACCESS.md); signing in alone does not grant access.

| Method | Path | Behavior |
|---|---|---|
| GET | `/runtime/context` | Local runtime markers and nonsecret hints; physical host remains unknown |
| POST | `/targets/register-host` | Explicit OS/transport/address/account/reference/scope/reason; returns Target, 201 |
| GET | `/targets/{id}/readiness` | Declaration checks with `ready_for_connection_test`; no connection |
| POST | `/targets/{id}/discover` | Explicit authorized connection test; returns existing AssetFacts |
| POST | `/discovery/scopes/preview` | Include/exclude normalization and exact counts; no state change or typed actor, but verified authentication still applies |
| PUT | `/discovery/scopes/ranges` | Same input plus required reason; returns `{scopes, preview}` |

Registration requires `id`, `name`, `asset_type`, `transport`, `address`, `username`, `credential_ref`, `in_scope` and `reason`; optional fields are `port` and `sudo` (default false). Reasons are limited to 1,000 characters. Range requests use `include`, optional `exclude`, `allow_public` and `scanner_target`; saves additionally require `reason`.

Preview returns `networks`, `network_count`, `input_address_count`, `excluded_address_count`, `address_count`, `truncated`, `can_save`, `normalizations` (`field`, `input`, `normalized`), `requires_normalization_acknowledgment`, `blocking_reasons`, `warnings` and `limits`. Readiness returns `target_id`, `ready_for_connection_test`, `checked="declarations_only"`, `connection_test_route`, `checks`, `warnings` and `runtime`.

Validation for this change uses isolated JSON/SQLite state, fake transports and command-building assertions. It is not evidence of a real container-to-host scan or a real IPv6 sweep. Those environment-specific checks remain part of the existing validation and deployment backlog.
