# vSphere inventory discovery (DIS-01)

The `vsphere` discovery source reads VM and ESXi host inventory from an explicitly
registered vCenter or standalone ESXi endpoint. It produces discovery candidates;
it does not register targets, assign credentials to guests, authorize scans, change
VM power state, or apply fixes. Operators still review and accept each candidate
through the existing discovery decision workflow.

The existing `hypervisor: vmware` source remains the Workstation `vmrun list` and
VMX-file reader. The new `hypervisor: vsphere` source is independent and does not
open the inventory target's SSH/WinRM transport.

## API and privileges

The client uses the vSphere Web Services SOAP endpoint at `/sdk`, with the 6.5
request schema and fixed property names. It accepts service descriptions for
`VirtualCenter` and `HostAgent`. The flow reads service content, logs in, creates
an ephemeral container view for `VirtualMachine` and `HostSystem`, and retrieves
selected properties through `RetrievePropertiesEx` and
`ContinueRetrievePropertiesEx`. It then attempts view destruction and logout.
No VM, host, guest, datastore or configuration mutation method is exposed.

Provision a dedicated inventory account with the built-in Read-only role and
access only to the intended inventory hierarchy. The source cannot verify that
an operator has assigned that role correctly; effective permissions and both
server types require acceptance against a real deployment.

Official API references:

- [Service instance and service content](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.ServiceInstance.html)
- [Session login and logout](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.SessionManager.html)
- [Session-scoped container views](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.view.ViewManager.html)
- [Bounded property retrieval and continuation](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vmodl.query.PropertyCollector.html)

## Explicit endpoint, trust and development credentials

The source requires an in-scope inventory target with a literal management IP in
`address`. That IP must also lie in a saved discovery range selected for this
sweep. The endpoint's DNS name is used only for HTTPS Host/SNI and certificate
verification; the socket connects directly to the reviewed IP without DNS,
redirects or proxy discovery. An IP-literal endpoint must match `address`.

Example options on an existing vCenter appliance inventory record:

```yaml
address: 10.20.0.2
in_scope: true
options:
  hypervisor: vsphere
  vsphere:
    endpoint: https://vc.lab/sdk
    tls_trust: ca_file
    ca_file: /run/trust/vcenter-ca.pem
    username: inventory-reader@lab
    credential_ref: VC_INVENTORY
```

Select `tls_trust: system` and omit `ca_file` to explicitly use the runtime trust
store. Custom CA files must be absolute paths; native Windows deployments use an
absolute Windows path. Certificates and hostnames are always verified with TLS
1.2 or newer. There is no insecure TLS option or trust-on-first-use behavior.
Only HTTPS `/sdk` is accepted, without URL credentials, query or fragment.

In explicitly configured development mode only, `credential_ref` selects
`CT_CRED_VC_INVENTORY` from the process environment. Passwords are never inline
options. There is no fallback to a bare environment variable, an inventory SSH
credential, `.netrc`, a prior session or an interactive login. Session cookies
are per-client memory only. Native and container deployment use Python's
standard library; no new package, executable or image dependency is needed.
For containers, supply the named development secret explicitly and mount custom
trust files read-only. Do not switch a verified deployment to development mode
to enable this source.

## Verified-mode integration seam

Verified mode fails before reading a password or opening a socket, with
`vsphere:verified_binding_unavailable` after the account's `discover` operation
and resource permission are checked. The current delegated credential model
only binds SSH, WinRM, kubeconfig and simulated transports. A grant for one of
those transports cannot authorize vSphere HTTPS access.

The smallest required integration is an explicit vSphere credential binding for
the requester, `discover` action, inventory target authorization generation, and
exact HTTPS endpoint. It must select the read-only username and secret reference
and supply a guard that rechecks session, resource scope, target configuration
and credential-grant revocation before every call. Credential-use audit evidence
must identify the binding without its secret. That belongs to the central
credential/context owner; this patch does not add an optional hook or shared
credential fallback around that boundary.

## Bounds, revocation and evidence

- Maximum 250 objects per page, 20 pages and 5,000 unique objects. Duplicate
  object references deduplicate; conflicting repeats or repeated continuation
  tokens fail the run rather than publishing a partial snapshot.
- Maximum 2 MiB response body, 16 MiB across the client, 10 seconds per HTTP call
  and 60 seconds for the client flow. A socket watchdog interrupts stalled
  reads; compressed responses, ambiguous framing, DTDs and entity declarations
  are refused. Native HTTP header limits also apply.
- Kill, target configuration/scope and the exact saved range grants are checked
  before connections and calls and after responses. A wider replacement range
  does not renew a revoked grant. Revocation prevents further network calls,
  including cleanup. The server must expire a session/view when guarded cleanup
  cannot complete. Cookies are discarded locally in every outcome.
- Any client failure aborts the discovery run without publishing that run's
  observations. Remote fault messages, response bodies, passwords and session
  cookies are omitted from errors and audit records. Source start/finish audit
  records identify the endpoint, target and object/candidate counts.

Object identity uses a hash of endpoint, service instance, object type and
managed-object reference. Names are display data, so duplicate names remain
distinct and renames keep identity. An endpoint alias or unregister/re-register
can create a new identity; no cross-endpoint identity inference is attempted.
Reported UUIDs and VM host references are retained as evidence. Network-probe
observations remain separate from these inventory objects rather than being
joined by IP or MAC alone.

Powered-off VMs, VMs without an IP, and hosts without a usable reported address
remain metadata-only candidates. A reported guest address is not proof of
reachability. Returned addresses outside the selected ranges are excluded;
objects whose usable reported addresses are all outside those ranges are
dropped. Objects without usable IP evidence remain tied to the scoped endpoint.
Shared reported IPs are flagged and left unresolved instead of attaching two
objects to an inventory target through the same address. ESXi host evidence does
not imply an ESXi remediation adapter exists.

## Local validation and external acceptance

Run with `PYTHONPATH` set to this checkout and the shared interpreter:

```powershell
$env:PYTHONPATH = (Get-Location).Path
& 'C:/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Scripts/python.exe' -m pytest tests/discovery
```

The new tests use synthetic SOAP responses and fake sockets only. They cover
both server descriptions, powered-off/addressless guests, Unicode names,
duplicate names and stable IDs, shared IPs, pagination/limits, scoped IPv4/v6
observations, TLS configuration, pinned connections, timeout interruption,
secret-safe failures and guard revocation. JSON and SQLite tests reopen saved
observations and confirm inventory/scope are not implicitly changed.

No live vCenter or ESXi endpoint was exercised. External acceptance still needs
the verified credential binding, real Read-only role and certificate-chain
validation, supported-server compatibility, and actual large-inventory latency
and pagination evidence. Fixtures establish the proposal and refusal behavior,
not fleet readiness or completed delegated-account integration.
