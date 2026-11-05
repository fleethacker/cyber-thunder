# Cyber Thunder System Review Technical Specification

## 1. Purpose and Scope

Cyber Thunder is an offline-first cyber defense workflow that discovers assets, normalizes security findings, explains risk, proposes vetted remediation, requires approval before change, verifies the result, and rolls back failed changes. The system is designed for isolated or low-bandwidth enclaves. Detection is performed by deterministic scanners, parsers, and adapter checks; model output is used for explanatory text only and is not an execution source.

This document answers the core review questions:

- What LLM models are being used.
- What security scanning software is being used.
- What ports and connections are being exposed.
- How security fix recommendations are generated.
- Additional implementation details relevant to system review.

## 2. LLM and Model Usage

### 2.1 Default Deployed Behavior

The Kubernetes deployment and container image default to:

| Setting | Default in deployment/image | Effect |
| --- | --- | --- |
| `CT_LLM_BACKEND` | `template` | No LLM call is made for explanations. The application generates deterministic template explanations from finding and fix metadata. |
| `CT_OPENAI_API_KEY` | unset/optional | No OpenAI API call is made unless a key is supplied and the cluster baseline request explicitly asks for it. |

In the packaged Kubernetes deployment, explanations work without any model server. This is the fielded-safe default for disconnected operation.

### 2.2 Local Explanation Model Options

The explain layer supports three backends:

| Backend | Configuration | Network path | Model default |
| --- | --- | --- | --- |
| Template | `CT_LLM_BACKEND=template` | none | none |
| Ollama | `CT_LLM_BACKEND=ollama`, `CT_LLM_URL` | local/enclave model server, default `http://localhost:11434` | `gemma3:4b`, fallback `qwen2.5:3b` |
| OpenAI-compatible local server | `CT_LLM_BACKEND=openai` or `openai-compat`, `CT_LLM_URL` | local/enclave `/v1/models` and `/v1/chat/completions` endpoint | `CT_LLM_MODEL`, default `gemma3:4b` |

Ollama uses `GET /api/tags` for availability and `POST /api/generate` with JSON mode for generation. The OpenAI-compatible backend is intended for local or enclave servers such as llama.cpp server, LM Studio, or vLLM, not necessarily the public OpenAI service.

### 2.3 Optional OpenAI Cloud Use

There is a separate optional cluster-baseline description path:

| Use | Trigger | Model | Endpoint | Data sent |
| --- | --- | --- | --- | --- |
| Namespace risk summary decoration | `POST /api/v1/cluster/baseline` with `{"use_openai": true}` and `CT_OPENAI_API_KEY` set | `CT_OPENAI_MODEL`, default `gpt-4o-mini` | `https://api.openai.com/v1/responses` | Namespace risk profile fields, vulnerability summaries, and top vulnerability rows |

This path is opt-in. The deterministic namespace risk profile is generated and stored even when OpenAI is unavailable. The package documentation states that OpenAI egress to `api.openai.com:443` must be explicitly allowed and is not configured by default.

### 2.4 Model Safety Boundaries

The explain model is not an agent and does not call tools. It receives a single normalized finding and an allowed citation list, then returns JSON fields:

- `risk`
- `impact`
- `plan`
- `citations`

The validator rejects unusable JSON, unknown identifiers, missing citations, and command-like text. If generation fails or validation fails, the system falls back to a deterministic template explanation. Model output is display text only and is never passed to a transport for execution.

## 3. Security Scanning Software and Inputs

Cyber Thunder combines scanner imports, adapter-native checks, and locally executed scanner tools.

### 3.1 Imported Scanner Formats

| Input | Purpose | Notes |
| --- | --- | --- |
| ACAS / Nessus `.nessus` export | Vulnerability and compliance import | Parsed offline. The system does not contact ACAS/Nessus. Host names must be explicitly mapped to inventory targets. |
| CKLB / Evaluate-STIG / STIG Viewer 3 JSON checklist | STIG checklist import and merge | Used especially for Windows and external STIG workflow results. |
| XCCDF / SCAP / OpenSCAP / SCC-style results | STIG and benchmark result normalization | Parsed into the common `Finding` schema. |
| Trivy JSON | CVE findings for root filesystems and images | Parsed offline; no online lookup is performed by the parser. |

### 3.2 Tools Executed by Cyber Thunder

| Tool | Where used | How used |
| --- | --- | --- |
| OpenSCAP `oscap` | Linux targets | If present, runs `oscap xccdf eval` on the target host against SSG content or a configured DISA datastream. |
| Trivy | Linux, container hosts, Kubernetes image baseline | Runs with `--skip-db-update` by default. Requires a staged vulnerability database for disconnected operation. The image includes Trivy `v0.56.2`. |
| `kubectl` | Kubernetes adapter and cluster baseline | Read-only `kubectl get ... -o json`, `kubectl version`, and optional kubelet `/configz` where allowed. The image includes kubectl `v1.36.4`. |
| Docker / Podman CLI | Container host adapter | Reads `version`, `info`, `ps`, `inspect`, and image metadata. |
| PowerShell / WinRM scripts | Windows adapter | Collects registry, local security policy, audit policy, local users/groups, files, services, and WMI/CIM data for native checks and the Windows SCAP evaluator. |
| `nmap` | Discovery, when used | Scoped discovery only. Public address space requires explicit scope authorization. |

### 3.3 Built-In Deterministic Checks

The adapters include deterministic checks and hunt logic for:

- Linux host STIG checks, package/CVE inventory, and hunt signals.
- Windows STIG checks, CKLB merge, SCAP OVAL evaluation, and hunt signals.
- Kubernetes configuration checks, workload checks, known-good exceptions, and cluster survey.
- Container runtime configuration and image vulnerability checks.
- Cisco IOS / IOS-XE STIG checks from parsed running configuration.

The scanner orchestration is read-only. State-changing remediation is only available after proposal and approval.

## 4. Ports, Services, and Network Connections

### 4.1 Inbound Application Exposure

| Deployment mode | Binding / exposure | Notes |
| --- | --- | --- |
| Standalone CLI/API server | `CT_HOST`, default `127.0.0.1`; `CT_PORT`, default `8000` | Local-only by default. |
| Container image | container port `8000`; command binds `0.0.0.0:8000` inside the container | The runtime exposure depends on the container host or orchestrator. |
| Plain Kubernetes manifest | `ClusterIP` Service `cyberthunder` port `80` -> container port `8000` | Internal service only. Docs use `kubectl port-forward service/cyberthunder 8000:80` for admin diagnostics. No ingress/auth is configured in this manifest. |
| UDS package | tenant gateway host `https://cyberthunder.<domain>` -> service port `80` -> target port `8000` | Protected by UDS Authservice / Keycloak SSO. Allowed group: `/UDS Core/Admin`. |

### 4.2 Outbound / Egress Connections

| Connection | Default port | Purpose | Default status |
| --- | --- | --- | --- |
| Kubernetes API | `443` via `https://kubernetes.default.svc` or configured kubeconfig | Cluster survey and Kubernetes scans | Enabled for in-cluster read-only survey in Kubernetes deployments. |
| Approved SSH targets | target configured port, default `22`; UDS package variable `SCAN_SSH_PORT` | Linux, container host, Cisco, and other SSH-based targets | Requires inventory scope and network policy/egress allowance. |
| WinRM targets | `5985` HTTP or `5986` HTTPS | Windows hosts | Requires target configuration and credentials. |
| Local/enclave model server | default `11434` for Ollama; configured for compatible servers | Optional LLM explanations | Not used in template mode; egress must be allowed when configured. |
| OpenAI API | `443` to `api.openai.com` | Optional namespace risk description only | Disabled unless API key, explicit request, and egress exist. |
| DISA/STIG content hosts | `443` to `www.cyber.mil` and `dl.dod.cyber.mil` | Optional STIG/SCAP content pull when link is up | Allow-listed in code; HTTPS only; redirects must stay on allowed hosts. |
| Image registries | registry-specific, usually `443` | Trivy image baseline must pull or inspect target images | Environment-specific and not bundled by default. |

### 4.3 Kubernetes RBAC and Service Account Access

The Kubernetes deployment uses a dedicated `cyberthunder` service account and read-only RBAC. It can list/get:

- namespaces, nodes, pods, service accounts, services
- deployments, statefulsets, daemonsets, replicasets in the package manifest
- cronjobs and jobs
- role bindings and cluster role bindings
- network policies
- `/version`

The default Kubernetes RBAC does not grant Secret reads and does not grant mutation verbs for Kubernetes remediation. The deployment mounts a projected service account token and a generated kubeconfig for the local cluster.

### 4.4 Credentials and Secrets

Target credentials are not stored in inventory. They are resolved at runtime from:

- `CT_CRED_<credential_ref>` environment variables for passwords.
- Read-only mounted key files for SSH.
- Optional Kubernetes Secret `cyberthunder-target-credentials` mounted at `/etc/cyberthunder/targets`.

The scanner service account is not granted permission to read Kubernetes Secrets.

## 5. Security Fix Recommendation Generation

### 5.1 Finding Normalization

All scanner outputs and adapter checks are normalized into the `Finding` schema. A finding includes:

- host / target ID
- asset type
- source
- rule ID, STIG ID, group ID, CVE, CCI, IAVM, or other citations
- severity and status
- evidence
- optional fix text or fix script from scanner content
- optional `fix_ref`

### 5.2 Fix Library Resolution

Recommendations are generated by resolving a finding to a `FixEntry` in the vetted remediation library. Adapters contribute fix entries for their asset types. A `FixEntry` declares:

- `fix_ref`
- title
- asset type
- rule IDs / STIG IDs / CVEs it applies to
- payload or runbook steps
- disruption, reboot, and service restart flags
- rollback kind and rollback plan
- before-state capture requirements
- verification checks
- citations and source

The engine may also wrap a ComplianceAsCode / SCAP fix script from evaluated scanner content into a dynamic `FixEntry`, but only for real Linux targets and only from scanner benchmark content, not from model output or operator free text.

### 5.3 Role of the LLM in Recommendations

The LLM does not create executable fixes. It may produce explanatory `risk`, `impact`, and `plan` text for an already detected finding and already resolved fix. If no explanation exists, proposals use deterministic template risk text.

Executable remediation comes only from:

- adapter-supplied `FixEntry` payloads,
- vetted runbooks,
- Kubernetes manifest fixes,
- Cisco configuration snippets generated by deterministic rules,
- Windows PowerShell fixes from the Windows adapter,
- ComplianceAsCode / scanner benchmark fix scripts when wrapped as dynamic fixes.

### 5.4 Proposal, Approval, Apply, Verify, Rollback

The recommendation workflow is:

1. Scanner detects a finding.
2. Engine resolves a vetted fix.
3. Engine creates a proposal with fix preview, rollback plan, risk text, citations, and fix digest.
4. A human operator or signed automation policy approves the proposal.
5. Apply captures before-state, runs the approved payload only, and records audit events.
6. Verify re-checks the rule and health.
7. Failed verification triggers rollback for payload fixes.
8. Manual rollback is available for applied or verified proposals.

The engine refuses to execute a fix if the current fix payload differs from what was approved.

## 6. Security Controls Relevant to Review

| Control | Implementation |
| --- | --- |
| Scope guardrail | Inventory is the authority. `assert_in_scope()` is called before scan, cluster access, apply, and rollback paths. |
| Human approval | Approval-gated transitions reject reserved machine actors such as `agent`, `llm`, and `system`. |
| Kill switch | Blocks scans between targets and blocks state-changing apply/rollback edges. |
| Auditability | Audit log is append-only and hash-chained. Scans, findings, proposals, approvals, denials, applies, verifies, rollbacks, kill switch events, policy updates, inventory updates, and explanation generation are logged. |
| Model output validation | JSON-only schema, citation allow-list, length clamps, unknown identifier rejection, command-like text rejection, template fallback. |
| Secret handling | Inventory stores credential references, not passwords. Optional model API key is read from process environment and not serialized in settings, prompts, logs, audit records, or reports. |
| Kubernetes least privilege | Read-only RBAC for survey and scan inputs; no Secret read; no Kubernetes mutation verbs in default package RBAC. |
| Content pull allow-list | DISA content pulls are HTTPS-only to `www.cyber.mil` and `dl.dod.cyber.mil`; non-allow-listed hosts and non-443 ports are refused. |
| Runtime hardening | Kubernetes deployment runs non-root, drops all Linux capabilities, disallows privilege escalation, uses seccomp `RuntimeDefault`, and uses a read-only root filesystem with writable PVC and `/tmp`. |

## 7. Operational Assumptions and Current Limits

- The default package uses one replica and one API worker with persistent file-backed state.
- The plain Kubernetes manifest exposes only an internal Service and does not configure authentication; authenticated ingress is provided by the UDS package.
- Trivy database content and private registry access are not bundled. They must be staged or allowed by the environment.
- Optional cloud OpenAI summaries are unsuitable for disconnected operation unless explicitly approved and egress is available.
- Scanner imports may contain sensitive evidence from external tools; normalized findings and reports should be handled as sensitive security data.
- SSH host key handling currently auto-adds missing keys for range use; fleet deployment should pin known hosts before operational use.
- Discovery and scanning are constrained by inventory scope, discovery scopes, target credentials, network policy, and the kill switch.

## 8. Implementation Traceability

| Topic | Primary files |
| --- | --- |
| Runtime settings and default models | `cyberthunder/config.py`, `Dockerfile`, `deploy/kubernetes/cyberthunder.yaml`, `packages/cyberthunder/app.yaml` |
| LLM backends and validation | `cyberthunder/explain/backends.py`, `cyberthunder/explain/service.py`, `cyberthunder/explain/prompts.py`, `cyberthunder/explain/validator.py`, `docs/MODEL_AUTH.md` |
| Scanner orchestration | `cyberthunder/scan.py`, `cyberthunder/adapters/*`, `cyberthunder/parsers/*` |
| ACAS/Nessus import | `cyberthunder/parsers/nessus.py`, `cyberthunder/ingest/scanner_results.py`, `docs/SCANNER_IMPORT.md` |
| SCAP / OpenSCAP | `cyberthunder/scap/`, `cyberthunder/adapters/linux/adapter.py`, `cyberthunder/adapters/windows/adapter.py`, `docs/SCAP.md` |
| Cluster baseline and optional OpenAI descriptions | `cyberthunder/cluster/service.py`, `cyberthunder/api/routes/cluster.py` |
| Fix library and remediation engine | `cyberthunder/remediation/library.py`, `cyberthunder/remediation/engine.py` |
| Inventory, scope, and transports | `cyberthunder/inventory/targets.py`, `cyberthunder/transport/*` |
| Kubernetes deployment and exposure | `deploy/kubernetes/cyberthunder.yaml`, `deploy/kubernetes/README.md`, `packages/cyberthunder/uds.yaml`, `packages/cyberthunder/README.md` |
| Architecture overview | `docs/ARCHITECTURE.md` |
