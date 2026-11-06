# Windows policy and credential file trust

Windows reads of the access policy, selected Kubernetes credential files and the OIDC JWKS cache
now verify native owners and DACLs on the actual file handles. A permissive or unverifiable path
fails closed. No runtime dependency, new configuration flag or automatic ACL repair is introduced.
Existing POSIX owner/mode and descriptor checks remain in place.

## Permission boundary

Trusted identities are the current process user SID, LocalSystem (`S-1-5-18`), built-in
Administrators (`S-1-5-32-544`) and TrustedInstaller
(`S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464`). Comparison uses SIDs, never localized
account names or inferred group membership. A different individual administrator's SID is not
automatically trusted as an owner; provision service files with the service account or Administrators
as owner. OS thread impersonation is unsupported and refused.

The checks distinguish these uses:

| File | Required protection |
| --- | --- |
| `access.json`, public CA/client certificates, JWKS cache | Integrity; other accounts may read |
| Selected kubeconfig (including inline tokens), client private key | Integrity and confidentiality; other accounts may not read data or execute/map the file |
| Every parent directory | Trusted owner; other accounts may not mutate permissions, attributes, extended attributes, delete the directory or delete its children |
| Immediate JWKS cache directory during writes | Parent protection plus no foreign child creation |

Untrusted owners are refused because an owner normally has implicit `WRITE_DAC`, even without an
allow ACE. The `OWNER RIGHTS` SID (`S-1-3-4`) is accepted only after the actual owner passes the trust
check. Windows can use OWNER RIGHTS entries to restrict implicit owner permissions; this module
conservatively rejects untrusted owners regardless. [Windows well-known SIDs](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)

For an untrusted trustee, effective allow entries must not grant file writes/appends, writes to
attributes or extended attributes, `DELETE`, `WRITE_DAC` or `WRITE_OWNER`. A parent's `DELETE_CHILD`
right can defeat a child's own delete restriction, so it is also forbidden. Generic rights are expanded
with `MapGenericMask`; checking only a literal write bit would miss `GENERIC_WRITE` and `GENERIC_ALL`.
Public read and metadata-only read rights do not confer integrity authority.
[File access rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)

This is a conservative protection proof, not an effective-access calculator for arbitrary domain
accounts. The kernel evaluates ACE order and the SIDs in the accessing token. The application rejects
dangerous allow entries even if a deny entry would currently block them; it does not subtract denies
using guessed memberships. Inherit-only entries do not apply to their current object, but effective
inherited entries do. Newly created cache files are checked separately because their inherited ACEs
may differ from those applying to their parent. Null/absent DACLs, unknown or conditional/object ACE
types, oversized ACLs and unavailable native APIs are refused. The kernel must also permit the
service's actual file open. [Windows access-check semantics](https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object)

## Stable reads and publication

`security.file_trust.open_protected(path, private=False)` opens each ancestor with
`FILE_FLAG_OPEN_REPARSE_POINT`, validates it, and holds its handle without `FILE_SHARE_DELETE`.
The leaf file is opened without write/delete sharing. `GetSecurityInfo` reads the descriptor from that
handle; native file identity and final-path checks bind it to the intended local path. Identity,
owner and DACL are checked again before the context exits. Policy parsing stays inside this protected
context. [Handle security descriptors](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo),
[Windows file-sharing rules](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)

Junctions, symlinks/reparse points, hardlinked files, device/UNC/network paths, alternate data streams
and ambiguous Windows filename aliases are refused. The local volume must advertise persistent
ACL support. Missing parent directories or missing native API support are failures; a missing cache
leaf remains an ordinary cache miss. Reads and cache size limits remain bounded by their callers.

JWKS writes hold the parent chain, check any existing destination, verify the newly created temporary
file's DACL before writing, recheck before atomic replacement and check the resulting bytes. Private
credential checks run again through the existing Kubernetes guard before each subprocess operation.
Kubernetes evidence reports `protection: "windows_dacl"` only after these checks succeed. Failures keep
the existing sanitized policy, authentication and credential error contracts; no credential contents
or raw native diagnostics enter responses.

## Provisioning a new local directory

An administrator can use the following PowerShell example for a **new, empty** directory. Substitute
the numeric SID of the actual service account. Run this during deployment, not on an existing tree;
the application never executes these commands. All ancestors must also satisfy the integrity rules.
The example grants the service, SYSTEM and Administrators full control and disables inherited ACEs.

```powershell
$ctTrustPath = 'C:\CyberThunderTrust'
$ctServiceSid = 'S-1-5-21-REPLACE-WITH-SERVICE-ACCOUNT-SID'
$ctSid = [System.Security.Principal.SecurityIdentifier]::new($ctServiceSid)
if (Test-Path -LiteralPath $ctTrustPath) { throw 'Choose a new empty directory' }
New-Item -ItemType Directory -Path $ctTrustPath -ErrorAction Stop | Out-Null
$ctAcl = [System.Security.AccessControl.DirectorySecurity]::new()
$ctAcl.SetAccessRuleProtection($true, $false)
$ctAcl.SetOwner([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
foreach ($ctIdentity in @($ctSid.Value, 'S-1-5-18', 'S-1-5-32-544')) {
    $ctRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        [System.Security.Principal.SecurityIdentifier]::new($ctIdentity),
        'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
    $ctAcl.AddAccessRule($ctRule)
}
Set-Acl -LiteralPath $ctTrustPath -AclObject $ctAcl -ErrorAction Stop
if (Get-ChildItem -LiteralPath $ctTrustPath -Force) { throw 'Directory must be empty' }
```

Create service-owned credential/cache subdirectories beneath this root. New files inherit its DACL;
moved files can retain their previous ACL, so validate after provisioning. Configure existing policy,
kubeconfig and JWKS path settings to use these locations. Test under the actual service identity:

```python
from cyberthunder.security.file_trust import open_protected
with open_protected(r"C:\CyberThunderTrust\credentials\selected.yaml", private=True):
    pass  # Prove protection without displaying or reading credential bytes.
```

Do not grant a broad Users/Authenticated Users group write access to make a failure disappear.
Choose a protected ancestor instead. An explicit `WRITE_DAC`, `DELETE` or parent `DELETE_CHILD`
grant is unsafe even when ordinary file data write permission is absent.

## Test provisioning and limits

On Windows, the default pytest session deliberately creates a disposable `ct-trust-tests-*` directory
at the temporary volume's root and applies a protected native DACL to that new directory. Pytest
`tmp_path`/`tmp_path_factory` and in-process `tempfile` fixtures use descendants of it. This avoids
silently inheriting permissions from a developer's writable home/temp ancestors. ACL mutation helpers
are restricted to registered temporary roots; negative tests alter only disposable files/directories.
An explicit `--basetemp` remains honored and must already have protected ancestors. No production
validator is patched off, and no live directory permissions are changed. POSIX fixture paths are unchanged.
At session teardown, the fixture closes retained test SQLite backends beneath its own disposable root
before deleting it; test request contexts can otherwise keep database handles open on Windows.

Tests exercise actual Windows security descriptors and sharing violations, including public/private
read distinctions, null DACLs, generic permissions, foreign trustees, OWNER RIGHTS, deny-plus-allow
semantics, parent deletion/ACL rights, inherited cache permissions, junction/replacement races,
policy changes during parsing and credential guard rechecks. The owner predicate is tested against an
actual descriptor with a deliberately restricted trusted SID set; tests do not create another Windows
account or enable restore privileges just to change ownership.

The checks trust the service account, SYSTEM and the named administrative principals. They do not
defend against those principals, accounts exercising backup/restore/take-ownership privileges, kernel
compromise, physical/offline disk access or previously copied credentials. No privileges are enabled
by this module. Domain-specific conditional ACLs, SMB shares,
remote filesystems, ReFS deployment and service-account rollout require separate acceptance; local
Windows fixtures do not establish enterprise effective access or validate a live identity provider.
