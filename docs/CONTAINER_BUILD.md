# Container build portability

The root `Dockerfile` builds the UI and installs Trivy and kubectl for the
unprivileged application image. Its kubectl install uses an explicitly copied
standard-library Python script and an ordinary `RUN` command. The legacy Docker
builder has been exercised; BuildKit execution remains untested locally. No
Dockerfile heredoc or buildx install is required. A legacy build previously reported success while silently skipping
the heredoc body, leaving kubectl absent.

The default kubectl version remains `v1.36.4`. `KUBECTL_VERSION` accepts stable
`v1.MINOR.PATCH` release names (no prereleases, URLs, leading zeros or path
components). Missing upstream releases fail the build. Explicit `TARGETARCH`
accepts only `amd64` or `arm64`. BuildKit supplies it automatically after the
stage's `ARG TARGETARCH` declaration, as described in the
[Dockerfile reference](https://docs.docker.com/reference/dockerfile/#automatic-platform-args-in-the-global-scope).
When the legacy builder leaves it empty,
the installer maps the running Linux machine's `x86_64`/`amd64` or
`aarch64`/`arm64` architecture. Other native platforms and architectures fail.
Cross builds require a matching target image and working execution/emulation;
an explicit architecture alone does not configure those.

Downloads use HTTPS on `dl.k8s.io` and its `cdn.dl.k8s.io` redirect host, with
15-second socket timeouts, a 120-second shared download deadline checked between
reads, a 256-byte checksum limit and a 128 MiB binary limit. A blocked read can
extend the deadline by at most its socket timeout. The published SHA-256 must
match before a sibling temporary file is made executable and atomically
replaces `/usr/local/bin/kubectl`. Failure preserves any previous executable and
removes the temporary file. The destination is fixed; build arguments cannot
select arbitrary files, URLs or credentials. Checksums downloaded from the same
release service provide integrity checking, not independent release signing.

The build must then successfully execute
`/usr/local/bin/kubectl version --client=true --output=json`. This checks presence
and executability without contacting a cluster. Network access is needed only
to obtain public build dependencies; this check and the runtime smoke can run
without networking. `.dockerignore` admits only this installer from `scripts/`.

For the supported local legacy builder, explicitly select the local socket and
cap build execution at one CPU (choose a unique local tag):

```sh
DOCKER_BUILDKIT=0 docker --host unix:///var/run/docker.sock build \
  --cpu-quota 100000 --cpu-period 100000 --force-rm \
  --tag cyberthunder-local:container-portability .
```

Leave `TARGETARCH` unset to exercise native fallback, or add
`--build-arg TARGETARCH=amd64` for an explicit native amd64 build. For an existing
BuildKit installation, use its ordinary build command with this same Dockerfile;
the legacy builder's CPU flags are not portable BuildKit resource settings.

Run focused tests serially with the repository's Python test environment:

```sh
python -m pytest tests/test_container_tools.py tests/test_package_identity.py
```

The helper tests cover input rejection, both supported architectures, checksum
failure, interrupted/oversized downloads, timeouts, redirect restrictions and
atomic replacement. A real image check should run as UID/GID `10001:10001` with
`--network none --read-only`, disposable writable state, and no operator
credentials. Verify kubectl and Trivy client versions, CLI startup, and local
JSON/SQLite API/state operation; retain image ID, source revision, command,
output, elapsed time and cleanup receipt. Unit tests alone do not establish a
working container or cross-architecture execution.

The separate root `Containerfile` uses the distribution's `kubernetes-client`
package and contains no kubectl heredoc. It is unchanged by this fix and is not
covered by a Dockerfile-only image smoke.
