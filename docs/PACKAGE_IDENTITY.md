# Packaged identity and startup

## Guarded container command

Both `Dockerfile` and `Containerfile` run `cyberthunder serve`, with `CT_HOST=0.0.0.0`,
`CT_PORT=8000` and `WEB_CONCURRENCY=1`. The CLI validates the actual bind address,
then `api.app.serve` validates it again before constructing the application and
starting Uvicorn. No Uvicorn CLI flag can silently choose a different address
from the settings inspected by application authentication. Retain one worker
and one replica: browser sessions are local to that process.
The shared serve implementation also passes `workers=1` explicitly. An external
`WEB_CONCURRENCY` override therefore cannot enable multiple workers; the startup
regressions set it to `8` and verify that one worker is retained.

This is a breaking startup correction. An image with no identity configuration
now exits with `development authentication may bind only to loopback` instead
of exposing development identity on the container network. Setting
`CT_AUTH_MODE=oidc` alone is insufficient: network OIDC requires TLS certificate
and key paths plus a valid issuer, API audience and JWKS URL. Only an actually
authenticated mesh deployment may use `CT_AUTH_MODE=mesh` without application
TLS; that mode still validates signed tokens and requires OIDC configuration.
It does not trust a caller-supplied actor name or arbitrary proxy headers.

Native CLI behavior is unchanged. Native development defaults to loopback.
An explicit container `CT_HOST=127.0.0.1` is also loopback-only inside that
container; publishing a Docker port does not make that listener reachable on
the container interface. Do not use development mode for shared access.

Both build definitions now pin Trivy 0.71.1 at digest
`sha256:53570e6911c2361ebe7995228088cf83a6b9b73e7f3cdca44bd8f8f425e80fa7`.
The default `docker build .` uses `Dockerfile`; its former Trivy 0.56.2 did not
meet the managed engine's minimum version. Scanner and guarded-command parity
are covered by a regression over both definitions.

Other build differences remain deliberate or require separate acceptance:
`Dockerfile` builds the UI and runs as UID/GID 10001; `Containerfile` retains
UID/GID 1000, its additional system scanners and its existing source/UI staging
requirements. The default `.dockerignore` excludes some of its COPY inputs
(README, STIG and built UI); it is not a validated alternative Docker build
using that default context. No image or package was rebuilt in this change.
The entrypoint accepts native CLI arguments (`image serve`, `image --help`);
custom diagnostic executables require an explicit `--entrypoint` override.

The existing checked-in image/package archives have not been rebuilt. A future
release must rebuild the image from the corrected source before publishing it.
Invoking Uvicorn directly as a custom container command bypasses the guarded
serve entrypoint and is unsupported. Do not override the worker count.

## First-stage validation

`tests/test_package_identity.py` reads both actual build commands and defaults,
drives the native CLI, and verifies missing configuration and nonloopback dev/TLS
refusals before any listener. Configured startup constructs the real application
and Uvicorn configuration, loads fixture TLS material, and rejects an anonymous
API request. Only the final blocking server runner is replaced; no real image,
cluster, realm or external identity endpoint is used. Stateful cases run with
both JSON and SQLite.

First-stage focused result: **26 passed, 49 existing framework deprecation
warnings in 11.66 seconds** with the shared Python interpreter and the worker
checkout on `PYTHONPATH`.

Manifest, UDS client/claim mapping and protected account-policy provisioning are
a separate integration batch. Gateway login alone does not create an application
browser session. Source deployment configuration must be migrated before an
image with this guard correction is rolled out.
