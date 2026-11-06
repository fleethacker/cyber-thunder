# Podinfo package image

The application image is pinned to the multi-platform index digest
`sha256:f107b0acc7f9350212571d8eb223ec004f6e20cf22083fc19b112280278827c9`.
Both `zarf.yaml` and `values.yaml` use the same release-tag-plus-digest reference.
The 6.10.1 chart renders `repository:tag`, so the digest is included in the tag
value; an unsupported `image.digest` value would not pin the rendered workload.

On 2026-11-06 UTC, the bytes returned by the public
[registry manifest endpoint](https://ghcr.io/v2/stefanprodan/podinfo/manifests/6.10.1)
hashed to the registry's `Docker-Content-Digest`. The index includes Linux amd64,
arm/v7 and arm64 manifests. This establishes the selected content identifier;
it does not establish image signing, vulnerability status or deployment acceptance.
The [upstream deployment template](https://github.com/stefanprodan/podinfo/blob/6.10.1/charts/podinfo/templates/deployment.yaml)
defines how the image values are rendered.

Validation on that date: `uds zarf dev lint packages/podinfo` passed, and rendering
the actual 6.10.1 OCI chart with `values.yaml` produced the same digest-pinned
Deployment image. The chart registry reported digest
`sha256:278638a6c1795c3b426f88d8f129f36f80589c0a4082451ce20a2d48aac3e587`.
This change pins the application image; optional upstream chart test-hook images
and the chart's own release reference are separate dependencies.

For an update, review the new release and its multi-platform manifest, check the
downloaded manifest hash against the registry digest, update both references,
then render the chart and rebuild the Zarf package. Rebuilding and redeploying an
already published package are separate operations; editing these sources does
not replace an existing deployment or cached package.
