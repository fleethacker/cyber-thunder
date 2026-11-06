FROM node:22-bookworm-slim AS ui
WORKDIR /ui
COPY cyberthunder/ui/package*.json ./
RUN npm ci
COPY cyberthunder/ui/ ./
RUN npm run build

FROM aquasec/trivy:0.71.1@sha256:53570e6911c2361ebe7995228088cf83a6b9b73e7f3cdca44bd8f8f425e80fa7 AS trivy

FROM python:3.12-slim-bookworm
ARG KUBECTL_VERSION=v1.36.4
ARG TARGETARCH
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CT_HOST=0.0.0.0 \
    CT_PORT=8000 \
    WEB_CONCURRENCY=1 \
    CT_STATE_DIR=/var/lib/cyberthunder \
    CT_LLM_BACKEND=template \
    HOME=/var/lib/cyberthunder \
    XDG_CACHE_HOME=/var/lib/cyberthunder/.cache \
    TRIVY_CACHE_DIR=/var/lib/cyberthunder/trivy-cache
RUN KUBECTL_VERSION="$KUBECTL_VERSION" TARGETARCH="$TARGETARCH" python - <<'PYTHON'
import hashlib
import os
from pathlib import Path
import urllib.request

version = os.environ["KUBECTL_VERSION"]
arch = os.environ["TARGETARCH"]
url = f"https://dl.k8s.io/release/{version}/bin/linux/{arch}/kubectl"
binary = urllib.request.urlopen(url).read()
expected = urllib.request.urlopen(url + ".sha256").read().decode().strip()
if hashlib.sha256(binary).hexdigest() != expected:
    raise RuntimeError("kubectl checksum mismatch")
path = Path("/usr/local/bin/kubectl")
path.write_bytes(binary)
path.chmod(0o755)
PYTHON
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
WORKDIR /app
COPY pyproject.toml requirements.txt ./
COPY cyberthunder/ ./cyberthunder/
COPY --from=ui /ui/dist/ ./cyberthunder/ui/dist/
RUN pip install --no-cache-dir . \
    && groupadd --gid 10001 cyberthunder \
    && useradd --uid 10001 --gid 10001 --create-home cyberthunder \
    && mkdir -p /var/lib/cyberthunder \
    && chown 10001:10001 /var/lib/cyberthunder
USER 10001:10001
EXPOSE 8000
ENTRYPOINT ["cyberthunder"]
CMD ["serve"]
