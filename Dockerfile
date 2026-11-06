FROM node:22.23.4-bookworm-slim@sha256:5ec23b7c622b00547753bc6ffd78085dd868a68aeb41c8e0a1418f033e13d96d AS ui
WORKDIR /ui
COPY cyberthunder/ui/package*.json ./
RUN npm ci
COPY cyberthunder/ui/ ./
RUN npm run build

FROM aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb AS trivy

FROM python:3.12.16-slim-trixie@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54
ARG KUBECTL_VERSION=v1.36.6
ARG KUBECTL_SHA256_AMD64=29818b6729dc9262b692307470d0558d027725e738be5dd47c760261868a2634
ARG KUBECTL_SHA256_ARM64=35507ef408c3d38849e5d3203e18f8e861db822aa664101a9ced0869edd06046
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
COPY scripts/install_kubectl.py /tmp/install_kubectl.py
RUN python /tmp/install_kubectl.py --version="$KUBECTL_VERSION" --arch="$TARGETARCH" \
    && case "$(uname -m)" in \
        x86_64|amd64) echo "$KUBECTL_SHA256_AMD64  /usr/local/bin/kubectl" ;; \
        aarch64|arm64) echo "$KUBECTL_SHA256_ARM64  /usr/local/bin/kubectl" ;; \
        *) exit 1 ;; \
       esac | sha256sum --check --strict \
    && /usr/local/bin/kubectl version --client=true --output=json \
    && rm /tmp/install_kubectl.py
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
WORKDIR /app
COPY pyproject.toml requirements.txt ./
COPY cyberthunder/ ./cyberthunder/
COPY --from=ui /ui/dist/ ./cyberthunder/ui/dist/
RUN printf '%s\n' 'pip==26.3 --hash=sha256:f3b60b20ffaadd4415ed7957212a38ac63fa4c5fa375bd0f4a797777940fad13' > /tmp/pip-pin.txt \
    && python -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/pip-pin.txt \
    && rm /tmp/pip-pin.txt \
    && python -m pip install --no-cache-dir . \
    && groupadd --gid 10001 cyberthunder \
    && useradd --uid 10001 --gid 10001 --create-home cyberthunder \
    && mkdir -p /var/lib/cyberthunder \
    && chown 10001:10001 /var/lib/cyberthunder
USER 10001:10001
EXPOSE 8000
ENTRYPOINT ["cyberthunder"]
CMD ["serve"]
