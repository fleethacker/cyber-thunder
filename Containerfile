FROM aquasec/trivy:0.71.1@sha256:53570e6911c2361ebe7995228088cf83a6b9b73e7f3cdca44bd8f8f425e80fa7 AS trivy

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CT_HOST=0.0.0.0 \
    CT_PORT=8000 \
    CT_STATE_DIR=/var/lib/cyberthunder \
    CT_UI_DIST=/app/cyberthunder/ui/dist \
    HOME=/var/lib/cyberthunder \
    XDG_CACHE_HOME=/var/lib/cyberthunder/.cache \
    TRIVY_CACHE_DIR=/var/lib/cyberthunder/trivy-cache

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        kubernetes-client \
        openscap-scanner \
        openscap-utils \
    && rm -rf /var/lib/apt/lists/*

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

RUN useradd --create-home --uid 1000 --user-group cyberthunder \
    && mkdir -p /app /var/lib/cyberthunder \
    && chown -R cyberthunder:cyberthunder /app /var/lib/cyberthunder

WORKDIR /app
COPY --chown=cyberthunder:cyberthunder pyproject.toml README.md requirements.txt ./
COPY --chown=cyberthunder:cyberthunder cyberthunder ./cyberthunder
COPY --chown=cyberthunder:cyberthunder STIG ./STIG

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

USER cyberthunder
EXPOSE 8000
VOLUME ["/var/lib/cyberthunder"]
ENTRYPOINT ["cyberthunder"]
CMD ["serve"]
