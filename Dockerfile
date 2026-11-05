FROM node:22-bookworm-slim AS ui
WORKDIR /ui
COPY cyberthunder/ui/package*.json ./
RUN npm ci
COPY cyberthunder/ui/ ./
RUN npm run build

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CT_STATE_DIR=/var/lib/cyberthunder \
    CT_LLM_BACKEND=template
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
CMD ["uvicorn", "cyberthunder.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
