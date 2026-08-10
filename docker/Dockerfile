FROM python:3.15.0rc1-alpine3.23@sha256:af4dbb84b898095e33a0e18ed70be66e6df4f85740da1a2c266907f31e036075

ARG APP_VERSION=dev

LABEL org.opencontainers.image.title="ScreenOS to Junos Converter" \
      org.opencontainers.image.description="Web and CLI application for converting ScreenOS configuration to Junos" \
      org.opencontainers.image.source="https://github.com/greyinghair/screenos_to_junos_converter" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${APP_VERSION}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN addgroup -S -g 10001 converter \
    && adduser -S -D -H -u 10001 -G converter converter

COPY requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir --disable-pip-version-check \
    -r requirements.txt

COPY --chown=10001:10001 convert.py ./convert.py
COPY --chown=10001:10001 packages ./packages

USER 10001:10001

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()"]

ENTRYPOINT ["gunicorn"]
CMD ["--bind=0.0.0.0:8080", "--workers=2", "--threads=2", "--timeout=120", "--no-control-socket", "--access-logfile=-", "--error-logfile=-", "packages.web_app:create_app()"]
