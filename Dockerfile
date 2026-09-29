FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PHISHSCAN_HOST=0.0.0.0 \
    PORT=8000 \
    PHISHSCAN_CACHE_DIR=/data

WORKDIR /app
COPY pyproject.toml README.md ./
COPY phishscan ./phishscan
RUN pip install . \
 && useradd --system --uid 10001 --home-dir /data phishscan \
 && mkdir -p /data && chown phishscan /data

USER phishscan
VOLUME /data
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=4s --start-period=10s --retries=3 \
  CMD python -c "import os,urllib.request as u; u.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT','8000'), timeout=3)"

CMD ["phishscan", "serve"]
