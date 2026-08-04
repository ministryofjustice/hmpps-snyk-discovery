FROM ghcr.io/ministryofjustice/hmpps-python:python3.13-alpine AS base

# initialise uv
COPY pyproject.toml .
RUN uv sync

# create the /app/snyk directory for the snyk cache
RUN mkdir -p /app/snyk_cache

COPY --chown=appuser:appgroup  ./snyk_discovery.py /app/snyk_discovery.py
COPY --chown=appuser:appgroup  ./includes ./includes
COPY --chown=appuser:appgroup  ./processes ./processes

CMD [ "uv", "run", "python", "-u", "/app/snyk_discovery.py" ]
