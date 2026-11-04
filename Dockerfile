FROM ghcr.io/ministryofjustice/hmpps-python:python3.13-alpine AS base

USER 0
# Install aws-cli and docker for ECR authentication and image pulls
RUN apk add --no-cache aws-cli docker

USER 2000
# initialise uv
COPY pyproject.toml .
RUN uv sync

# create the /app/snyk directory for the snyk cache
RUN mkdir -p /app/snyk_cache

COPY --chown=appuser:appgroup  ./snyk_discovery.py /app/snyk_discovery.py
COPY --chown=appuser:appgroup  ./includes ./includes
COPY --chown=appuser:appgroup  ./processes ./processes

CMD [ "uv", "run", "python", "-u", "/app/snyk_discovery.py" ]
