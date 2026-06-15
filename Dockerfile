FROM ghcr.io/ministryofjustice/hmpps-python:python3.13-alpine AS base

# initialise uv
COPY pyproject.toml .
RUN uv sync

# create the /app/snyk directory for the snyk cache
RUN mkdir -p /app/snyk_cache
ENV DOCKER_CONFIG=/app/.docker
RUN mkdir -p /app/.docker \
	&& touch /app/.docker/config.json \
	&& chown -R appuser:appgroup /app/.docker \
	&& chmod 700 /app/.docker \
	&& chmod 600 /app/.docker/config.json

COPY --chown=appuser:appgroup  ./snyk_discovery.py /app/snyk_discovery.py
COPY --chown=appuser:appgroup  ./includes ./includes
COPY --chown=appuser:appgroup  ./processes ./processes

CMD ["uv", "run", "python", "-u", "/app/snyk_discovery.py"]
