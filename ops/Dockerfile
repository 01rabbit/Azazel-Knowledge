# Azazel-CTI runtime image (design S11). One image, two services:
# `api` runs gunicorn/uvicorn workers; `worker` runs `python -m
# azazel_cti.worker`. Which one a container is depends only on the
# command docker-compose.yml gives it -- see ops/docker-compose.yml.

FROM python:3.11-slim

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin azazel

WORKDIR /app

COPY pyproject.toml ./
COPY src ./src
COPY config ./config
COPY tools ./tools
COPY azctl ./azctl

# `.[api]` pulls in fastapi/pydantic/uvicorn (used only by the `api`
# service); `gunicorn` is the process manager gunicorn -k
# uvicorn.workers.UvicornWorker requires and isn't itself an
# azazel_cti dependency, so it's installed alongside rather than added
# to pyproject.toml's core dependency list (core packages stay
# stdlib+PyYAML+idna+PyNaCl per design S1).
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir '.[api]' gunicorn

RUN mkdir -p /app/var /app/data /app/secrets \
    && chown -R azazel:azazel /app

USER azazel
ENV PYTHONUNBUFFERED=1
ENV AZAZEL_ROOT=/app

# Overridden per-service in docker-compose.yml.
CMD ["python", "-m", "azazel_cti.worker", "--once"]
