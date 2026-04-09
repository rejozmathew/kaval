FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV KAVAL_CORE_HOST=0.0.0.0
ENV KAVAL_CORE_PORT=9800
ENV KAVAL_DATABASE_PATH=/data/kaval.db
ENV KAVAL_SETTINGS_PATH=/data/kaval.yaml
ENV KAVAL_DOCKER_SOCKET=/var/run/docker.sock
ENV KAVAL_EXECUTOR_SOCKET=/run/kaval/executor.sock
ENV KAVAL_MIGRATIONS_DIR=/app/migrations
ENV KAVAL_RUNTIME_DIR=/run/kaval
ENV KAVAL_SERVICES_DIR=/app/services
ENV KAVAL_WEB_DIST=/app/src/web/dist

WORKDIR /app

COPY pyproject.toml README.md /app/
COPY src /app/src
COPY migrations /app/migrations
COPY services /app/services

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir .

RUN groupadd --gid 10001 kaval \
    && useradd --create-home --uid 10001 --gid 10001 kaval \
    && groupadd --gid 10002 kaval-exec \
    && useradd --create-home --uid 10002 --gid 10002 kaval-exec \
    && groupadd --gid 10003 kaval-ipc \
    && usermod -a -G kaval-ipc kaval \
    && usermod -a -G kaval-ipc kaval-exec \
    && mkdir -p /data /run/kaval \
    && chown -R kaval:kaval /data

EXPOSE 9800

CMD ["kaval-supervisor"]
