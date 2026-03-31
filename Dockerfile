FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md /app/
COPY src /app/src
COPY migrations /app/migrations

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir .

RUN useradd --create-home --uid 10001 kaval \
    && mkdir -p /data \
    && chown -R kaval:kaval /app /data

USER kaval

CMD ["python", "-c", "from pathlib import Path; from kaval.database import KavalDatabase; from kaval.pipeline import run_mock_pipeline; db = KavalDatabase(Path('/data/kaval.db'), migrations_dir=Path('/app/migrations')); db.bootstrap(); result = run_mock_pipeline(db); print(result.console_output, flush=True); db.close(); import time; time.sleep(10**9)"]
