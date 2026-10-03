FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml ./

RUN pip install --no-cache-dir .

COPY aegis/ ./aegis/

RUN groupadd -r aegis && useradd -r -g aegis aegis \
    && mkdir -p /app/state /app/reports \
    && chown -R aegis:aegis /app

USER aegis

EXPOSE 8000

CMD ["uvicorn", "aegis.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
