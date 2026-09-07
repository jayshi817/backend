FROM python:3.12-slim

WORKDIR /app

COPY ZINHOST_Railway.zip /tmp/ZINHOST_Railway.zip

RUN apt-get update \
    && apt-get install -y --no-install-recommends unzip nodejs npm \
    && rm -rf /var/lib/apt/lists/* \
    && unzip -q /tmp/ZINHOST_Railway.zip -d /tmp/zinhost \
    && cp -a /tmp/zinhost/. /app/ \
    && rm -rf /tmp/zinhost /tmp/ZINHOST_Railway.zip \
    && pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]