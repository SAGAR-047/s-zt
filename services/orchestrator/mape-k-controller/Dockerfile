FROM python:3.11-slim

LABEL maintainer="sentinelcloud-advanced"
LABEL service="mape-k-controller"

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY controller.py .

EXPOSE 8083

ENV OVERRIDE_PORT=8083
ENV PYTHONUNBUFFERED=1

CMD ["kopf", "run", "controller.py", "--verbose"]
