FROM python:3.11-slim

LABEL maintainer="sentinelcloud-advanced"
LABEL service="sentinel-backend"

WORKDIR /app

# Install system dependencies if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ /app/backend/
COPY datasets/ /app/datasets/

RUN mkdir -p /app/data /data

EXPOSE 5050

ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "5050"]
