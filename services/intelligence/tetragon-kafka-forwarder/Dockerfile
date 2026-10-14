FROM python:3.11-slim

LABEL maintainer="sentinelcloud-advanced"
LABEL service="tetragon-kafka-forwarder"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 8082

ENV PORT=8082
ENV PYTHONUNBUFFERED=1

# Mount tetragon export and falco logs via hostPath volumes
CMD ["python", "app.py"]
