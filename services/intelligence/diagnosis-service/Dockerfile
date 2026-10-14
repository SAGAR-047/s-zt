FROM python:3.11-slim

LABEL maintainer="sentinelcloud-advanced"
LABEL service="diagnosis-service"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 8081

ENV PORT=8081
ENV PYTHONUNBUFFERED=1

CMD ["gunicorn", "--bind", "0.0.0.0:8081", "--workers", "2", "--threads", "4", "app:app"]
