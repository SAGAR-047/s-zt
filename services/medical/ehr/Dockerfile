FROM python:3.11-slim

LABEL maintainer="sentinelcloud-advanced"
LABEL service="ehr"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 5002

ENV PORT=5002

CMD ["gunicorn", "--bind", "0.0.0.0:5002", "--workers", "2", "--threads", "4", "app:app"]
