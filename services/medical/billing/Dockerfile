FROM python:3.11-slim

LABEL maintainer="sentinelcloud-advanced"
LABEL service="billing"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 5003

ENV PORT=5003

CMD ["gunicorn", "--bind", "0.0.0.0:5003", "--workers", "2", "--threads", "4", "app:app"]
