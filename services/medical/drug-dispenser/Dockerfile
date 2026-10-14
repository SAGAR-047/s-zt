FROM python:3.11-slim

LABEL maintainer="sentinelcloud-advanced"
LABEL service="drug-dispenser"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 5001

ENV PORT=5001

CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--workers", "2", "--threads", "4", "app:app"]
