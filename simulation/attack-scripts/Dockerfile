FROM python:3.11-slim

LABEL maintainer="sentinelcloud-advanced"
LABEL purpose="attack-simulation"

RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils \
    nmap \
    netcat-openbsd \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /attack

COPY ransomware_simulator.py .

CMD ["python", "ransomware_simulator.py"]
