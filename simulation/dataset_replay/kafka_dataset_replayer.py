"""
SentinelCloud-Advanced: Kafka & HTTP Benchmark Dataset Stream Replayer
======================================================================
Streams benchmark cybersecurity datasets (BETH, ADFA-LD, CIC-IDS, Falco)
directly into the Strimzi Kafka cluster topic ('syscalls') or the local
runner ingestion endpoint.

Usage:
  python simulation/dataset_replay/kafka_dataset_replayer.py --target http://localhost:5050/api/event --rate 5
  python simulation/dataset_replay/kafka_dataset_replayer.py --kafka kafka.sentinel:9092 --topic syscalls
"""

import os
import sys
import json
import time
import argparse
import logging
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s [DATASET-REPLAYER] %(message)s")
logger = logging.getLogger("kafka-replayer")

# Default dataset sample path
DEFAULT_DATASET = os.path.join(os.path.dirname(__file__), "sample_beth_adfa_logs.json")

def load_dataset(filepath: str) -> list:
    if not os.path.exists(filepath):
        logger.warning("Dataset file %s not found. Using default internal samples.", filepath)
        return [
            {"dataset": "ADFA-LD", "pod_name": "ehr", "syscall": "sys_read", "target": "/var/data/patient-8842.dat", "port": 0, "binary": "/usr/bin/python", "label": 0},
            {"dataset": "BETH", "pod_name": "vitals", "syscall": "sys_connect", "target": "telemetry.internal:443", "port": 443, "binary": "/usr/bin/vitals-daemon", "label": 0},
            {"dataset": "ADFA-LD Attack", "pod_name": "ehr", "syscall": "sys_execve", "target": "/bin/sh", "port": 0, "binary": "/bin/sh", "label": 1},
            {"dataset": "BETH Attack", "pod_name": "ehr", "syscall": "sys_connect", "target": "10.0.0.45:445", "port": 445, "binary": "/usr/bin/python", "label": 1},
            {"dataset": "ADFA-LD Attack", "pod_name": "ehr", "syscall": "sys_rename", "target": "/data/records.locked", "port": 0, "binary": "/usr/bin/python", "label": 1},
        ]
    with open(filepath, "r") as f:
        return json.load(f)

def replay_to_kafka(records: list, kafka_bootstrap: str, topic: str, rate: float):
    try:
        from kafka import KafkaProducer
        producer = KafkaProducer(
            bootstrap_servers=kafka_bootstrap,
            value_serializer=lambda v: json.dumps(v).encode("utf-8")
        )
        logger.info("Connected to Kafka %s, streaming to topic '%s'...", kafka_bootstrap, topic)
        for rec in records:
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "pod_name": rec.get("pod_name", "ehr"),
                "namespace": "medical",
                "syscall_name": rec.get("syscall", "sys_read"),
                "params": {
                    "target": rec.get("target", ""),
                    "port": rec.get("port", 0),
                    "binary": rec.get("binary", "")
                },
                "dataset_source": rec.get("dataset", "ADFA-LD/BETH"),
                "is_malicious": rec.get("label", 0) == 1
            }
            producer.send(topic, value=event)
            logger.info("Sent [%s] %s -> %s", rec.get("dataset"), event["syscall_name"], event["params"]["target"])
            time.sleep(1.0 / max(rate, 0.1))
        producer.flush()
        logger.info("Kafka dataset replay completed successfully.")
    except Exception as e:
        logger.error("Kafka stream error: %s", e)

def replay_to_http(records: list, target_url: str, rate: float):
    import urllib.request
    logger.info("Streaming dataset events to HTTP target: %s (rate: %s events/sec)", target_url, rate)
    for rec in records:
        event = {
            "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "pod_name": rec.get("pod_name", "ehr"),
            "syscall": rec.get("syscall", "sys_read"),
            "target": rec.get("target", ""),
            "port": rec.get("port", 0),
            "binary": rec.get("binary", ""),
            "dataset_source": rec.get("dataset", "ADFA-LD/BETH"),
            "is_malicious": rec.get("label", 0) == 1
        }
        try:
            req = urllib.request.Request(
                target_url,
                data=json.dumps(event).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                pass
            logger.info("Ingested [%s] %s -> %s", event["dataset_source"], event["syscall"], event["target"])
        except Exception as e:
            logger.warning("HTTP POST error: %s", e)
        time.sleep(1.0 / max(rate, 0.1))
    logger.info("HTTP dataset replay completed successfully.")

def main():
    parser = argparse.ArgumentParser(description="SentinelCloud Dataset Stream Replayer")
    parser.add_argument("--dataset", default=DEFAULT_DATASET, help="Path to dataset JSON file")
    parser.add_argument("--target", default="http://localhost:5050/api/event", help="HTTP ingestion URL")
    parser.add_argument("--kafka", default=None, help="Kafka bootstrap server (e.g. kafka.sentinel:9092)")
    parser.add_argument("--topic", default="syscalls", help="Kafka topic name")
    parser.add_argument("--rate", type=float, default=2.0, help="Events per second")
    args = parser.parse_args()

    records = load_dataset(args.dataset)
    logger.info("Loaded %d dataset records for streaming replay.", len(records))

    if args.kafka:
        replay_to_kafka(records, args.kafka, args.topic, args.rate)
    else:
        replay_to_http(records, args.target, args.rate)

if __name__ == "__main__":
    main()
