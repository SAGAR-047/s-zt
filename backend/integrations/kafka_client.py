"""
SentinelCloud Kafka Client
===========================
Kafka producer and consumer wrapper.
Enabled only when SENTINEL_KAFKA_ENABLED=true.
"""

import json
import logging
import threading
from typing import Optional, Callable

from backend.config import settings

logger = logging.getLogger("sentinel.integrations.kafka")


class KafkaProducerClient:
    """Lazy-initialized Kafka producer."""

    def __init__(self):
        self._producer = None
        self._lock = threading.Lock()

    def _get_producer(self):
        if self._producer is None and settings.kafka_enabled:
            with self._lock:
                if self._producer is None:
                    try:
                        from kafka import KafkaProducer
                        self._producer = KafkaProducer(
                            bootstrap_servers=settings.kafka_bootstrap,
                            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
                            acks="all",
                            retries=3,
                        )
                        logger.info("Kafka producer connected to %s", settings.kafka_bootstrap)
                    except Exception as e:
                        logger.warning("Failed to create Kafka producer: %s", e)
        return self._producer

    def send(self, topic: str, value: dict, key: Optional[str] = None) -> bool:
        """Send a message to a Kafka topic."""
        producer = self._get_producer()
        if producer is None:
            return False
        try:
            producer.send(
                topic,
                value=value,
                key=key.encode("utf-8") if key else None,
            )
            producer.flush()
            return True
        except Exception as e:
            logger.error("Kafka send failed (topic=%s): %s", topic, e)
            return False

    def send_event(self, event) -> bool:
        """Send a TelemetryEvent to the raw telemetry topic."""
        return self.send(
            settings.kafka_topic_raw,
            event.model_dump(mode="json"),
            key=event.event_id,
        )

    def send_detection(self, detection) -> bool:
        """Send a DetectionResult to the detections topic."""
        return self.send(
            settings.kafka_topic_detections,
            detection.model_dump(mode="json"),
            key=detection.event_id,
        )

    def send_audit(self, record) -> bool:
        """Send an AuditRecord to the audit topic."""
        return self.send(
            settings.kafka_topic_audit,
            record.model_dump(mode="json"),
            key=record.audit_id,
        )

    def close(self):
        if self._producer:
            self._producer.close()
            self._producer = None


class KafkaConsumerClient:
    """Kafka consumer that runs in a background thread."""

    def __init__(self):
        self._consumer = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self, topic: str, callback: Callable[[dict], None], group_id: Optional[str] = None):
        """Start consuming from a topic in a background thread."""
        if not settings.kafka_enabled:
            logger.info("Kafka consumer disabled (SENTINEL_KAFKA_ENABLED=false)")
            return

        def _run():
            try:
                from kafka import KafkaConsumer
                self._consumer = KafkaConsumer(
                    topic,
                    bootstrap_servers=settings.kafka_bootstrap,
                    group_id=group_id or settings.kafka_group_id,
                    auto_offset_reset="latest",
                    value_deserializer=lambda v: json.loads(v.decode("utf-8")),
                    consumer_timeout_ms=1000,
                )
                logger.info("Kafka consumer started on topic=%s group=%s",
                            topic, group_id or settings.kafka_group_id)
                self._running = True

                while self._running:
                    try:
                        records = self._consumer.poll(timeout_ms=1000)
                        for tp, messages in records.items():
                            for msg in messages:
                                try:
                                    callback(msg.value)
                                except Exception as e:
                                    logger.error("Error processing Kafka message: %s", e)
                    except Exception as e:
                        if self._running:
                            logger.error("Kafka consumer poll error: %s", e)

            except ImportError:
                logger.warning("kafka-python not installed; Kafka consumer disabled")
            except Exception as e:
                logger.error("Kafka consumer failed to start: %s", e)

        self._thread = threading.Thread(target=_run, daemon=True, name="kafka-consumer")
        self._thread.start()

    def stop(self):
        """Stop the consumer."""
        self._running = False
        if self._consumer:
            try:
                self._consumer.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=5)


# Singletons
kafka_producer = KafkaProducerClient()
kafka_consumer = KafkaConsumerClient()
