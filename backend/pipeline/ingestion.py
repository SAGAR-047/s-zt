"""
SentinelCloud Telemetry Ingestion
==================================
Receives events from multiple sources:
- Kafka consumer (LIVE/LAB mode)
- HTTP REST API (all modes)
- Direct function call (DEV mode)

Routes events into the central pipeline.
"""

import logging
from typing import Callable, Optional

from backend.config import settings
from backend.core.event_schema import TelemetryEvent, TelemetrySource, DataMode

logger = logging.getLogger("sentinel.pipeline.ingestion")


class IngestionService:
    """
    Multi-source event ingestion.
    Normalizes incoming events and feeds them to the pipeline.
    """

    def __init__(self):
        self._pipeline_callback: Optional[Callable] = None
        self._kafka_consumer_started = False
        self.events_ingested = 0

    def set_pipeline_callback(self, callback: Callable):
        """Set the callback to invoke for each ingested event."""
        self._pipeline_callback = callback

    def start_kafka_consumer(self):
        """Start the Kafka consumer if enabled."""
        if not settings.kafka_enabled or self._kafka_consumer_started:
            return

        try:
            from backend.integrations.kafka_client import kafka_consumer

            def _handle_kafka_message(msg: dict):
                try:
                    event = self._normalize_kafka_event(msg)
                    if event and self._pipeline_callback:
                        self._pipeline_callback(event)
                        self.events_ingested += 1
                except Exception as e:
                    logger.error("Error processing Kafka message: %s", e)

            kafka_consumer.start(
                topic=settings.kafka_topic_raw,
                callback=_handle_kafka_message,
                group_id=settings.kafka_group_id,
            )
            self._kafka_consumer_started = True
            logger.info("Kafka ingestion started on topic=%s", settings.kafka_topic_raw)
        except Exception as e:
            logger.warning("Failed to start Kafka ingestion: %s", e)

    def ingest_http(self, event: TelemetryEvent) -> TelemetryEvent:
        """Ingest an event from the HTTP API."""
        event.source = event.source or TelemetrySource.HTTP_INGESTION
        event.data_mode = DataMode.LIVE if settings.is_live else DataMode.LAB_TEST
        self.events_ingested += 1
        return event

    def _normalize_kafka_event(self, raw: dict) -> Optional[TelemetryEvent]:
        """Convert a raw Kafka message into a TelemetryEvent."""
        try:
            return TelemetryEvent(
                source=TelemetrySource.TETRAGON,
                data_mode=DataMode.LIVE if settings.is_live else DataMode.LAB_TEST,
                pod_name=raw.get("pod_name", raw.get("pod", "")),
                namespace=raw.get("namespace", "medical"),
                syscall_name=raw.get("syscall_name", raw.get("event_type", "")),
                binary=raw.get("binary", raw.get("process", {}).get("binary", "")),
                target=raw.get("target", ""),
                port=int(raw.get("port", 0)),
                protocol=raw.get("protocol", ""),
                payload_size=int(raw.get("payload_size", raw.get("size", 0))),
                params=raw.get("params", {}),
            )
        except Exception as e:
            logger.error("Failed to normalize Kafka event: %s", e)
            return None

    def stop(self):
        """Stop all ingestion sources."""
        if self._kafka_consumer_started:
            try:
                from backend.integrations.kafka_client import kafka_consumer
                kafka_consumer.stop()
            except Exception:
                pass
            self._kafka_consumer_started = False


# Singleton
ingestion_service = IngestionService()
