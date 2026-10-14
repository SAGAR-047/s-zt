"""
SentinelCloud Internal Event Bus
=================================
In-process event bus for pipeline component communication.
In LIVE mode, events are also forwarded to Kafka topics.
"""

import logging
from enum import Enum
from typing import Callable, Optional

from backend.config import settings

logger = logging.getLogger("sentinel.core.event_bus")


class EventType(str, Enum):
    TELEMETRY = "telemetry"
    DETECTION = "detection"
    DIAGNOSIS = "diagnosis"
    INCIDENT = "incident"
    ACTION = "action"
    AUDIT = "audit"
    SERVICE_UPDATE = "service_update"
    METRICS = "metrics"


class EventBus:
    """
    In-process pub/sub event bus.
    Components subscribe to event types and receive callbacks.
    Optionally forwards events to Kafka.
    """

    def __init__(self):
        self._subscribers: dict[EventType, list[Callable]] = {
            et: [] for et in EventType
        }

    def subscribe(self, event_type: EventType, callback: Callable):
        """Register a callback for an event type."""
        self._subscribers[event_type].append(callback)
        logger.debug("Subscriber added for %s (total: %d)",
                      event_type.value, len(self._subscribers[event_type]))

    def unsubscribe(self, event_type: EventType, callback: Callable):
        """Remove a callback."""
        try:
            self._subscribers[event_type].remove(callback)
        except ValueError:
            pass

    def publish(self, event_type: EventType, data):
        """Publish an event to all subscribers of this type."""
        for callback in self._subscribers[event_type]:
            try:
                callback(data)
            except Exception as e:
                logger.error("Event bus subscriber error (%s): %s", event_type.value, e)

        # Forward to Kafka if enabled
        if settings.kafka_enabled:
            self._forward_to_kafka(event_type, data)

    def _forward_to_kafka(self, event_type: EventType, data):
        """Forward events to Kafka topics."""
        try:
            from backend.integrations.kafka_client import kafka_producer

            topic_map = {
                EventType.TELEMETRY: settings.kafka_topic_raw,
                EventType.DETECTION: settings.kafka_topic_detections,
                EventType.DIAGNOSIS: settings.kafka_topic_diagnoses,
                EventType.ACTION: settings.kafka_topic_actions,
                EventType.AUDIT: settings.kafka_topic_audit,
            }

            topic = topic_map.get(event_type)
            if topic and hasattr(data, "model_dump"):
                kafka_producer.send(topic, data.model_dump(mode="json"))
        except Exception as e:
            logger.debug("Kafka forwarding failed for %s: %s", event_type.value, e)


# Singleton
event_bus = EventBus()
