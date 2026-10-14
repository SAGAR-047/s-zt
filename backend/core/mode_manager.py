"""
SentinelCloud Mode Manager
===========================
Central mode tracking and capability reporting.
Determines what infrastructure is available based on the operating mode.
"""

import logging
from backend.config import settings, OperatingMode

logger = logging.getLogger("sentinel.core.mode_manager")


class ModeManager:
    """
    Tracks the operating mode and reports available capabilities.
    Components check mode_manager before attempting real infrastructure calls.
    """

    def __init__(self):
        self._mode = settings.mode
        logger.info("ModeManager initialized: mode=%s", self._mode.value)

    @property
    def mode(self) -> OperatingMode:
        return self._mode

    @property
    def mode_label(self) -> str:
        labels = {
            OperatingMode.LIVE: "🛡 LIVE — Full Kubernetes Cluster",
            OperatingMode.LAB: "🔬 LAB — Docker Compose Environment",
            OperatingMode.DEV: "⚙ DEV — Local Development",
        }
        return labels.get(self._mode, "UNKNOWN")

    @property
    def is_live(self) -> bool:
        return self._mode == OperatingMode.LIVE

    @property
    def is_lab(self) -> bool:
        return self._mode == OperatingMode.LAB

    @property
    def is_dev(self) -> bool:
        return self._mode == OperatingMode.DEV

    @property
    def has_kafka(self) -> bool:
        """Whether Kafka is expected to be available."""
        return settings.kafka_enabled and self._mode in (OperatingMode.LIVE, OperatingMode.LAB)

    @property
    def has_clickhouse(self) -> bool:
        """Whether ClickHouse is expected to be available."""
        return settings.clickhouse_enabled and self._mode in (OperatingMode.LIVE, OperatingMode.LAB)

    @property
    def has_kubernetes(self) -> bool:
        """Whether Kubernetes API is available."""
        return settings.kubernetes_enabled and self._mode == OperatingMode.LIVE

    @property
    def has_cilium(self) -> bool:
        """Whether Cilium CNI is available."""
        return self.has_kubernetes

    @property
    def has_tetragon(self) -> bool:
        """Whether Tetragon is expected to be available."""
        return settings.tetragon_enabled and self._mode == OperatingMode.LIVE

    @property
    def has_external_detector(self) -> bool:
        """Whether the external anomaly detector is reachable."""
        return settings.detector_enabled

    @property
    def has_external_diagnoser(self) -> bool:
        """Whether the external diagnosis service is reachable."""
        return settings.diagnosis_enabled

    @property
    def allows_real_remediation(self) -> bool:
        """Whether remediation actions should touch real infrastructure."""
        return self._mode == OperatingMode.LIVE and self.has_kubernetes

    def get_capabilities(self) -> dict:
        """Return all capabilities as a dict for the frontend."""
        return {
            "mode": self._mode.value,
            "mode_label": self.mode_label,
            "kafka": self.has_kafka,
            "clickhouse": self.has_clickhouse,
            "kubernetes": self.has_kubernetes,
            "cilium": self.has_cilium,
            "tetragon": self.has_tetragon,
            "external_detector": self.has_external_detector,
            "external_diagnoser": self.has_external_diagnoser,
            "real_remediation": self.allows_real_remediation,
        }


# Singleton
mode_manager = ModeManager()
