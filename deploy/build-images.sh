#!/bin/bash
# ============================================================================
# SentinelCloud-Advanced: Build and Push Docker Images
# ============================================================================
# Usage:
#   ./build-images.sh [registry]
#   ./build-images.sh docker.io/yourlab
# ============================================================================

set -euo pipefail

REGISTRY="${1:-sentinelcloud}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Building SentinelCloud images with registry: ${REGISTRY}"

# Medical services
for svc in vitals drug-dispenser ehr billing; do
    echo "Building ${REGISTRY}/${svc}:latest ..."
    docker build -t "${REGISTRY}/${svc}:latest" "${PROJECT_ROOT}/services/medical/${svc}/"
done

# Intelligence services
echo "Building ${REGISTRY}/streaming-anomaly-detector:latest ..."
docker build -t "${REGISTRY}/streaming-anomaly-detector:latest" "${PROJECT_ROOT}/services/intelligence/streaming-anomaly-detector/"

echo "Building ${REGISTRY}/diagnosis-service:latest ..."
docker build -t "${REGISTRY}/diagnosis-service:latest" "${PROJECT_ROOT}/services/intelligence/diagnosis-service/"

echo "Building ${REGISTRY}/tetragon-kafka-forwarder:latest ..."
docker build -t "${REGISTRY}/tetragon-kafka-forwarder:latest" "${PROJECT_ROOT}/services/intelligence/tetragon-kafka-forwarder/"

# Orchestrator
echo "Building ${REGISTRY}/mape-k-controller:latest ..."
docker build -t "${REGISTRY}/mape-k-controller:latest" "${PROJECT_ROOT}/services/orchestrator/mape-k-controller/"

# Attack simulator
echo "Building ${REGISTRY}/attack-simulator:latest ..."
docker build -t "${REGISTRY}/attack-simulator:latest" "${PROJECT_ROOT}/simulation/attack-scripts/"

echo ""
echo "All images built successfully!"
echo ""
echo "To push to registry:"
for img in vitals drug-dispenser ehr billing streaming-anomaly-detector diagnosis-service tetragon-kafka-forwarder mape-k-controller attack-simulator; do
    echo "  docker push ${REGISTRY}/${img}:latest"
done
