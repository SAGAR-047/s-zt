#!/usr/bin/env bash
#
# Check health of all services in the SentinelCloud stack.
#

set -u

SERVICES=(
    "http://localhost:5050/api/health"
    "http://localhost:5000/health"
    "http://localhost:5001/health"
    "http://localhost:5002/health"
    "http://localhost:5003/health"
    "http://localhost:8080/health"
    "http://localhost:8081/health"
    "http://localhost:8083/health"
)

echo "=== SentinelCloud Health Check ==="
for url in "${SERVICES[@]}"; do
    if response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$url"); then
        if [ "$response" -eq 200 ]; then
            echo "✅ $url (HTTP 200)"
        else
            echo "⚠️  $url (HTTP $response)"
        fi
    else
        echo "❌ $url (unreachable)"
    fi
done

echo "=== Infrastructure Services ==="
# Check Kafka (simple port check)
if nc -z localhost 9092 2>/dev/null; then
    echo "✅ Kafka on port 9092"
else
    echo "❌ Kafka on port 9092"
fi

# Check ClickHouse
if nc -z localhost 9000 2>/dev/null; then
    echo "✅ ClickHouse on port 9000"
else
    echo "❌ ClickHouse on port 9000"
fi

echo "Health check complete."
