"""
Unit tests for SentinelCloud Internal Traffic Benchmark Dataset
"""

import os
import json
import pytest
from backend.pipeline.live_traffic_generator import LiveTrafficGenerator, DATASET_RECORDS, DATASET_METADATA


def test_internal_dataset_file_exists():
    path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "datasets", "internal_traffic_dataset.json")
    )
    assert os.path.exists(path), f"Dataset file not found at {path}"
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "metadata" in data
    assert "records" in data
    assert len(data["records"]) >= 50


def test_dataset_sources_and_citations():
    meta = LiveTrafficGenerator.get_dataset_metadata()
    assert "ADFA-LD" in meta["dataset_name"]
    assert "MIMIC-III" in meta["dataset_name"]

    source_names = [s["name"] for s in meta.get("sources", [])]
    assert any("ADFA-LD" in name for name in source_names)
    assert any("MIMIC-III" in name for name in source_names)

    # Check institutions
    institutions = [s["institution"] for s in meta.get("sources", [])]
    assert any("UNSW Canberra" in inst for inst in institutions)
    assert any("MIT" in inst for inst in institutions)


def test_microservices_coverage():
    pods = {r.get("pod_name") for r in DATASET_RECORDS}
    required = {"ehr", "vitals", "drug-dispenser", "billing"}
    assert required.issubset(pods), f"Missing coverage for pods: {required - pods}"


def test_records_schema_integrity():
    for r in DATASET_RECORDS:
        assert r.get("record_id"), "Missing record_id"
        assert r.get("pod_name") in ("ehr", "vitals", "drug-dispenser", "billing")
        assert r.get("syscall_name"), "Missing syscall_name"
        assert r.get("binary"), "Missing binary"
        assert r.get("dataset_source"), "Missing dataset_source"
        assert r.get("benchmark_ref"), "Missing benchmark_ref"
        assert isinstance(r.get("params"), dict), "params must be a dict"
