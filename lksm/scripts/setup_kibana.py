#!/usr/bin/env python3
"""
One-time Kibana setup: waits for Kibana to be healthy, then creates the
"LKSM Events" data view pointing at the lksm_events index.

Usage:
    python scripts/setup_kibana.py
"""

import sys
import time

import requests

KIBANA_URL = "http://localhost:5601"
DATA_VIEW_BODY = {
    "data_view": {
        "title": "lksm_events",
        "name": "LKSM Events",
        "timeFieldName": "@timestamp",
    }
}


def wait_for_kibana(timeout: int = 120) -> None:
    """Poll Kibana /api/status until it reports 'available'."""
    print(f"Waiting for Kibana at {KIBANA_URL} ...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = requests.get(f"{KIBANA_URL}/api/status", timeout=5)
            if resp.ok and resp.json().get("status", {}).get("overall", {}).get("level") == "available":
                print("Kibana is ready.")
                return
        except requests.ConnectionError:
            pass
        time.sleep(3)
    print("ERROR: Kibana did not become healthy within timeout.", file=sys.stderr)
    sys.exit(1)


def create_data_view() -> None:
    """Create the LKSM Events data view (idempotent — 409 means it exists)."""
    resp = requests.post(
        f"{KIBANA_URL}/api/data_views/data_view",
        json=DATA_VIEW_BODY,
        headers={"kbn-xsrf": "true", "Content-Type": "application/json"},
    )
    if resp.status_code == 200:
        dv_id = resp.json().get("data_view", {}).get("id", "unknown")
        print(f"Data view 'LKSM Events' created (id={dv_id}).")
    elif resp.status_code == 409:
        print("Data view 'LKSM Events' already exists — nothing to do.")
    else:
        print(f"ERROR creating data view: {resp.status_code} {resp.text}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    wait_for_kibana()
    create_data_view()
