"""
ElasticsearchWriter — indexes LKSM events into Elasticsearch for Kibana visualization.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

from python_tools.core.module_base import LKSMEvent

log = logging.getLogger(__name__)

INDEX_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
    },
    "mappings": {
        "properties": {
            "seq": {"type": "integer"},
            "ts": {"type": "double"},
            "@timestamp": {"type": "date"},
            "type": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "source": {"type": "keyword"},
            "data": {
                "properties": {
                    "message": {
                        "type": "text",
                        "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
                    },
                    "symbol": {"type": "keyword"},
                    "pid": {"type": "integer"},
                    "process_name": {"type": "keyword"},
                }
            },
        }
    },
}


class ElasticsearchWriter:
    """Mirrors the EventLogger interface but writes to Elasticsearch."""

    def __init__(self, config: dict) -> None:
        es_cfg = config.get("elasticsearch", {})
        self.enabled = es_cfg.get("enabled", True)
        self.index = es_cfg.get("index", "lksm_events")
        host = es_cfg.get("host", "http://localhost:9200")

        if not self.enabled:
            log.info("Elasticsearch output disabled in config")
            return

        try:
            self.es = Elasticsearch(hosts=[host])
            self._ensure_index()
            log.info("Connected to Elasticsearch at %s", host)
        except Exception:
            log.exception("Failed to connect to Elasticsearch — events will not be indexed")
            self.enabled = False

    def _ensure_index(self) -> None:
        """Create the index with explicit mapping if it doesn't already exist."""
        if not self.es.indices.exists(index=self.index):
            self.es.indices.create(
                index=self.index,
                settings=INDEX_MAPPING["settings"],
                mappings=INDEX_MAPPING["mappings"],
            )
            log.info("Created index '%s'", self.index)

    def _to_doc(self, event: LKSMEvent) -> Dict[str, Any]:
        """Convert an LKSMEvent to an Elasticsearch document."""
        doc = event.to_dict()
        doc["@timestamp"] = datetime.now(timezone.utc).isoformat()
        return doc

    def log_event(self, event: LKSMEvent) -> None:
        """Index a single event."""
        if not self.enabled:
            return
        try:
            self.es.index(index=self.index, document=self._to_doc(event))
        except Exception:
            log.exception("Failed to index event seq=%s", getattr(event, "seq", "?"))

    def log_events(self, events: List[LKSMEvent]) -> None:
        """Bulk-index a list of events."""
        if not self.enabled or not events:
            return
        actions = [
            {"_index": self.index, "_source": self._to_doc(ev)}
            for ev in events
        ]
        try:
            bulk(self.es, actions)
        except Exception:
            log.exception("Bulk index failed for %d events", len(events))
