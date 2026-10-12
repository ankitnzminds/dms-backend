"""Prometheus metrics (low-cardinality labels only: route templates, never raw paths/ids)."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

HTTP_REQUESTS = Counter("dms_http_requests_total", "HTTP requests", ["method", "route", "status"])
HTTP_LATENCY = Histogram(
    "dms_http_request_duration_seconds", "HTTP request latency", ["method", "route"]
)
AUTH_FAILURES = Counter(
    "dms_auth_failures_total", "Authentication/authorization failures", ["kind"]
)
AUTHZ_DENIALS = Counter("dms_authz_denials_total", "Authorization denials", ["action"])
UPLOADS = Counter("dms_uploads_total", "Upload session outcomes", ["outcome"])
SCANS = Counter("dms_scans_total", "Malware scan outcomes", ["outcome"])
DOWNLOAD_URLS = Counter("dms_download_urls_issued_total", "Download URLs issued")
OUTBOX_PROCESSED = Counter(
    "dms_outbox_events_total", "Outbox events handled", ["event_type", "result"]
)
OUTBOX_BACKLOG = Gauge("dms_outbox_backlog", "Outbox events pending")
OUTBOX_DEAD = Gauge(
    "dms_outbox_dead", "Outbox events that exhausted their retries (need attention)"
)
OUTBOX_OLDEST_AGE = Gauge("dms_outbox_oldest_pending_age_seconds", "Age of oldest pending event")
