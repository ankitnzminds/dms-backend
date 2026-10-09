"""When should the scheduler look at an automation next? (UTC in, UTC out.)"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from app.modules.automations.registry import CONDITIONS

SCAN_EVERY = timedelta(hours=24)


def _local(raw: str, tz: ZoneInfo) -> datetime:
    dt = datetime.fromisoformat(raw)
    return dt.replace(tzinfo=tz) if dt.tzinfo is None else dt


def next_fire(trigger: dict[str, Any], now: datetime, *, first: bool = False) -> datetime | None:
    """Next time the scheduler should evaluate this trigger; None for event-driven triggers."""
    spec = CONDITIONS.get(trigger.get("key", ""))
    if spec is None or spec.kind == "event":
        return None
    p = trigger.get("params") or {}
    if spec.kind == "scan":
        return now if first else now + SCAN_EVERY
    tz = ZoneInfo(p.get("timezone", "UTC"))
    end = _local(p["end_at"], tz).astimezone(UTC) if p.get("end_at") else None

    def capped(t: datetime) -> datetime | None:
        return None if end and t > end else t

    if spec.key == "specified_date":
        at = _local(p["run_at"], tz).astimezone(UTC)
        return at if at > now else None
    if spec.key == "periodic_interval":
        step = timedelta(minutes=int(p["every_minutes"]))
        start = _local(p["start_at"], tz).astimezone(UTC) if p.get("start_at") else None
        if first:
            return capped(max(start, now) if start else now + step)
        return capped(now + step)
    # periodic_schedule
    hh, mm = (int(x) for x in p.get("time", "09:00").split(":"))
    local_now = now.astimezone(tz)
    freq = p["frequency"]
    if freq == "hourly":
        cand = local_now.replace(minute=mm, second=0, microsecond=0)
        if cand <= local_now:
            cand += timedelta(hours=1)
    else:
        cand = local_now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        if freq == "daily":
            if cand <= local_now:
                cand += timedelta(days=1)
        elif freq == "weekly":
            cand += timedelta(days=(int(p.get("weekday", 0)) - cand.weekday()) % 7)
            if cand <= local_now:
                cand += timedelta(days=7)
        else:  # monthly
            day = int(p.get("day_of_month", 1))
            cand = cand.replace(day=day)
            if cand <= local_now:
                year, month = (
                    (cand.year + 1, 1) if cand.month == 12 else (cand.year, cand.month + 1)
                )
                cand = cand.replace(year=year, month=month)
    return capped(cand.astimezone(UTC))


def fire_key(trigger: dict[str, Any], at: datetime) -> str:
    """Idempotency key for a timer/scan firing: one run per (period, fire time)."""
    spec = CONDITIONS[trigger["key"]]
    if spec.kind == "scan":
        return f"scan:{at.astimezone(UTC):%Y-%m-%d}"
    return f"timer:{at.astimezone(UTC):%Y-%m-%dT%H:%M}"
