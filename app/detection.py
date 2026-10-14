from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from .models import SecurityEvent, SecurityAlert

FAILED_LOGIN_RULE = "AUTH-001"
SUSPICIOUS_PATH_RULE = "WEB-001"
FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW_MINUTES = 10

SUSPICIOUS_PATH_MARKERS = (
    "/../", "..\\", "/etc/passwd", "wp-admin", ".env",
    "config.php", "/.git", "union select", "<script"
)

def evaluate_event(db: Session, event: SecurityEvent) -> list[SecurityAlert]:
    """Run deterministic, explainable rules against one newly ingested event."""
    created: list[SecurityAlert] = []
    message_and_meta = (event.message + " " + str(event.event_metadata)).lower()

    if event.event_type.lower() in {"login_failed", "authentication_failed"} and event.source_ip:
        since = datetime.now(timezone.utc) - timedelta(minutes=FAILED_LOGIN_WINDOW_MINUTES)
        recent = db.scalars(
            select(SecurityEvent).where(
                SecurityEvent.event_type.in_(["login_failed", "authentication_failed"]),
                SecurityEvent.source_ip == event.source_ip,
                SecurityEvent.created_at >= since,
            )
        ).all()
        if len(recent) >= FAILED_LOGIN_THRESHOLD and not db.scalar(
            select(SecurityAlert.id).where(
                SecurityAlert.event_id == event.id,
                SecurityAlert.rule_id == FAILED_LOGIN_RULE,
            )
        ):
            created.append(SecurityAlert(
                event_id=event.id,
                title="Repeated failed logins",
                description=f"{len(recent)} failed login events from {event.source_ip} within {FAILED_LOGIN_WINDOW_MINUTES} minutes.",
                severity="high",
                status="open",
                rule_id=FAILED_LOGIN_RULE,
            ))

    if event.event_type.lower() in {"http_request", "web_request"} and any(
        marker in message_and_meta for marker in SUSPICIOUS_PATH_MARKERS
    ):
        created.append(SecurityAlert(
            event_id=event.id,
            title="Suspicious web request pattern",
            description="The event contains a path or payload marker that matches a configured suspicious-request rule. Validate the request in context.",
            severity="medium",
            status="open",
            rule_id=SUSPICIOUS_PATH_RULE,
        ))

    db.add_all(created)
    return created
