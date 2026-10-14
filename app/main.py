from .security import get_current_user, require_role
from .auth import create_access_token, verify_password
from .models import User
from .schemas import LoginRequest, TokenResponse
from datetime import datetime, timezone
from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from .database import Base, engine, get_db
from .detection import evaluate_event
from .models import SecurityAlert, SecurityEvent
from .schemas import AlertRead, EventCreate, EventRead, SummaryRead

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SENTINEL Security Monitor API",
    description="Local-first security event ingestion, rule-based alerting, and incident tracking.",
    version="0.1.0",
)

@app.get("/health", tags=["system"])
def health():
    return {"status": "ok", "service": "sentinel-api", "version": "0.1.0"}

@app.get("/api/v1/summary", response_model=SummaryRead, tags=["dashboard"])
def get_summary(db: Session = Depends(get_db)):
    total_events = db.scalar(select(func.count(SecurityEvent.id))) or 0
    total_alerts = db.scalar(select(func.count(SecurityAlert.id))) or 0
    open_alerts = db.scalar(select(func.count(SecurityAlert.id)).where(SecurityAlert.status == "open")) or 0
    critical_alerts = db.scalar(select(func.count(SecurityAlert.id)).where(
        SecurityAlert.severity == "critical", SecurityAlert.status == "open"
    )) or 0
    return SummaryRead(
        total_events=total_events,
        total_alerts=total_alerts,
        open_alerts=open_alerts,
        critical_alerts=critical_alerts,
    )

@app.post("/api/v1/events", response_model=EventRead, status_code=201, tags=["events"])
def ingest_event(payload: EventCreate, db: Session = Depends(get_db)):
    event = SecurityEvent(
        source=payload.source,
        event_type=payload.event_type,
        severity=payload.severity,
        source_ip=str(payload.source_ip) if payload.source_ip else None,
        message=payload.message,
        event_metadata=payload.metadata,
    )
    db.add(event)
    db.flush()
    evaluate_event(db, event)
    db.commit()
    db.refresh(event)
    return event

@app.get("/api/v1/events", response_model=list[EventRead], tags=["events"])
def list_events(limit: int = Query(default=50, ge=1, le=200), db: Session = Depends(get_db)):
    return db.scalars(
        select(SecurityEvent).order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc()).limit(limit)
    ).all()

@app.get("/api/v1/alerts", response_model=list[AlertRead], tags=["alerts"])
def list_alerts(limit: int = Query(default=50, ge=1, le=200), status: str | None = None, db: Session = Depends(get_db)):
    stmt = select(SecurityAlert).order_by(SecurityAlert.created_at.desc(), SecurityAlert.id.desc()).limit(limit)
    if status is not None:
        if status not in {"open", "acknowledged", "resolved"}:
            raise HTTPException(status_code=400, detail="status must be open, acknowledged, or resolved")
        stmt = select(SecurityAlert).where(SecurityAlert.status == status).order_by(
            SecurityAlert.created_at.desc(), SecurityAlert.id.desc()
        ).limit(limit)
    return db.scalars(stmt).all()

@app.patch("/api/v1/alerts/{alert_id}/acknowledge", response_model=AlertRead, tags=["alerts"])
def acknowledge_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(SecurityAlert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.status == "open":
        alert.status = "acknowledged"
        alert.acknowledged_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(alert)
    return alert
@app.post(
    "/api/v1/auth/login",
    response_model=TokenResponse,
    tags=["authentication"],
)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(
        User.username == payload.username
    ).first()

    if (
        user is None
        or not user.is_active
        or not verify_password(payload.password, user.password_hash)
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    token = create_access_token(
        subject=user.username,
        role=user.role,
    )

    return TokenResponse(access_token=token)