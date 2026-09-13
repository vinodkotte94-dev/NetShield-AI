from fastapi import APIRouter

from app.services.live_monitor import (
    start_monitor,
    stop_monitor,
    get_status
)

router = APIRouter(
    prefix="/api/live",
    tags=["Live Network Monitoring"]
)


@router.post("/start")
def start_live_monitor():
    return start_monitor()


@router.post("/stop")
def stop_live_monitor():
    return stop_monitor()


@router.get("/status")
def live_monitor_status():
    return get_status()