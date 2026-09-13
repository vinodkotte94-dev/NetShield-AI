from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers.alerts import router as alerts_router
from app.routers.upload import router as upload_router
from app.routers.auth import router as auth_router
from app.routers.prediction import router as prediction_router
from app.routers.prediction_history import router as history_router
from app.routers.dashboard import router as dashboard_router
from app.routers import pcap
from app.routers import reports
from app.routers import report_export
from app.routers import live
from app.routers import agent


app = FastAPI(
    title="NetShield AI",
    version="1.0.0"
)


# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://netshield-ai-1-f.onrender.com",
        "https://net-shield-ai-azure.vercel.app",
    ],
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# API routers
app.include_router(auth_router)
app.include_router(prediction_router)
app.include_router(upload_router)
app.include_router(history_router)
app.include_router(dashboard_router)
app.include_router(alerts_router)

app.include_router(pcap.router)
app.include_router(reports.router)
app.include_router(report_export.router)
app.include_router(live.router)
app.include_router(agent.router)

@app.get("/")
def root():
    return {
        "message": "NetShield AI API is running",
        "status": "online"
    }


