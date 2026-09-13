from pathlib import Path
import shutil

from fastapi import APIRouter, File, Header, HTTPException, UploadFile

from app.services.pcap_ai_prediction import predict_pcap_threats


router = APIRouter(
    prefix="/api/agent",
    tags=["NetShield Agent"]
)


BASE_DIR = Path(__file__).resolve().parents[1]

AGENT_UPLOAD_DIR = BASE_DIR / "uploads" / "agent"

AGENT_UPLOAD_DIR.mkdir(
    parents=True,
    exist_ok=True
)


@router.post("/analyze")
async def analyze_agent_pcap(
    file: UploadFile = File(...),
    x_user_id: str | None = Header(default=None)
):
    if not x_user_id:
        raise HTTPException(
            status_code=401,
            detail="User ID is required."
        )

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No PCAP file provided."
        )

    filename = Path(file.filename).name

    if not filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(
            status_code=400,
            detail="Only PCAP or PCAPNG files are allowed."
        )

    user_dir = AGENT_UPLOAD_DIR / x_user_id
    user_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    file_path = user_dir / filename

    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        result = predict_pcap_threats(str(file_path))

        result["user_id"] = x_user_id

        return result

    except Exception as e:
        print("Agent PCAP analysis error:", str(e))

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

    finally:
        try:
            if file_path.exists():
                file_path.unlink()
        except Exception as cleanup_error:
            print(
                "Agent PCAP cleanup error:",
                str(cleanup_error)
            )