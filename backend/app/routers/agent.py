from pathlib import Path
import shutil

from fastapi import APIRouter, File, Header, HTTPException, UploadFile

from app.services.pcap_ai_prediction import predict_pcap_threats
from app.services.live_monitor import update_from_agent


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

    # ========================================================
    # USER VALIDATION
    # ========================================================

    if not x_user_id:

        raise HTTPException(
            status_code=401,
            detail="User ID is required."
        )

    # ========================================================
    # FILE VALIDATION
    # ========================================================

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="No PCAP file provided."
        )

    filename = Path(
        file.filename
    ).name

    if not filename.lower().endswith(
        (".pcap", ".pcapng")
    ):

        raise HTTPException(
            status_code=400,
            detail="Only PCAP or PCAPNG files are allowed."
        )

    # ========================================================
    # USER UPLOAD DIRECTORY
    # ========================================================

    user_dir = (
        AGENT_UPLOAD_DIR
        / x_user_id
    )

    user_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    file_path = (
        user_dir
        / filename
    )

    # ========================================================
    # PROCESS PCAP
    # ========================================================

    try:

        with open(
            file_path,
            "wb"
        ) as buffer:

            shutil.copyfileobj(
                file.file,
                buffer
            )

        print(
            "=========================================="
        )

        print(
            "NETSHIELD AGENT PCAP RECEIVED"
        )

        print(
            f"User ID : {x_user_id}"
        )

        print(
            f"File    : {filename}"
        )

        print(
            "=========================================="
        )

        # ----------------------------------------------------
        # AI THREAT PREDICTION
        # ----------------------------------------------------

        result = predict_pcap_threats(
            str(file_path)
        )

        # ----------------------------------------------------
        # ADD USER ID
        # ----------------------------------------------------

        result["user_id"] = x_user_id

        # ----------------------------------------------------
        # UPDATE LIVE NETWORK MONITOR
        # ----------------------------------------------------

        live_update = update_from_agent(
            result
        )

        result["live_monitor_updated"] = (
            live_update.get(
                "success",
                False
            )
        )

        print(
            "Live monitor updated:",
            result["live_monitor_updated"]
        )

        # ----------------------------------------------------
        # RETURN RESULT
        # ----------------------------------------------------

        return result

    except Exception as e:

        print(
            "Agent PCAP analysis error:",
            str(e)
        )

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

    finally:

        # ====================================================
        # DELETE TEMPORARY PCAP
        # ====================================================

        try:

            if file_path.exists():

                file_path.unlink()

                print(
                    "Temporary Agent PCAP deleted."
                )

        except Exception as cleanup_error:

            print(
                "Agent PCAP cleanup error:",
                str(cleanup_error)
            )