from fastapi import APIRouter, HTTPException, UploadFile, File
from app.database.mongodb import pcap_analysis_collection
from app.services.pcap_analysis import analyze_pcap
from app.services.pcap_ai_prediction import predict_pcap_threats

import os
import shutil
import tempfile


router = APIRouter(
    prefix="/pcap",
    tags=["PCAP Analysis"]
)


# ============================================================
# ANALYZE PCAP FILE
# ============================================================

@router.post("/analyze")
async def analyze_uploaded_pcap(file: UploadFile = File(...)):

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No PCAP file provided"
        )

    if not file.filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(
            status_code=400,
            detail="Only .pcap and .pcapng files are supported"
        )

    temp_path = None

    try:
        suffix = os.path.splitext(file.filename)[1]

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=suffix
        ) as temp_file:

            temp_path = temp_file.name

            shutil.copyfileobj(
                file.file,
                temp_file
            )

        # Traditional PCAP analysis
        analysis = analyze_pcap(temp_path)

        # AI threat prediction
        ai_prediction = predict_pcap_threats(temp_path)

        result = {
            "filename": file.filename,
            "analysis": analysis,
            "ai_prediction": ai_prediction
        }

        # Save combined result
        pcap_analysis_collection.insert_one(result)

        # Convert MongoDB ID if needed
        result["_id"] = str(result["_id"])

        return {
            "success": True,
            "message": "PCAP analyzed successfully.",
            "filename": file.filename,
            "analysis": analysis,
            "ai_prediction": ai_prediction
        }

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"PCAP analysis failed: {str(e)}"
        )

    finally:

        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


# ============================================================
# GET ALL PCAP ANALYSES
# ============================================================

@router.get("/analyses")
def get_pcap_analyses():

    analyses = list(
        pcap_analysis_collection.find({})
        .sort("created_at", -1)
        .limit(50)
    )

    for analysis in analyses:
        analysis["_id"] = str(analysis["_id"])

    return {
        "total": len(analyses),
        "analyses": analyses
    }


# ============================================================
# GET LATEST PCAP ANALYSIS
# ============================================================

@router.get("/latest")
def get_latest_pcap():

    analysis = pcap_analysis_collection.find_one(
        {},
        sort=[("created_at", -1)]
    )

    if not analysis:
        raise HTTPException(
            status_code=404,
            detail="No PCAP analysis found"
        )

    analysis["_id"] = str(analysis["_id"])

    return analysis