from fastapi import APIRouter, HTTPException, Query
from bson import ObjectId
from datetime import datetime, timezone

from app.database.mongodb import (
    alerts_collection,
    notifications_collection,
    incidents_collection
)


router = APIRouter(
    prefix="/api/alerts",
    tags=["Alerts & Notifications"]
)


# ============================================================
# CONSTANTS
# ============================================================

ALERT_STATUSES = [
    "New",
    "Acknowledged",
    "Investigating",
    "Resolved",
    "Closed"
]

SEVERITIES = [
    "Critical",
    "High",
    "Medium",
    "Low"
]

ROLES = [
    "Administrator",
    "Security Analyst",
    "SOC Operator"
]


# ============================================================
# SERIALIZER
# ============================================================

def serialize_document(document):
    """
    Convert MongoDB ObjectId and datetime values
    into JSON-safe values.
    """

    if not document:
        return document

    document = dict(document)

    if "_id" in document:
        document["_id"] = str(document["_id"])

    for key, value in document.items():

        if isinstance(value, ObjectId):
            document[key] = str(value)

        elif isinstance(value, datetime):
            document[key] = value.isoformat()

    return document

def calculate_risk_score(
    threat_type: str,
    threat_count: int,
    confidence: float,
    severity: str
):
    """
    Calculate an explainable 0-100 security risk score.

    Factors:
    - AI confidence: 50%
    - Threat count: 30%
    - Severity: 20%
    """

    confidence_score = max(
        0,
        min(float(confidence), 100)
    )

    # Threat count contribution.
    # 100+ malicious records reaches the maximum.
    threat_count_score = min(
        int(threat_count),
        100
    )

    severity_scores = {
        "Critical": 100,
        "High": 80,
        "Medium": 60,
        "Low": 30
    }

    severity_score = severity_scores.get(
        severity,
        0
    )

    risk_score = (
        confidence_score * 0.50
        + threat_count_score * 0.30
        + severity_score * 0.20
    )

    return round(
        max(0, min(risk_score, 100)),
        2
    )


# ============================================================
# SEVERITY CALCULATION
# ============================================================

def calculate_severity(
    threat_type: str,
    threat_count: int,
    confidence: float
):

    threat = threat_type.lower()

    critical_keywords = [
        "ddos",
        "dos",
        "bot",
        "malware",
        "ransomware",
        "infiltration"
    ]

    high_keywords = [
        "sql injection",
        "brute force",
        "xss",
        "exploit",
        "backdoor",
        "shellcode",
        "web attack"
    ]

    if any(
        keyword in threat
        for keyword in critical_keywords
    ):
        return "Critical"

    if any(
        keyword in threat
        for keyword in high_keywords
    ):
        return "High"

    if threat_count >= 100 and confidence >= 90:
        return "High"

    if threat_count >= 20:
        return "Medium"

    return "Low"


# ============================================================
# CREATE NOTIFICATIONS
# ============================================================

def create_notification_for_alert(
    alert_id,
    dataset: str,
    threat_type: str,
    threat_count: int,
    severity: str,
    confidence: float
):

    now = datetime.now(timezone.utc)

    notification_ids = []

    title = f"{severity} Security Alert"

    message = (
        f"{threat_type} attack detected. "
        f"{threat_count} malicious records identified "
        f"with {confidence:.2f}% confidence."
    )

    for role in ROLES:

        notification_document = {

            "alert_id": alert_id,

            "notification_type": "Security Alert",

            "title": title,

            "message": message,

            "threat_type": threat_type,

            "severity": severity,

            "threat_count": int(threat_count),

            "confidence": float(confidence),

            "dataset": dataset,

            "recipient_role": role,

            "read": False,

            "status": "Unread",

            "created_at": now,

            "updated_at": now,

            "source": "NetShield AI"
        }

        result = notifications_collection.insert_one(
            notification_document
        )

        notification_ids.append(
            str(result.inserted_id)
        )

    return notification_ids


# ============================================================
# CREATE ALERT
# ============================================================

@router.post("/create")
def create_alert(
    dataset: str,
    threat_type: str,
    threat_count: int,
    confidence: float,
    prediction_id: str | None = None
):

    # --------------------------------------------------------
    # Calculate severity
    # --------------------------------------------------------

    severity = calculate_severity(
        threat_type,
        threat_count,
        confidence
    )
    
    risk_score = calculate_risk_score(
    threat_type=threat_type,
    threat_count=threat_count,
    confidence=confidence,
    severity=severity
)

    now = datetime.now(timezone.utc)

    # --------------------------------------------------------
    # Create alert document
    # --------------------------------------------------------

    alert_document = {

        "dataset": dataset.upper(),

        "threat_type": threat_type,

        "threat_count": int(threat_count),

        "severity": severity,
        "risk_score": risk_score,

        "confidence": float(confidence),

        "status": "New",

        "message": (
            f"{threat_type} attack detected. "
            f"{threat_count} malicious records identified."
        ),

        "source": "NetShield AI",

        "created_at": now,

        "updated_at": now
    }

    # --------------------------------------------------------
    # Attach prediction ID if supplied
    # --------------------------------------------------------

    if prediction_id:

        try:

            alert_document["prediction_id"] = ObjectId(
                prediction_id
            )

        except Exception:

            raise HTTPException(
                status_code=400,
                detail="Invalid prediction ID."
            )

    # --------------------------------------------------------
    # Insert alert
    # --------------------------------------------------------

    result = alerts_collection.insert_one(
        alert_document
    )

    alert_id = result.inserted_id

    # --------------------------------------------------------
    # Create notifications
    # --------------------------------------------------------

    notification_ids = create_notification_for_alert(

        alert_id=alert_id,

        dataset=dataset.upper(),

        threat_type=threat_type,

        threat_count=threat_count,

        severity=severity,

        confidence=confidence
    )

    # --------------------------------------------------------
    # Automatically create incident
    # --------------------------------------------------------
    #
    # This was the missing connection:
    #
    # AI Detection
    #      ↓
    # Alert
    #      ↓
    # Notifications
    #      ↓
    # Incident
    #
    # --------------------------------------------------------

    incident_id = None

    if threat_type.lower() not in [
        "benign",
        "normal"
    ]:

        incident_result = create_incident_from_alert(
            str(alert_id)
        )

        incident_id = incident_result.get(
            "incident_id"
        )

    # --------------------------------------------------------
    # Response
    # --------------------------------------------------------

    return {

        "success": True,

        "message": (
            "Security alert created successfully."
        ),

        "alert_id": str(alert_id),

        "incident_id": incident_id,

        "severity": severity,

        "status": "New",

        "notifications_created": len(
            notification_ids
        ),

        "notification_ids": notification_ids
    }


# ============================================================
# GET ALL ALERTS
# ============================================================

@router.get("/")
def get_alerts(
    status: str | None = Query(
        default=None
    ),
    severity: str | None = Query(
        default=None
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=500
    )
):

    query = {}

    if status:

        query["status"] = status

    if severity:

        query["severity"] = severity

    alerts = list(
        alerts_collection
        .find(query)
        .sort(
            "created_at",
            -1
        )
        .limit(limit)
    )

    serialized_alerts = [
        serialize_document(alert)
        for alert in alerts
    ]

    return {

        "success": True,

        "total": len(
            serialized_alerts
        ),

        "alerts": serialized_alerts
    }


# ============================================================
# GET ACTIVE ALERTS
# ============================================================

@router.get("/active")
def get_active_alerts():

    alerts = list(
        alerts_collection
        .find(
            {
                "status": {
                    "$in": [
                        "New",
                        "Acknowledged",
                        "Investigating"
                    ]
                }
            }
        )
        .sort(
            "created_at",
            -1
        )
    )

    serialized_alerts = [
        serialize_document(alert)
        for alert in alerts
    ]

    return {

        "success": True,

        "total": len(
            serialized_alerts
        ),

        "alerts": serialized_alerts
    }


# ============================================================
# ALERT STATISTICS
# ============================================================

@router.get("/statistics")
def get_alert_statistics():

    total = alerts_collection.count_documents({})

    critical = alerts_collection.count_documents(
        {
            "severity": "Critical"
        }
    )

    high = alerts_collection.count_documents(
        {
            "severity": "High"
        }
    )

    medium = alerts_collection.count_documents(
        {
            "severity": "Medium"
        }
    )

    low = alerts_collection.count_documents(
        {
            "severity": "Low"
        }
    )

    new = alerts_collection.count_documents(
        {
            "status": "New"
        }
    )

    acknowledged = alerts_collection.count_documents(
        {
            "status": "Acknowledged"
        }
    )

    investigating = alerts_collection.count_documents(
        {
            "status": "Investigating"
        }
    )

    resolved = alerts_collection.count_documents(
        {
            "status": "Resolved"
        }
    )

    closed = alerts_collection.count_documents(
        {
            "status": "Closed"
        }
    )

    return {

        "success": True,

        "total": total,

        "critical": critical,

        "high": high,

        "medium": medium,

        "low": low,

        "new": new,

        "acknowledged": acknowledged,

        "investigating": investigating,

        "resolved": resolved,

        "closed": closed
    }


# ============================================================
# CREATE INCIDENT FROM ALERT
# ============================================================

@router.post("/{alert_id}/incident")
def create_incident_from_alert(
    alert_id: str
):

    # --------------------------------------------------------
    # Validate alert ID
    # --------------------------------------------------------

    try:

        object_id = ObjectId(
            alert_id
        )

    except Exception:

        raise HTTPException(
            status_code=400,
            detail="Invalid alert ID."
        )

    # --------------------------------------------------------
    # Find alert
    # --------------------------------------------------------

    alert = alerts_collection.find_one(
        {
            "_id": object_id
        }
    )

    if not alert:

        raise HTTPException(
            status_code=404,
            detail="Alert not found."
        )

    # --------------------------------------------------------
    # Check existing incident
    # --------------------------------------------------------

    existing_incident = incidents_collection.find_one(
        {
            "alert_id": object_id
        }
    )

    if existing_incident:

        return {

            "success": True,

            "message": "Incident already exists.",

            "incident_id": str(
                existing_incident["_id"]
            ),

            "alert_id": alert_id
        }

    # --------------------------------------------------------
    # Create incident
    # --------------------------------------------------------

    now = datetime.now(timezone.utc)

    incident_document = {

        "alert_id": object_id,

        "prediction_id": alert.get(
            "prediction_id"
        ),

        "title": (
            f"{alert.get('severity', 'Unknown')} - "
            f"{alert.get('threat_type', 'Security Threat')}"
        ),

        # Frontend field
        "attack_type": alert.get(
            "threat_type",
            "Unknown"
        ),

        # Original threat field
        "threat_type": alert.get(
            "threat_type",
            "Unknown"
        ),

        # Dataset from alert
        "dataset": alert.get(
            "dataset",
            "Unknown"
        ),

        # Threat count is used as detected packets
        "detected_packets": alert.get(
            "threat_count",
            0
        ),

        # Confidence from AI prediction
        "confidence": alert.get(
            "confidence",
            0
        ),

        # Severity
        "severity": alert.get(
            "severity",
            "Low"
        ),
        "risk_score": alert.get("risk_score", 0),

        # New incident
        "status": "Open",

        "description": alert.get(
            "message",
            "Security incident created from alert."
        ),

        "created_at": now,

        "updated_at": now,

        "source": "NetShield AI"
    }

    # --------------------------------------------------------
    # Insert incident
    # --------------------------------------------------------

    result = incidents_collection.insert_one(
        incident_document
    )

    # --------------------------------------------------------
    # Link incident to alert
    # --------------------------------------------------------

    alerts_collection.update_one(

        {
            "_id": object_id
        },

        {
            "$set": {

                "incident_id": result.inserted_id,

                "updated_at": now
            }
        }
    )

    # --------------------------------------------------------
    # Response
    # --------------------------------------------------------

    return {

        "success": True,

        "message": (
            "Incident created successfully."
        ),

        "incident_id": str(
            result.inserted_id
        ),

        "alert_id": alert_id
    }


# ============================================================
# GET SINGLE ALERT
# ============================================================

@router.get("/{alert_id}")
def get_alert(
    alert_id: str
):

    try:

        object_id = ObjectId(
            alert_id
        )

    except Exception:

        raise HTTPException(
            status_code=400,
            detail="Invalid alert ID."
        )

    alert = alerts_collection.find_one(
        {
            "_id": object_id
        }
    )

    if not alert:

        raise HTTPException(
            status_code=404,
            detail="Alert not found."
        )

    return {

        "success": True,

        "alert": serialize_document(
            alert
        )
    }


# ============================================================
# UPDATE ALERT STATUS
# ============================================================

@router.put("/{alert_id}/status")
def update_alert_status(
    alert_id: str,
    status: str
):

    if status not in ALERT_STATUSES:

        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid alert status. "
                f"Allowed values: {ALERT_STATUSES}"
            )
        )

    try:

        object_id = ObjectId(
            alert_id
        )

    except Exception:

        raise HTTPException(
            status_code=400,
            detail="Invalid alert ID."
        )

    alert = alerts_collection.find_one(
        {
            "_id": object_id
        }
    )

    if not alert:

        raise HTTPException(
            status_code=404,
            detail="Alert not found."
        )

    now = datetime.now(timezone.utc)

    alerts_collection.update_one(

        {
            "_id": object_id
        },

        {
            "$set": {

                "status": status,

                "updated_at": now
            }
        }
    )

    return {

        "success": True,

        "message": (
            "Alert status updated successfully."
        ),

        "alert_id": alert_id,

        "status": status
    }


# ============================================================
# GET NOTIFICATIONS
# ============================================================

@router.get("/notifications/all")
def get_notifications(
    role: str | None = Query(
        default=None
    ),
    unread_only: bool = Query(
        default=False
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=500
    )
):

    query = {}

    if role:

        query["recipient_role"] = role

    if unread_only:

        query["read"] = False

    notifications = list(

        notifications_collection
        .find(query)
        .sort(
            "created_at",
            -1
        )
        .limit(limit)
    )

    serialized_notifications = [

        serialize_document(
            notification
        )

        for notification in notifications
    ]

    return {

        "success": True,

        "total": len(
            serialized_notifications
        ),

        "notifications": serialized_notifications
    }


# ============================================================
# UNREAD NOTIFICATION COUNT
# ============================================================

@router.get("/notifications/unread")
def get_unread_notifications(
    role: str | None = Query(
        default=None
    )
):

    query = {
        "read": False
    }

    if role:

        query["recipient_role"] = role

    count = notifications_collection.count_documents(
        query
    )

    return {

        "success": True,

        "unread_count": count
    }


# ============================================================
# MARK NOTIFICATION AS READ
# ============================================================

@router.put("/notifications/{notification_id}/read")
def mark_notification_as_read(
    notification_id: str
):

    try:

        object_id = ObjectId(
            notification_id
        )

    except Exception:

        raise HTTPException(
            status_code=400,
            detail="Invalid notification ID."
        )

    notification = notifications_collection.find_one(
        {
            "_id": object_id
        }
    )

    if not notification:

        raise HTTPException(
            status_code=404,
            detail="Notification not found."
        )

    now = datetime.now(timezone.utc)

    notifications_collection.update_one(

        {
            "_id": object_id
        },

        {
            "$set": {

                "read": True,

                "status": "Read",

                "updated_at": now
            }
        }
    )

    return {

        "success": True,

        "message": (
            "Notification marked as read."
        ),

        "notification_id": notification_id
    }


# ============================================================
# MARK ALL NOTIFICATIONS AS READ
# ============================================================

@router.put("/notifications/read-all")
def mark_all_notifications_as_read(
    role: str | None = Query(
        default=None
    )
):

    query = {
        "read": False
    }

    if role:

        query["recipient_role"] = role

    now = datetime.now(timezone.utc)

    result = notifications_collection.update_many(

        query,

        {
            "$set": {

                "read": True,

                "status": "Read",

                "updated_at": now
            }
        }
    )

    return {

        "success": True,

        "message": (
            "All notifications marked as read."
        ),

        "updated_count": result.modified_count
    }