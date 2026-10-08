from fastapi import APIRouter
from cyberfusion.app.schemas.schemas import RansomwareSimulationRequest
from cyberfusion.app.modules.ransomware.monitor import ransomware_monitor

router = APIRouter(prefix="/api/ransomware", tags=["Ransomware Behavioral Detection"])

@router.post("/simulate")
async def simulate_ransomware(req: RansomwareSimulationRequest):
    return ransomware_monitor.evaluate_behavior(
        host=req.host,
        process_name=req.process_name,
        files_modified=req.files_modified,
        duration_seconds=req.duration_seconds
    )

@router.get("/alerts")
async def get_ransomware_alerts():
    return [
        {
            "id": 1,
            "host": "workstation-09.corp",
            "process_name": "cryptolocker.exe",
            "files_modified_count": 1284,
            "duration_seconds": 45,
            "entropy_score": 7.9,
            "behavior_flag": "Mass File Encryption Spike",
            "severity": "CRITICAL",
            "is_isolated": True,
            "containment_action": "ISOLATE_ENDPOINT_IMMEDIATELY",
            "status": "CONTAINED"
        }
    ]
