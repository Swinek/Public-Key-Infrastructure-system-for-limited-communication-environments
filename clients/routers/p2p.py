import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
import requests
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from fastapi.responses import JSONResponse, FileResponse

import config
import state
from models import MessagePayload, IncomingMessage

router = APIRouter(prefix="/api/p2p", tags=["P2P Communication"])


@router.get("/test", summary="Test P2P connectivity with peer")
def test_p2p_link(timeout: float = 3.0):
    target_url = f"http://{config.PEER_IP}:{config.PORT}/api/status"
    start_t = time.time()
    try:
        resp = requests.get(
            target_url,
            headers={"User-Agent": f"ClientNode/{config.NODE_ID}"},
            timeout=timeout
        )
        latency_ms = round((time.time() - start_t) * 1000, 2)
        if resp.status_code == 200:
            peer_data = resp.json()
            return {
                "node_id": config.NODE_ID,
                "node_name": config.NODE_NAME,
                "p2p_connected": True,
                "target_peer": config.PEER_NAME,
                "target_address": f"{config.PEER_IP}:{config.PORT}",
                "latency_ms": latency_ms,
                "message": f"P2P link to {config.PEER_NAME} established successfully ({latency_ms} ms).",
                "peer_info": {
                    "node_id": peer_data.get("node_id"),
                    "node_name": peer_data.get("node_name"),
                    "uptime_seconds": peer_data.get("uptime_seconds"),
                    "network_mode": peer_data.get("network_mode")
                }
            }
        else:
            return JSONResponse(
                status_code=502,
                content={
                    "p2p_connected": False,
                    "target_peer": config.PEER_NAME,
                    "target_address": f"{config.PEER_IP}:{config.PORT}",
                    "error": f"Peer responded with HTTP status {resp.status_code}"
                }
            )
    except Exception as e:
        return JSONResponse(
            status_code=200,
            content={
                "node_id": config.NODE_ID,
                "node_name": config.NODE_NAME,
                "p2p_connected": False,
                "target_peer": config.PEER_NAME,
                "target_address": f"{config.PEER_IP}:{config.PORT}",
                "error": f"No P2P connection: {type(e).__name__} ({str(e)})"
            }
        )


@router.post("/send-message", summary="Send P2P message to peer")
def send_p2p_message(payload: MessagePayload):
    target_url = f"http://{config.PEER_IP}:{config.PORT}/api/p2p/receive-message"
    outgoing = {
        "sender_id": config.NODE_ID,
        "sender_name": config.NODE_NAME,
        "message": payload.message,
        "sent_at": datetime.now(timezone.utc).isoformat()
    }
    try:
        resp = requests.post(target_url, json=outgoing, timeout=4.0)
        if resp.status_code == 200:
            return {
                "status": "SENT",
                "recipient": config.PEER_NAME,
                "recipient_address": f"{config.PEER_IP}:{config.PORT}",
                "sent_message": outgoing,
                "delivery_confirmation": resp.json()
            }
        raise HTTPException(status_code=502, detail=f"Peer reception error: {resp.text}")
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Failed to send P2P message to {config.PEER_NAME} ({config.PEER_IP}): {str(e)}"
        )


@router.post("/receive-message", summary="Receive P2P message")
def receive_p2p_message(msg: IncomingMessage):
    received_entry = {
        "id": len(state.INBOX) + 1,
        "sender_id": msg.sender_id,
        "sender_name": msg.sender_name,
        "message": msg.message,
        "sent_at": msg.sent_at,
        "received_at": datetime.now(timezone.utc).isoformat()
    }
    state.INBOX.append(received_entry)
    print(f"\n[P2P MESSAGE RECEIVED] From: {msg.sender_name} | Content: {msg.message}\n")
    return {
        "status": "DELIVERED",
        "inbox_id": received_entry["id"],
        "received_at": received_entry["received_at"]
    }


@router.get("/inbox", summary="P2P messages inbox")
def get_p2p_inbox():
    return {
        "node_name": config.NODE_NAME,
        "messages_count": len(state.INBOX),
        "messages": state.INBOX
    }


@router.post("/send-file", summary="Send file via P2P with SHA-256 verification")
async def send_file_to_peer(file: UploadFile = File(...)):
    content = await file.read()
    sha256_hash = hashlib.sha256(content).hexdigest()

    target_url = f"http://{config.PEER_IP}:{config.PORT}/api/p2p/receive-file"
    files = {"file": (file.filename, content, file.content_type)}
    data = {
        "sender_id": config.NODE_ID,
        "sender_name": config.NODE_NAME,
        "expected_sha256": sha256_hash
    }

    try:
        resp = requests.post(target_url, files=files, data=data, timeout=10.0)
        if resp.status_code == 200:
            return {
                "status": "FILE_TRANSFERRED",
                "filename": file.filename,
                "size_bytes": len(content),
                "sha256": sha256_hash,
                "recipient": config.PEER_NAME,
                "peer_response": resp.json()
            }
        raise HTTPException(status_code=502, detail=f"Peer rejected file: {resp.text}")
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"P2P transfer error: {str(e)}")


@router.post("/receive-file", summary="Receive file and verify SHA-256 checksum")
async def receive_file(
    file: UploadFile = File(...),
    sender_id: str = Form(...),
    sender_name: str = Form(...),
    expected_sha256: str = Form(...)
):
    content = await file.read()
    calculated_sha256 = hashlib.sha256(content).hexdigest()

    if calculated_sha256.lower() != expected_sha256.lower():
        raise HTTPException(
            status_code=400,
            detail=f"DATA INTEGRITY ERROR: SHA-256 mismatch! Expected: {expected_sha256}, Calculated: {calculated_sha256}"
        )

    safe_name = Path(file.filename).name
    save_path = config.STORAGE_DIR / safe_name
    with open(save_path, "wb") as f:
        f.write(content)

    print(f"\n[FILE TRANSFER COMPLETED] File '{safe_name}' ({len(content)} B) from {sender_name} verified (SHA-256 OK).\n")

    return {
        "status": "SAVED",
        "filename": safe_name,
        "size_bytes": len(content),
        "sha256": calculated_sha256,
        "integrity_verified": True,
        "saved_at": datetime.now(timezone.utc).isoformat()
    }


@router.get("/files", summary="List received P2P files")
def list_received_files():
    files = []
    for f in config.STORAGE_DIR.glob("*"):
        if f.is_file():
            stat = f.stat()
            content = f.read_bytes()
            files.append({
                "filename": f.name,
                "size_bytes": stat.st_size,
                "sha256": hashlib.sha256(content).hexdigest(),
                "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
            })
    return {
        "node_name": config.NODE_NAME,
        "storage_path": str(config.STORAGE_DIR),
        "count": len(files),
        "files": files
    }


@router.get("/files/{filename}", summary="Download received file")
def download_received_file(filename: str):
    safe_name = Path(filename).name
    target_path = config.STORAGE_DIR / safe_name
    if not target_path.exists() or not target_path.is_file():
        raise HTTPException(status_code=404, detail="File does not exist.")
    return FileResponse(target_path, filename=safe_name)
