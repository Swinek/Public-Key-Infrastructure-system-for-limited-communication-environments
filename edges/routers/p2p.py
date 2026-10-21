import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse

import config
import routing
import state
from models import MessagePayload, IncomingMessage

router = APIRouter(prefix="/api/p2p", tags=["P2P Communication"])


def _p2p_timeout():
    return (config.P2P_CONNECT_TIMEOUT, config.P2P_READ_TIMEOUT)


def _error_detail(resp: requests.Response) -> str:
    try:
        return str(resp.json().get("detail", resp.text))
    except ValueError:
        return resp.text


def _next_hop_or_404(destination_id: str) -> Dict[str, str]:
    try:
        return routing.resolve_next_hop(destination_id)
    except routing.NoRouteError as e:
        raise HTTPException(status_code=404, detail=str(e))


def _check_hops(hops: List[str]) -> None:
    if config.NODE_ID in hops:
        raise HTTPException(status_code=409, detail=f"Routing loop detected: {config.NODE_ID} already in hops {hops}.")
    if len(hops) >= config.P2P_MAX_HOPS:
        raise HTTPException(status_code=409, detail=f"Hop limit exceeded ({config.P2P_MAX_HOPS}): {hops}.")


def _test_peer(peer: Dict[str, str], timeout: float) -> Dict[str, Any]:
    result = {
        "peer_id": peer["id"],
        "peer_name": peer["name"],
        "target_address": f"{peer['ip']}:{config.PORT}",
        "p2p_connected": False,
    }
    start_t = time.time()
    try:
        resp = requests.get(
            routing.peer_url(peer, "/api/status"),
            headers={"User-Agent": f"ClientNode/{config.NODE_ID}"},
            timeout=timeout
        )
        latency_ms = round((time.time() - start_t) * 1000, 2)
        if resp.status_code != 200:
            result["error"] = f"Peer responded with HTTP status {resp.status_code}"
            return result
        peer_data = resp.json()
        result.update({
            "p2p_connected": True,
            "latency_ms": latency_ms,
            "peer_info": {
                "node_id": peer_data.get("node_id"),
                "node_name": peer_data.get("node_name"),
                "uptime_seconds": peer_data.get("uptime_seconds"),
                "network_mode": peer_data.get("network_mode")
            }
        })
    except Exception as e:
        result["error"] = f"No P2P connection: {type(e).__name__} ({str(e)})"
    return result


@router.get("/test", summary="Test P2P connectivity with neighbours (all or ?peer_id=)")
def test_p2p_link(timeout: float = 3.0, peer_id: Optional[str] = None):
    peers = config.PEERS
    if peer_id:
        peer = routing.get_peer(peer_id)
        if not peer:
            raise HTTPException(status_code=404, detail=f"'{peer_id}' is not a direct neighbour of {config.NODE_ID}.")
        peers = [peer]

    results = [_test_peer(p, timeout) for p in peers]
    connected = [r for r in results if r["p2p_connected"]]
    return {
        "node_id": config.NODE_ID,
        "node_name": config.NODE_NAME,
        "p2p_connected": len(connected) > 0,
        "peers_total": len(results),
        "peers_connected": len(connected),
        "message": f"{len(connected)}/{len(results)} P2P neighbours reachable.",
        "results": results
    }


@router.get("/destinations", summary="Known destinations (neighbours + routed)")
def get_destinations():
    return {
        "node_id": config.NODE_ID,
        "peers": config.PEERS,
        "routes": config.ROUTES,
        "destinations": routing.known_destinations()
    }


def _relay_message(msg: Dict[str, Any]) -> Dict[str, Any]:
    """Synchronously hands the message to the next hop towards msg['destination_id'].
    Stage 3: this is the place to enqueue instead of failing when the next hop is unreachable."""
    next_hop = _next_hop_or_404(msg["destination_id"])
    try:
        resp = requests.post(
            routing.peer_url(next_hop, "/api/p2p/receive-message"), json=msg, timeout=_p2p_timeout()
        )
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"{config.NODE_ID} -> {next_hop['id']} ({next_hop['ip']}) unreachable: {type(e).__name__} ({str(e)})"
        )
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"{next_hop['id']}: {_error_detail(resp)}")
    return {"next_hop": next_hop, "response": resp.json()}


@router.post("/send-message", summary="Send P2P message (direct or routed via neighbours)")
def send_p2p_message(payload: MessagePayload):
    try:
        destination_id = routing.resolve_destination(payload.to)
    except routing.NoRouteError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if destination_id == config.NODE_ID:
        raise HTTPException(status_code=400, detail="Cannot send a message to this node itself.")

    outgoing = IncomingMessage(
        sender_id=config.NODE_ID,
        sender_name=config.NODE_NAME,
        origin_id=config.NODE_ID,
        origin_name=config.NODE_NAME,
        destination_id=destination_id,
        hops=[config.NODE_ID],
        message=payload.message,
        sent_at=datetime.now(timezone.utc).isoformat()
    ).model_dump()

    relayed = _relay_message(outgoing)
    next_hop = relayed["next_hop"]
    confirmation = relayed["response"]
    return {
        "status": "SENT",
        "recipient": destination_id,
        "next_hop": next_hop["id"],
        "next_hop_address": f"{next_hop['ip']}:{config.PORT}",
        "route": confirmation.get("route"),
        "sent_message": outgoing,
        "delivery_confirmation": confirmation
    }


@router.post("/receive-message", summary="Receive P2P message (store locally or forward)")
def receive_p2p_message(msg: IncomingMessage):
    hops = list(msg.hops) or [msg.sender_id]
    _check_hops(hops)
    destination_id = msg.destination_id or config.NODE_ID

    if destination_id != config.NODE_ID:
        forwarded = msg.model_dump()
        forwarded.update({
            "sender_id": config.NODE_ID,
            "sender_name": config.NODE_NAME,
            "destination_id": destination_id,
            "hops": hops + [config.NODE_ID]
        })
        print(f"\n[P2P FORWARD] {msg.msg_id}: {hops} -> {config.NODE_ID} -> {destination_id}\n")
        relayed = _relay_message(forwarded)
        downstream = relayed["response"]
        return {**downstream, "forwarded_by": config.NODE_ID}

    entry, created = state.add_inbox_entry({
        "msg_id": msg.msg_id,
        "sender_id": msg.sender_id,
        "sender_name": msg.sender_name,
        "origin_id": msg.origin_id or msg.sender_id,
        "origin_name": msg.origin_name or msg.sender_name,
        "hops": hops,
        "route": hops + [config.NODE_ID],
        "message": msg.message,
        "sent_at": msg.sent_at,
        "received_at": datetime.now(timezone.utc).isoformat()
    })
    if created:
        print(f"\n[P2P MESSAGE RECEIVED] From: {entry['origin_name']} | Route: {' -> '.join(entry['route'])} | Content: {msg.message}\n")
    return {
        "status": "DELIVERED" if created else "DUPLICATE",
        "inbox_id": entry["id"],
        "msg_id": entry["msg_id"],
        "route": entry["route"],
        "received_at": entry["received_at"]
    }


@router.get("/inbox", summary="P2P messages inbox")
def get_p2p_inbox():
    messages = state.inbox_snapshot()
    return {
        "node_name": config.NODE_NAME,
        "messages_count": len(messages),
        "messages": messages
    }


def _relay_file(filename: str, content: bytes, content_type: Optional[str], meta: Dict[str, Any]) -> Dict[str, Any]:
    """Synchronously hands the file to the next hop towards meta['destination_id'] (kept in memory only)."""
    next_hop = _next_hop_or_404(meta["destination_id"])
    data = {**meta, "hops": json.dumps(meta["hops"])}
    try:
        resp = requests.post(
            routing.peer_url(next_hop, "/api/p2p/receive-file"),
            files={"file": (filename, content, content_type)},
            data=data,
            timeout=_p2p_timeout()
        )
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"{config.NODE_ID} -> {next_hop['id']} ({next_hop['ip']}) unreachable: {type(e).__name__} ({str(e)})"
        )
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"{next_hop['id']}: {_error_detail(resp)}")
    return {"next_hop": next_hop, "response": resp.json()}


@router.post("/send-file", summary="Send file via P2P (direct or routed via neighbours)")
async def send_file_to_peer(file: UploadFile = File(...), to: Optional[str] = Form(None)):
    try:
        destination_id = routing.resolve_destination(to)
    except routing.NoRouteError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if destination_id == config.NODE_ID:
        raise HTTPException(status_code=400, detail="Cannot send a file to this node itself.")

    content = await file.read()
    meta = {
        "msg_id": uuid.uuid4().hex,
        "sender_id": config.NODE_ID,
        "sender_name": config.NODE_NAME,
        "origin_id": config.NODE_ID,
        "origin_name": config.NODE_NAME,
        "destination_id": destination_id,
        "hops": [config.NODE_ID],
        "expected_sha256": hashlib.sha256(content).hexdigest()
    }
    relayed = _relay_file(file.filename, content, file.content_type, meta)
    return {
        "status": "FILE_TRANSFERRED",
        "filename": file.filename,
        "size_bytes": len(content),
        "sha256": meta["expected_sha256"],
        "recipient": destination_id,
        "next_hop": relayed["next_hop"]["id"],
        "route": relayed["response"].get("route"),
        "peer_response": relayed["response"]
    }


@router.post("/receive-file", summary="Receive file (save locally or forward)")
async def receive_file(
    file: UploadFile = File(...),
    sender_id: str = Form(...),
    sender_name: str = Form(...),
    msg_id: Optional[str] = Form(None),
    origin_id: Optional[str] = Form(None),
    origin_name: Optional[str] = Form(None),
    destination_id: Optional[str] = Form(None),
    hops: Optional[str] = Form(None, description="JSON list of traversed node ids"),
    expected_sha256: Optional[str] = Form(None)
):
    try:
        hop_list = json.loads(hops) if hops else [sender_id]
        if not isinstance(hop_list, list):
            raise ValueError
    except ValueError:
        raise HTTPException(status_code=422, detail="'hops' must be a JSON list of node ids.")
    _check_hops(hop_list)

    content = await file.read()
    actual_sha256 = hashlib.sha256(content).hexdigest()
    if expected_sha256 and expected_sha256.lower() != actual_sha256:
        raise HTTPException(
            status_code=422,
            detail=f"SHA-256 mismatch at {config.NODE_ID}: expected {expected_sha256}, got {actual_sha256}."
        )

    destination_id = destination_id or config.NODE_ID
    if destination_id != config.NODE_ID:
        # Transit: the file is not stored in this node's received_files.
        meta = {
            "msg_id": msg_id or uuid.uuid4().hex,
            "sender_id": config.NODE_ID,
            "sender_name": config.NODE_NAME,
            "origin_id": origin_id or sender_id,
            "origin_name": origin_name or sender_name,
            "destination_id": destination_id,
            "hops": hop_list + [config.NODE_ID],
            "expected_sha256": actual_sha256
        }
        print(f"\n[P2P FORWARD FILE] '{file.filename}' ({len(content)} B): {hop_list} -> {config.NODE_ID} -> {destination_id}\n")
        relayed = _relay_file(file.filename, content, file.content_type, meta)
        return {**relayed["response"], "forwarded_by": config.NODE_ID}

    safe_name = Path(file.filename).name
    if not safe_name or safe_name.startswith("."):
        raise HTTPException(status_code=422, detail="Invalid file name.")
    save_path = config.STORAGE_DIR / safe_name
    # Atomic write: an interrupted transfer never leaves a truncated file under the final name.
    tmp_path = config.STORAGE_DIR / f".part-{uuid.uuid4().hex}"
    with open(tmp_path, "wb") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, save_path)

    route = hop_list + [config.NODE_ID]
    print(f"\n[FILE TRANSFER COMPLETED] File '{safe_name}' ({len(content)} B) from {origin_name or sender_name}, route: {' -> '.join(route)}.\n")

    return {
        "status": "SAVED",
        "filename": safe_name,
        "size_bytes": len(content),
        "sha256": actual_sha256,
        "route": route,
        "saved_at": datetime.now(timezone.utc).isoformat()
    }


@router.get("/files", summary="List received P2P files")
def list_received_files():
    files = []
    for f in config.STORAGE_DIR.glob("*"):
        if f.is_file() and not f.name.startswith("."):
            stat = f.stat()
            files.append({
                "filename": f.name,
                "size_bytes": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
            })
    return {
        "node_name": config.NODE_NAME,
        "storage_path": str(config.STORAGE_DIR),
        "count": len(files),
        "files": files
    }


@router.get("/files/{filename}", summary="Download or preview received file")
def download_received_file(filename: str, inline: bool = False):
    safe_name = Path(filename).name
    target_path = config.STORAGE_DIR / safe_name
    if safe_name.startswith(".") or not target_path.exists() or not target_path.is_file():
        raise HTTPException(status_code=404, detail="File does not exist.")

    media_type = None
    ext = target_path.suffix.lower()
    if ext in [".txt", ".pem", ".crl", ".crt", ".key", ".csr", ".log", ".json", ".md"]:
        media_type = "text/plain; charset=utf-8"
    elif ext in [".jpg", ".jpeg"]:
        media_type = "image/jpeg"
    elif ext == ".png":
        media_type = "image/png"
    elif ext == ".gif":
        media_type = "image/gif"
    elif ext == ".webp":
        media_type = "image/webp"
    elif ext == ".svg":
        media_type = "image/svg+xml"
    elif ext == ".pdf":
        media_type = "application/pdf"

    disposition = "inline" if inline else "attachment"
    return FileResponse(
        target_path,
        filename=safe_name,
        media_type=media_type,
        content_disposition_type=disposition
    )
