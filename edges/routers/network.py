import socket
import time
from datetime import datetime, timezone
import requests
from fastapi import APIRouter
from fastapi.responses import JSONResponse

import config
import neighbours
import routing
import state
from utils import has_default_gateway, check_socket_connectivity

router = APIRouter(tags=["Network & Diagnostics"])


@router.get("/api/status", summary="Detailed node status")
def get_status():
    uptime = int(time.time() - state.START_TIME)
    has_gw = has_default_gateway()
    mode = "ONLINE" if has_gw else "OFFLINE"

    return {
        "node_id": config.NODE_ID,
        "node_name": config.NODE_NAME,
        "client_id": config.NODE_ID,
        "client_name": config.NODE_NAME,
        "local_ips": [i["ip"] for i in neighbours.p2p_interfaces()],
        "local_port": config.PORT,
        "peers": neighbours.current(),
        "destinations": routing.known_destinations(),
        "uptime_seconds": uptime,
        "system_time_utc": datetime.now(timezone.utc).isoformat(),
        "network_mode": mode,
        "has_internet": has_gw,
        "has_default_gateway": has_gw,
        "received_messages_count": len(state.inbox_snapshot()),
        "received_files_count": len([f for f in config.STORAGE_DIR.glob("*") if f.is_file() and not f.name.startswith(".")])
    }


@router.get("/api/clock", summary="Query external Clock API")
def get_external_clock(timeout: float = 3.0):
    primary_msg = None
    fallback_msg = None

    try:
        start_req = time.time()
        resp = requests.get(
            config.CLOCK_API_PRIMARY,
            headers={"User-Agent": f"ClientNode/{config.NODE_ID}"},
            timeout=timeout
        )
        latency_ms = round((time.time() - start_req) * 1000, 2)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "node_id": config.NODE_ID,
                "node_name": config.NODE_NAME,
                "internet_accessible": True,
                "status": "ONLINE",
                "message": "Successfully retrieved time from external Clock API.",
                "source": config.CLOCK_API_PRIMARY,
                "latency_ms": latency_ms,
                "dateTime": data.get("dateTime"),
                "date": data.get("date"),
                "time": data.get("time"),
                "timeZone": data.get("timeZone"),
                "raw": data
            }
    except Exception as primary_err:
        primary_msg = str(primary_err)

    try:
        start_req = time.time()
        resp = requests.get(
            config.CLOCK_API_FALLBACK,
            headers={"User-Agent": f"ClientNode/{config.NODE_ID}"},
            timeout=timeout
        )
        latency_ms = round((time.time() - start_req) * 1000, 2)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "node_id": config.NODE_ID,
                "node_name": config.NODE_NAME,
                "internet_accessible": True,
                "status": "ONLINE",
                "message": "Successfully retrieved time from fallback Clock API.",
                "source": config.CLOCK_API_FALLBACK,
                "latency_ms": latency_ms,
                "dateTime": data.get("datetime"),
                "raw": data
            }
    except Exception as fallback_err:
        fallback_msg = str(fallback_err)

    return JSONResponse(
        status_code=200,
        content={
            "node_id": config.NODE_ID,
            "node_name": config.NODE_NAME,
            "internet_accessible": False,
            "status": "OFFLINE",
            "message": "No Internet access. External Clock API is unreachable.",
            "primary_error": primary_msg,
            "fallback_error": fallback_msg
        }
    )


@router.get("/api/internet/check", summary="Check Internet connectivity")
def check_internet():
    has_gw = has_default_gateway()

    dns_resolved = False
    try:
        socket.gethostbyname("dns.google")
        dns_resolved = True
    except Exception:
        pass

    tcp_connected = check_socket_connectivity("1.1.1.1", 80, timeout=2.0)

    public_ip = None
    if tcp_connected or dns_resolved:
        try:
            r = requests.get("https://api.ipify.org?format=json", timeout=2.5)
            if r.status_code == 200:
                public_ip = r.json().get("ip")
        except Exception:
            pass

    has_internet = bool(tcp_connected or dns_resolved)
    mode = "ONLINE" if has_internet else "OFFLINE"

    return {
        "node_id": config.NODE_ID,
        "node_name": config.NODE_NAME,
        "mode": mode,
        "status": mode,
        "has_internet": has_internet,
        "has_default_gateway": has_gw,
        "dns_resolution_ok": dns_resolved,
        "tcp_outbound_ok": tcp_connected,
        "public_ip": public_ip,
        "message": (
            "Internet access: ACTIVE (ONLINE)."
            if has_internet else
            "No Internet access (OFFLINE)."
        )
    }


@router.get("/api/internet/test", summary="Test Internet connectivity (WAN RTT)")
def test_internet_link(timeout: float = 3.0):
    has_gw = has_default_gateway()
    if not has_gw:
        return JSONResponse(
            status_code=200,
            content={
                "node_id": config.NODE_ID,
                "node_name": config.NODE_NAME,
                "channel": "INTERNET / WAN",
                "internet_connected": False,
                "status": "OFFLINE",
                "latency_ms": None,
                "target": "Internet WAN Gateway (1.1.1.1)",
                "error": "No Internet connectivity (interface disconnected).",
                "message": "Internet connection unavailable - OFFLINE mode."
            }
        )

    start_t = time.time()
    target_host = "https://1.1.1.1"
    try:
        resp = requests.get(target_host, timeout=timeout, headers={"User-Agent": f"ClientNode/{config.NODE_ID}"})
        latency_ms = round((time.time() - start_t) * 1000, 2)

        # Other nodes over WAN: client.sh connects nodes to internet_net with alias "inet-<id>",
        # so this name resolves only via internet_net (never via the P2P radio networks).
        peers_internet = []
        for dest in routing.known_destinations():
            entry = {"id": dest["id"], "name": dest["name"], "accessible": False, "latency_ms": None}
            try:
                start_p = time.time()
                p_resp = requests.get(f"http://inet-{dest['id']}:{config.PORT}/api/status", timeout=1.5)
                if p_resp.status_code == 200:
                    entry["accessible"] = True
                    entry["latency_ms"] = round((time.time() - start_p) * 1000, 2)
            except Exception:
                pass
            peers_internet.append(entry)

        public_ip = None
        try:
            ip_resp = requests.get("https://api.ipify.org?format=json", timeout=2.0)
            if ip_resp.status_code == 200:
                public_ip = ip_resp.json().get("ip")
        except Exception:
            pass

        return {
            "node_id": config.NODE_ID,
            "node_name": config.NODE_NAME,
            "channel": "INTERNET / WAN",
            "internet_connected": True,
            "status": "ONLINE",
            "latency_ms": latency_ms,
            "target": "Internet WAN Gateway (Cloudflare 1.1.1.1)",
            "public_ip": public_ip,
            "peer_internet_accessible": any(p["accessible"] for p in peers_internet),
            "peers_internet": peers_internet,
            "message": f"Internet connection active (RTT: {latency_ms} ms)."
        }
    except Exception as e:
        return JSONResponse(
            status_code=200,
            content={
                "node_id": config.NODE_ID,
                "node_name": config.NODE_NAME,
                "channel": "INTERNET / WAN",
                "internet_connected": False,
                "status": "OFFLINE",
                "latency_ms": None,
                "target": "Internet WAN Gateway (1.1.1.1)",
                "error": f"Internet connection error: {type(e).__name__} ({str(e)})",
                "message": "Failed to establish connection via Internet."
            }
        )
