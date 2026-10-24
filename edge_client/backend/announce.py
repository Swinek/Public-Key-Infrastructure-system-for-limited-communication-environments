"""Impuls z centrum: nowa CRL albo decyzja o wniosku CSR -> natychmiastowy kontakt WAN u węzłów online.

CA po zapisaniu CRL wysyła NOTIFY na kanale `crl_issued` (admin/backend/pki/store.py). Portal nasłuchuje na nim
(LISTEN nie wymaga uprawnień, wystarcza konto tylko do odczytu) i każdemu węzłowi online wysyła
POST /api/contact/wan. Węzeł sam pobiera wtedy /pki/summary i nowszą CRL (pki_sync.py), a po zapisie ogłasza ją
sąsiadom przez P2P – więc CRL idzie od razu dalej do węzłów bez internetu.

Portal nie zna topologii ani adresów z konfiguracji: „węzeł online” to Edge client, który pobrał /pki/summary
przez internet_net (robi to przy każdym kontakcie WAN, np. `client.sh internet on`); jego id pochodzi
z nagłówka User-Agent `EdgeClient/<id>`. Węzeł, do którego impuls nie dojdzie (`internet off`), jest usuwany
z listy i wraca przy następnym kontakcie. Impuls niczego nie przenosi – dane i tak są sprawdzane podpisem CA.
"""

import asyncio
import logging
import os
import urllib.request
from typing import Dict, List, Optional

import asyncpg
from fastapi import Request

logger = logging.getLogger("pki_edge_client_backend.announce")

# Kanały NOTIFY z CA: nowa CRL (admin/backend/pki/store.py) i decyzja o wniosku CSR (admin/backend/routers/csr.py).
CHANNELS = ("crl_issued", "cert_issued")
NODE_PORT = int(os.getenv("NODE_PORT", "8000"))
NOTIFY_TIMEOUT = float(os.getenv("NODE_NOTIFY_TIMEOUT", "3"))

_ONLINE: Dict[str, str] = {}  # node_id -> adres w internet_net (z ostatniego żądania węzła)


def remember(request: Request) -> Optional[str]:
    """Zapamiętuje węzeł, który właśnie pobiera dane przez WAN. Zwraca jego id albo None (nie Edge client)."""
    agent = request.headers.get("user-agent", "")
    if not agent.startswith("EdgeClient/") or request.client is None:
        return None
    node_id = agent.split("/", 1)[1][:64]
    _ONLINE[node_id] = request.client.host
    return node_id


def online() -> Dict[str, str]:
    return dict(_ONLINE)


def _post(url: str) -> int:
    req = urllib.request.Request(url, data=b"", method="POST", headers={"User-Agent": "PkiPortal"})
    with urllib.request.urlopen(req, timeout=NOTIFY_TIMEOUT) as resp:
        return resp.status


async def notify_nodes(reason: str) -> Dict[str, str]:
    """Wysyła impuls do wszystkich węzłów online (równolegle). Zwraca node_id -> 'ok' / opis błędu."""
    targets = online()

    async def one(node_id: str, host: str) -> str:
        try:
            await asyncio.to_thread(_post, f"http://{host}:{NODE_PORT}/api/contact/wan")
            return "ok"
        except Exception as exc:  # węzeł odłączony od internet_net albo nie odpowiada
            if _ONLINE.get(node_id) == host:
                del _ONLINE[node_id]
            return f"{type(exc).__name__}: {exc}"

    results = await asyncio.gather(*(one(n, h) for n, h in targets.items()))
    outcome = dict(zip(targets, results))
    logger.info("Impuls %s -> węzły online: %s", reason, outcome or "brak")
    return outcome


async def listen(dsn: str, retry_delay: float = 2.0) -> None:
    """Zadanie w tle: LISTEN crl_issued; po zerwaniu połączenia z bazą łączy się ponownie."""
    loop = asyncio.get_running_loop()
    tasks: List[asyncio.Task] = []

    def on_notify(connection, pid, channel, payload):
        tasks.append(loop.create_task(notify_nodes(f"{channel}:{payload}")))
        tasks[:] = [t for t in tasks if not t.done()]

    while True:
        conn = None
        try:
            conn = await asyncpg.connect(dsn)
            closed = asyncio.Event()
            conn.add_termination_listener(lambda c: closed.set())
            for channel in CHANNELS:
                await conn.add_listener(channel, on_notify)
            logger.info("Nasłuch zdarzeń CA (LISTEN %s)", ", ".join(CHANNELS))
            await closed.wait()
            logger.warning("Połączenie LISTEN zerwane – ponawiam")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("LISTEN nieudany: %s – ponawiam za %.0f s", exc, retry_delay)
        finally:
            if conn is not None and not conn.is_closed():
                await conn.close()
        await asyncio.sleep(retry_delay)
