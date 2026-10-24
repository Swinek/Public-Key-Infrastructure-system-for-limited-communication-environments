"""Measurements: how many bytes this edge client sent and received, per kind of object and per peer."""
from fastapi import APIRouter, Query
from fastapi.responses import Response

import config
import transfers

router = APIRouter(prefix="/api/stats", tags=["Transfer statistics"])


@router.get("/transfers", summary="Totals by kind, peer and direction (?format=csv: every record as CSV)")
def get_transfers(format: str = Query("json", pattern="^(json|csv)$"), records: bool = False):
    if format == "csv":
        return Response(content=transfers.to_csv(), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{config.NODE_ID}_transfers.csv"'})
    result = transfers.summary()
    if records:
        result["entries"] = transfers.entries()
    return result


@router.delete("/transfers", summary="Clear the register (before a measurement scenario)")
def reset_transfers():
    return {"node_id": config.NODE_ID, "removed": transfers.reset()}
