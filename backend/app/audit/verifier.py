"""Hourly audit-chain verification job + on-demand API support."""
from __future__ import annotations

import asyncio
import logging

from app.audit import chain

log = logging.getLogger("cwb.audit.verifier")


async def verifier_loop(period_s: int = 3600):
    while True:
        try:
            res = await asyncio.to_thread(chain.verify_chain)
            if not res["ok"]:
                log.critical("AUDIT CHAIN BROKEN at seq %s: %s", res.get("broken_at"), res.get("reason"))
                chain.safe_append("system:verifier", "audit.chain_broken", "audit_log", res)
            else:
                log.info("audit chain verified: %s rows", res.get("verified"))
        except Exception:
            log.exception("verifier crashed")
        await asyncio.sleep(period_s)
