"""Dratove tvary. Zavazna je KNIHOVNA, ne drat - tvar zprav je jeji vnitrek.

Presne ctyri podoby odpovedi na authenticate; `reason` jen komponentam
s detail=true. Jen stdlib - modul musi jit importovat bez extras.
"""
from __future__ import annotations

from .principals import Group, User
from .verdicts import Verdict


def verdict_to_wire(verdikt: Verdict, *, detail: bool) -> dict:
    telo: dict = {"outcome": verdikt.outcome, "gen": verdikt.gen}
    if verdikt.outcome == "ok":
        telo["subject_id"] = verdikt.subject_id
        telo["principals"] = sorted(verdikt.principals)
    elif verdikt.outcome == "need_factor":
        telo["required"] = list(verdikt.required)
    elif verdikt.outcome == "throttled":
        telo["retry_after"] = verdikt.retry_after
    elif detail and verdikt.reason:
        telo["reason"] = verdikt.reason
    return telo


def user_to_wire(user: User | None) -> dict:
    if user is None:
        return {"exists": False}
    return {
        "exists": True,
        "subject_id": user.subject_id,
        "enabled": user.enabled,
        "principals": sorted(user.principals),
    }


def group_to_wire(name: str, group: Group | None) -> dict:
    if group is None:
        return {"exists": False}
    return {
        "exists": True,
        "members": list(group.members),
        "includes": [f"group:{g}" for g in group.includes],
    }
