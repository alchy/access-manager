"""Realm = subadresar. Uvnitr ma presne dosavadni layout ulozisti.

Zadny vychozi realm neexistuje: kdo se pta, pta se vzdy v ramci jednoho
realmu, a pres hranici realmu nevede nic. Nazev prochazi stejnou kontrolou
jako jmena (FQDN projde) a normalizuje se na mala pismena.
"""
from __future__ import annotations

from pathlib import Path

from .principals import check_realm

#: Prefix adresare realmu. `realm-example.com/` je koren, na ktery se stavi
#: FileStore - ten o realmech nic nevi a vedet nema.
REALM_PREFIX = "realm-"


def realm_root(home, realm: str) -> Path:
    """Koren realmu pod domovskym adresarem instance."""
    return Path(home).expanduser() / f"{REALM_PREFIX}{check_realm(realm)}"
