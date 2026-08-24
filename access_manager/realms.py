"""Realm = subadresar. Uvnitr ma presne dosavadni layout ulozisti.

Zadny vychozi realm neexistuje: kdo se pta, pta se vzdy v ramci jednoho
realmu, a pres hranici realmu nevede nic. Nazev prochazi stejnou kontrolou
jako jmena (FQDN projde) a normalizuje se na mala pismena.
"""
from __future__ import annotations

from pathlib import Path

from .files import FileStore
from .principals import Enrolment, check_identity, check_realm

#: Prefix adresare realmu. `realm-example.com/` je koren, na ktery se stavi
#: FileStore - ten o realmech nic nevi a vedet nema.
REALM_PREFIX = "realm-"


def realm_root(home, realm: str) -> Path:
    """Koren realmu pod domovskym adresarem instance."""
    return Path(home).expanduser() / f"{REALM_PREFIX}{check_realm(realm)}"


def reconcile(home, declarations) -> list[Enrolment]:
    """Dorovnej stav podle deklaraci. Doplnuje se JEN co chybi.

    Existujiciho se nedotyka: restart ve 3 rano nikomu nic nevymeni.
    Expirovane nesparovane zavedeni spravce dostane novy QR - vymena
    tajemstvi, ktere nikdo nikdy nepouzil, nikoho nezamyka. Zmizeni
    realmu z deklarace NENI mazani; sjednocenim nejde nic odebrat.
    """
    videne: set[str] = set()
    nova: list[Enrolment] = []
    for deklarace in declarations:
        nazev = check_realm(deklarace["name"])
        if nazev in videne:
            msg = f"realm {nazev!r} je deklarovany dvakrat; konflikt zavira start"
            raise ValueError(msg)
        videne.add(nazev)
        store = FileStore(
            realm_root(home, nazev),
            realm=nazev,
            qr_ttl_days=int(deklarace.get("qr_ttl_days", 14)),
            audit_retention_days=int(deklarace.get("audit_retention_days", 90)),
        )
        for jmeno in deklarace.get("admins", ()):
            jmeno = check_identity(jmeno)
            adresar = store.home / f"admin-{jmeno}"
            if not adresar.is_dir():
                nova.append(store.add_admin(jmeno))
            elif not (adresar / "totp.secret").is_file():
                nova.append(store.pair_admin(jmeno))
            elif store._enrolment_expired(adresar):
                # Guard posledniho spravce tu neplati: tajemstvi nikdo
                # nikdy nepouzil a bez vymeny by se realm zasekl.
                store._replace_expired_admin_enrolment(jmeno)
                nova.append(store.pair_admin(jmeno))
    return nova
