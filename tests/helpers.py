"""Spolecne ruce testu. Nejsou to testy - jen zakladani stavu.

Konstanty PUBLIC/USERS jsou tu ZNOVU, ne importem z balicku: balicek je
schvalne neexportuje a testy maji drzet jmena PROTOKOLU nezavisle na kodu.
"""
import json

PUBLIC = "group:public"
USERS = "group:users"
TAJEMSTVI = "JBSWY3DPEHPK3PXP"
REALM = "example.com"


def koren(home):
    """Koren realmu pod testovacim domovem - stejny vzorec jako `realm_root`."""
    return home / f"realm-{REALM}"


def zaloz(home, name, secret=TAJEMSTVI):
    directory = koren(home) / f"user-{name}"
    directory.mkdir(parents=True)
    (directory / "totp.secret").write_text(secret + "\n", encoding="utf-8")
    return directory


def skupiny(home, table):
    koren(home).mkdir(parents=True, exist_ok=True)
    (koren(home) / "groups.json").write_text(json.dumps(table), encoding="utf-8")


def kod(secret=TAJEMSTVI, at=None):
    import pyotp

    totp = pyotp.TOTP(secret)
    return totp.now() if at is None else totp.at(at)


def principaly(home, name):
    from access_manager import Access

    return Access.local(home, realm=REALM).user(name).principals
