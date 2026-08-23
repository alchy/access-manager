"""`Admin` - co drzi v ruce spravcovsky nastroj.

Zavadeni a clenstvi. `authenticate` tu zamerne NENI: kdyby byl, je pokuseni
pouzit spravcovsky klic v aplikaci - a ten smi vsechno.

Rozdeleni na dva objekty je tvar, ne ochrana. Skutecne vynuceni je na sluzbe,
ktera se diva na rozsah klice; tohle jen brani tomu, aby to nekdo zavolal
omylem.
"""
from __future__ import annotations

from .files import FileStore
from .principals import Enrolment


class Admin:
    """Sprava identit a skupin."""

    __slots__ = ("_store",)

    def __init__(self, store) -> None:
        self._store = store

    @classmethod
    def local(cls, home) -> Admin:
        return cls(FileStore(home))

    # -- lide --------------------------------------------------------------

    def add_user(self, name: str) -> Enrolment:
        """Zalozi cloveka i s parovacim kodem. Vraci UKAZATEL, ne tajemstvi."""
        return self._store.add_user(name)

    def pair_missing(self) -> list[Enrolment]:
        """Doplni parovaci kod tem, kdo zadny nemaji. Ostatnich se nedotkne."""
        return self._store.pair_missing()

    def revoke_credential(self, name: str, mechanism: str = "totp") -> None:
        """Ztraceny telefon: odvolat, pak `pair` pro novy."""
        self._store.revoke_credential(name, mechanism)

    def pair(self, name: str) -> Enrolment:
        """Nove parovani jednoho cloveka. Existujici tajemstvi neprepise."""
        return self._store.pair(name)

    def disable_user(self, name: str) -> None:
        """Docasne vypnuti - clenstvi i auditni stopa zustavaji."""
        self._store.disable_user(name)

    def enable_user(self, name: str) -> None:
        self._store.enable_user(name)

    def remove_user(self, name: str) -> None:
        """Smazani vcetne clenstvi. Na tri dny se clovek vypina, ne maze."""
        self._store.remove_user(name)

    # -- skupiny -----------------------------------------------------------

    def add_group(self, name: str) -> None:
        self._store.add_group(name)

    def add_member(self, group: str, name: str) -> None:
        self._store.add_member(group, name)

    def include(self, parent: str, child: str) -> None:
        """`parent` obsahuje `child`: kdo je v child, je i v parent."""
        self._store.include(parent, child)

    def remove_member(self, group: str, name: str) -> None:
        self._store.remove_member(group, name)
