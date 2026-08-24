"""`Access` - co drzi v ruce aplikace.

Cte a overuje. NIC, co meni stav: kdyby zavadeni viselo na tomtez objektu,
umi kazda apka se svym klicem zalozit uzivatele a strcit ho do
`group:spravci`. Unik klice jedne apky by byl klic ke vsemu.

Uloziste tu neni videt zamerne. Kdyby si apka mohla vybrat "soubory misto
sluzby", obejde tim origin ACL, omezovani pokusu i auditni stopu - a udela
to, protoze je to jednodussi.
"""
from __future__ import annotations

from .files import FileStore
from .principals import Group, User, check_realm
from .realms import realm_root
from .verdicts import Verdict


class Access:
    """Identita a politika. Postav jednou pri startu a dal jen predavej."""

    __slots__ = ("_store",)

    def __init__(self, store) -> None:
        self._store = store

    @classmethod
    def local(cls, home, *, realm: str) -> Access:
        """V jednom procesu, primo ze souboru realmu.

        Realm je povinny - zadny vychozi neexistuje. Obchazi sit, a tim
        i vsechno, co se na siti kontroluje.
        """
        return cls(FileStore(realm_root(home, realm), realm=check_realm(realm)))

    # -- identita ----------------------------------------------------------

    def authenticate(self, username: str, credentials, *, purpose: str) -> Verdict:
        return self._store.authenticate(username, credentials, purpose=purpose)

    def user(self, name: str) -> User | None:
        return self._store.user(name)

    def users(self) -> list[str]:
        return self._store.users()

    def groups(self) -> list[str]:
        return self._store.groups()

    def group(self, name: str) -> Group | None:
        return self._store.group(name)

    def generation(self) -> int:
        """Cislo generace: nezmenene znamena, ze drzena odpoved plati dal."""
        return self._store.generation()

    def unknown_principals(self, names) -> list[str]:
        """Ktere z principalu neexistuji - hromadne, kvuli startu instance."""
        return self._store.unknown_principals(names)

    def ready(self) -> str | None:
        """`None` znamena pripraveno; jinak duvod."""
        return self._store.ready()
