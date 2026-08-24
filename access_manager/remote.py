"""Klient sluzby pres HTTP: `RemoteStore`.

TLS je povinne a bez vypinace - vyjimka je jen loopback (127.0.0.1/::1/
localhost), kam certifikat davat nema smysl. Vlastni CA jde predat jen
pres `ca=`; overeni certifikatu se neda nikde vypnout.

`httpx` se importuje az uvnitr `_require_remote()` - modul samotny musi
jit naimportovat bez extras (`pip install 'access-manager[remote]'`).
"""
from __future__ import annotations

import time
from urllib.parse import quote, urlparse

from .principals import Group, User
from .verdicts import Verdict

#: Kam smi jit http:// bez TLS - jen misto, kam nikdo cizi nedosahne.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

#: Jak dlouho plati zapamatovany `user()`, kdyz se generace realmu nehnula.
_USER_CACHE_TTL_S = 5.0


def _require_remote():
    """Vrat httpx, nebo rekni JAK ho doinstalovat."""
    try:
        import httpx
    except ImportError as chybi:
        raise RuntimeError(
            "vzdaleny pristup potrebuje httpx: pip install 'access-manager[remote]'"
        ) from chybi
    return httpx


def _check_scheme(url: str) -> None:
    """https je povinne; http projde jen na loopback (vyvoj bez certifikatu)."""
    rozebrane = urlparse(url)
    if rozebrane.scheme == "https":
        return
    if rozebrane.scheme == "http" and rozebrane.hostname in _LOOPBACK_HOSTS:
        return
    raise ValueError(
        f"{url!r}: https je povinne (vyjimka jen pro 127.0.0.1/::1/localhost) "
        "- overeni certifikatu nema vypinac"
    )


class RemoteStore:
    """Klient sluzby - stejna role jako `FileStore`, jina strana site.

    TLS, spojeni s klicem, overeni verze a totoznosti sluzby pri startu,
    retry pro `_request` a datove metody (users/groups/authenticate) nad
    tymz dratem jako `wire.py` na serverove strane. `authenticate` se
    NIKDY necachuje; `user()` ma kratkou cache platnou, dokud se nezmeni
    znama generace realmu (viz `_observe_gen`).
    """

    def __init__(
        self,
        url: str,
        key: str,
        *,
        realm: str | None = None,
        ca=None,
        timeout: float = 5.0,
        deadline: float = 30.0,
        transport=None,
    ) -> None:
        _check_scheme(url)
        httpx = _require_remote()
        self._httpx = httpx
        self._deadline = deadline

        # Cache `user()`: jmeno -> (User|None, znama generace pri ulozeni,
        # monotonicky cas ulozeni). `_known_gen` je nejvyssi generace, kterou
        # kdy nesla nejaka odpoved (authenticate/generation) - viz _observe_gen.
        self._known_gen: int | None = None
        self._user_cache: dict[str, tuple] = {}

        client_kwargs = {}
        if ca is not None:
            if isinstance(ca, bool):
                # ca je cesta k CA bundle; bool by byl vypinac overeni -
                # a ten neexistuje.
                raise TypeError("ca musi byt cesta k CA bundle, ne bool")
            client_kwargs["verify"] = ca
        if transport is not None:
            client_kwargs["transport"] = transport
        self._client = httpx.Client(
            base_url=url,
            headers={"Authorization": f"Bearer {key}"},
            timeout=timeout,
            **client_kwargs,
        )

        verze = self._request("GET", "/v1/version").json()
        major = str(verze.get("api", "")).split(".")[0]
        if major != "1":
            raise RuntimeError(
                f"nepodporovana verze API sluzby: {verze.get('api')!r}"
            )

        kdo = self._request("GET", "/v1/whoami").json()
        self.component = kdo["component"]
        self.realm_name = kdo["realm"]
        self.key_id = kdo["key_id"]
        if realm is not None and realm != self.realm_name:
            # Hlucne, schvalne: potichu pripojit se ke spatnemu realmu je
            # horsi nez spadnout hned na startu.
            raise RuntimeError(
                f"realm nesouhlasi: ocekavano {realm!r}, sluzba hlasi "
                f"{self.realm_name!r}"
            )

    def _request(self, method: str, path: str, *, json=None):
        """GET/POST s retry na sitove chyby a 5xx, do `deadline` sekund celkem.

        401/403 se neopakuji - to neni vypadek site, ale odmitnuti, a klic
        se do zpravy vyjimky nikdy nedostane.
        """
        limit = time.monotonic() + self._deadline
        attempt = 0
        while True:
            try:
                odpoved = self._client.request(method, path, json=json)
            except self._httpx.TransportError as chyba:
                duvod = chyba
            else:
                if odpoved.status_code in (401, 403):
                    raise RuntimeError(f"pristup odmitnut ({odpoved.status_code})")
                if odpoved.status_code < 500:
                    return odpoved
                duvod = f"server vratil {odpoved.status_code}"

            cekani = 0.2 * (2**attempt)
            attempt += 1
            if time.monotonic() + cekani >= limit:
                raise RuntimeError(f"pozadavek selhal: {duvod}") from (
                    duvod if isinstance(duvod, BaseException) else None
                )
            time.sleep(cekani)

    # == cache podle generace ==============================================

    def _observe_gen(self, gen: int | None) -> None:
        """Zaznamenej generaci z odpovedi, ktera ji nese (authenticate,
        generation). Kdyz je vyssi nez znama, cely `user()` cache zahodime -
        je to jednodussi a bezpecnejsi nez cistit po jednotlivych jmenech."""
        if gen is None:
            return
        if self._known_gen is None or gen > self._known_gen:
            self._known_gen = gen
            self._user_cache.clear()

    # == identita ===========================================================

    def authenticate(
        self,
        username: str,
        credentials,
        *,
        purpose: str,
        component: str | None = None,
    ) -> Verdict:
        """Odpoved na "jsi to ty?" - vzdy z dratu, NIKDY z cache.

        `component` se ignoruje: na strane sluzby ho urcuje klic samotny
        (kazda komponenta ma svuj), parametr tu zustava jen kvuli stejnemu
        podpisu jako `Access.authenticate`/`FileStore.authenticate`.
        400 od sluzby je chyba VOLAJICIHO (spatny tvar ucelu/pole), ne
        verdikt - takova odpoved se hlasi jako `RuntimeError`.
        """
        odpoved = self._request(
            "POST", "/v1/authenticate",
            json={
                "username": username, "credentials": credentials, "purpose": purpose,
            },
        )
        if odpoved.status_code == 400:
            raise RuntimeError(
                "authenticate: sluzba odmitla pozadavek jako spatny "
                "(chyba volajiciho - spatny tvar ucelu nebo chybejici pole)"
            )
        data = odpoved.json()
        gen = data.get("gen")
        self._observe_gen(gen)
        return Verdict(
            outcome=data["outcome"],
            reason=data.get("reason"),
            subject_id=data.get("subject_id"),
            principals=frozenset(data.get("principals", ())),
            required=tuple(data.get("required", ())),
            gen=gen,
            retry_after=data.get("retry_after"),
        )

    def user(self, name: str) -> User | None:
        """Clovek s plochym uzaverem principalu. Kratce cachovano - viz
        `_USER_CACHE_TTL_S` a `_observe_gen`."""
        zaznam = self._user_cache.get(name)
        if zaznam is not None:
            hodnota, gen, ulozeno = zaznam
            stari = time.monotonic() - ulozeno
            if gen == self._known_gen and stari < _USER_CACHE_TTL_S:
                return hodnota

        odpoved = self._request("GET", f"/v1/users/{quote(name, safe='')}")
        if odpoved.status_code == 400:
            raise ValueError(f"neplatne jmeno {name!r}")
        data = odpoved.json()
        if not data.get("exists"):
            hodnota = None
        else:
            hodnota = User(
                name=name,
                subject_id=data["subject_id"],
                enabled=data["enabled"],
                principals=frozenset(data.get("principals", ())),
            )
        self._user_cache[name] = (hodnota, self._known_gen, time.monotonic())
        return hodnota

    def users(self) -> list[str]:
        return self._request("GET", "/v1/users").json()["users"]

    def groups(self) -> list[str]:
        return self._request("GET", "/v1/groups").json()["groups"]

    def group(self, name: str) -> Group | None:
        """Skupina TAK, JAK JE NAPSANA - `includes` bez prefixu `group:`,
        zrcadleni `group_to_wire`, ktery ho na drat prida."""
        odpoved = self._request("GET", f"/v1/groups/{quote(name, safe='')}")
        if odpoved.status_code == 400:
            raise ValueError(f"neplatne jmeno skupiny {name!r}")
        data = odpoved.json()
        if not data.get("exists"):
            return None
        return Group(
            name=name,
            members=tuple(data.get("members", ())),
            includes=tuple(
                zaznam[len("group:"):] if zaznam.startswith("group:") else zaznam
                for zaznam in data.get("includes", ())
            ),
        )

    def unknown_principals(self, names) -> list[str]:
        """Ktere z principalu NEEXISTUJI - hromadne, kvuli startu instance."""
        odpoved = self._request(
            "POST", "/v1/principals/check", json={"principals": list(names)},
        )
        return odpoved.json()["unknown"]

    def generation(self) -> int:
        """Cislo generace realmu - i tahle odpoved cisti `user()` cache,
        kdyz je vyssi nez znama (viz `_observe_gen`)."""
        gen = self._request("GET", "/v1/generation").json()["gen"]
        self._observe_gen(gen)
        return gen

    def ready(self) -> str | None:
        """`None` znamena pripraveno; jinak strucny popis proc ne.

        Nejde pres `_request`: 503 je tu OCEKAVANY tvar odpovedi (sluzba
        rika "jeste ne"), ne vypadek site k opakovani. Hlavicka s klicem se
        posila i tady - `/readyz` ji nevyzaduje, ale poslat ji nevadi.
        """
        odpoved = self._client.get("/readyz")
        if odpoved.status_code == 200:
            return None
        telo = odpoved.json()
        reasons = telo.get("reasons") or {}
        if reasons:
            return "; ".join(
                f"{jmeno}: {duvod}" for jmeno, duvod in sorted(reasons.items())
            )
        return str(telo.get("status", odpoved.status_code))
