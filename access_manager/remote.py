"""Klient sluzby pres HTTP: `RemoteStore`.

TLS je povinne a bez vypinace - vyjimka je jen loopback (127.0.0.1/::1/
localhost), kam certifikat davat nema smysl. Vlastni CA jde predat jen
pres `ca=`; overeni certifikatu se neda nikde vypnout.

`httpx` se importuje az uvnitr `_require_remote()` - modul samotny musi
jit naimportovat bez extras (`pip install 'access-manager[remote]'`).
"""
from __future__ import annotations

import time
from urllib.parse import urlparse

#: Kam smi jit http:// bez TLS - jen misto, kam nikdo cizi nedosahne.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


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

    Ukol 8 doplni datove metody (users/groups/authenticate). Tady je jadro:
    TLS, spojeni s klicem, overeni verze a totoznosti sluzby pri startu,
    a retry pro `_request`.
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

        client_kwargs = {}
        if ca is not None:
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
