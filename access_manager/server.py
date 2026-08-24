"""WSGI aplikace sluzby: bezpecnostni pater a provozni endpointy.

Poradi zpracovani pozadavku je NEPORUSITELNE (spec §3):

    puvod (peer/XFF) -> Bearer klic -> komponenta (401 bez rozdilu)
    -> origin ACL (403 a NIC dal - zadne cteni, zadny throttle)
    -> g.realm/g.store/g.component pro dal

`flask` a `waitress` se importuji az uvnitr `create_app`/`_require_server` -
modul samotny musi jit naimportovat bez extras (`pip install
'access-manager[server]'`).
"""
from __future__ import annotations

import argparse
import importlib.metadata
import sys
import threading
from ipaddress import ip_address, ip_network
from pathlib import Path

from .config import ServiceConfig, load_config
from .files import FileStore
from .konzole.app import create_console_app
from .principals import Component, check_realm
from .realms import realm_root, reconcile
from .wire import group_to_wire, user_to_wire, verdict_to_wire

#: Provozni cesty projdou bez klice - jinak by si /healthz nemohl overit
#: zivotnost sam orchestrator bez tajemstvi.
_OPERATIONAL_PATHS = frozenset({"/healthz", "/readyz", "/v1/version"})


def _require_server():
    """Vrat (flask, waitress), nebo rekni JAK to doinstalovat."""
    try:
        import flask
        import waitress
    except ImportError as chybi:
        raise RuntimeError(
            "sluzba potrebuje flask a waitress: pip install 'access-manager[server]'"
        ) from chybi
    return flask, waitress


def _is_trusted_proxy(peer: str, trusted_proxies) -> bool:
    """Je `peer` mezi duveryhodnymi proxy? Prijima adresu i CIDR."""
    try:
        adresa = ip_address(peer)
    except ValueError:
        return False
    for polozka in trusted_proxies:
        try:
            sit = ip_network(polozka, strict=False)
        except ValueError:
            continue
        if adresa in sit:
            return True
    return False


def _resolve_origin(environ: dict, cfg: ServiceConfig) -> str:
    """Puvod pozadavku: peer socketu, nebo hlavicka od duveryhodne proxy.

    Cizi peer se nikdy neveri - hlavicka se cte JEN, kdyz je peer sam
    v `trusted_proxies`. Bere se `hops`-ty prvek ZPRAVA; chybejici nebo
    zdeformovana hlavicka spadne zpatky na peer.
    """
    peer = environ.get("REMOTE_ADDR", "")
    if not _is_trusted_proxy(peer, cfg.trusted_proxies):
        return peer
    header_klic = "HTTP_" + cfg.forwarded_header.upper().replace("-", "_")
    surovy = environ.get(header_klic)
    if not surovy:
        return peer
    prvky = [p.strip() for p in surovy.split(",") if p.strip()]
    if not (1 <= cfg.hops <= len(prvky)):
        return peer
    return prvky[-cfg.hops]


def _origin_allowed(component: Component, origin: str) -> bool:
    """Smi komponenta z tohoto puvodu? Prazdne origins = jen smycka."""
    try:
        adresa = ip_address(origin)
    except ValueError:
        return False
    if not component.origins:
        return adresa.is_loopback
    for polozka in component.origins:
        try:
            sit = ip_network(polozka, strict=False)
        except ValueError:
            continue
        if adresa in sit:
            return True
    return False


def _bearer_key(hlavicka: str) -> str | None:
    """Klic z `Authorization: Bearer <klic>`, nebo `None`."""
    prefix = "Bearer "
    if not hlavicka.startswith(prefix):
        return None
    klic = hlavicka[len(prefix):].strip()
    return klic or None


def _component_for_key(stores: dict, key: str, cache: dict):
    """Komponenta a jeji realm podle klice - linearni prohledani vsech
    realmu, s cache platnou jen dokud se generace realmu neposune.

    Vraci `(realm, komponenta)`, nebo `(None, None)` kdyz klic nikam nepatri.
    """
    zasah = cache.get(key)
    if zasah is not None:
        realm, komponenta, gen = zasah
        if stores[realm].generation() == gen:
            return realm, komponenta
    for realm, store in stores.items():
        komponenta = store.component_for_key(key)
        if komponenta is not None:
            cache[key] = (realm, komponenta, store.generation())
            return realm, komponenta
    return None, None


def create_app(cfg: ServiceConfig):
    """Postav Flask aplikaci nad realmy z `cfg` - uloziste, pipeline,
    provozni endpointy. Ukoly 5, 6 a 9 na tuhle aplikaci stavi dal."""
    flask, _waitress = _require_server()

    stores: dict[str, FileStore] = {}
    videne: set[str] = set()
    for deklarace in cfg.realms:
        if "name" not in deklarace:
            # Stejna chyba a stejne zneni jako v realms.reconcile - deklarace
            # je zmatena a start se ma zastavit driv, nez neco napulku zalozi.
            raise ValueError(f"deklarace realmu bez jmena: {deklarace!r}")
        # Normalizace na mala pismena - stejne jako v realms.reconcile, jinak
        # by "Example.com" a "example.com" zalozily dve uloziste pro jeden realm.
        jmeno = check_realm(deklarace["name"])
        if jmeno in videne:
            msg = f"realm {jmeno!r} je deklarovany dvakrat; konflikt zavira start"
            raise ValueError(msg)
        videne.add(jmeno)
        stores[jmeno] = FileStore(
            realm_root(cfg.data, jmeno),
            realm=jmeno,
            qr_ttl_days=int(
                deklarace.get("qr_ttl_days", cfg.defaults["qr_ttl_days"])
            ),
            audit_retention_days=int(
                deklarace.get(
                    "audit_retention_days", cfg.defaults["audit_retention_days"]
                )
            ),
            throttle_attempts=int(cfg.throttle["attempts"]),
            throttle_window_s=int(cfg.throttle["window_s"]),
        )

    # Cache klic -> (realm, komponenta, gen); zije po dobu aplikace, ne
    # jednoho pozadavku - proto je to uzaver, ne g.
    cache: dict[str, tuple[str, Component, int]] = {}

    app = flask.Flask(__name__)

    @app.before_request
    def _security_pipeline():
        if flask.request.path in _OPERATIONAL_PATHS:
            return None

        origin = _resolve_origin(flask.request.environ, cfg)
        key = _bearer_key(flask.request.headers.get("Authorization", ""))
        realm = component = None
        if key is not None:
            realm, component = _component_for_key(stores, key, cache)
        if component is None:
            # Nezname i spatne jsou 401 UPLNE stejny - jinak by odpoved
            # prozradila, ktere klice existuji.
            # Klic ani hlavicka Authorization sem NIKDY nepatri - jen puvod
            # a cesta, at je 401 vubec videt v provoznim logu (spec §3).
            print(
                f"401 unauthorized: puvod={origin} cesta={flask.request.path}",
                file=sys.stderr,
            )
            return flask.jsonify({"error": "unauthorized"}), 401

        if not _origin_allowed(component, origin):
            # 403 a NIC dal: zadny throttle, zadne parsovani tela.
            stores[realm].audit_event(
                kind="origin_denied", component=component.name,
                key_id=component.key_id, origin=origin,
            )
            return flask.jsonify({"error": "forbidden"}), 403

        flask.g.realm = realm
        flask.g.store = stores[realm]
        flask.g.component = component
        return None

    @app.get("/healthz")
    def _healthz():
        return flask.jsonify({"status": "ok"})

    @app.get("/readyz")
    def _readyz():
        reasons = {}
        for jmeno, store in stores.items():
            duvod = store.ready()
            if duvod is not None:
                reasons[jmeno] = duvod
        if reasons:
            return flask.jsonify({"status": "unready", "reasons": reasons}), 503
        return flask.jsonify({"status": "ok"})

    @app.get("/v1/version")
    def _version():
        return flask.jsonify({
            "api": "1",
            "build": importlib.metadata.version("access-manager"),
        })

    def _bad_request():
        # Chyba volajiciho (zdeformovane jmeno, chybejici pole) - ne verdikt.
        return flask.jsonify({"error": "bad_request"}), 400

    @app.get("/v1/users/<path:name>")
    def _user(name):
        try:
            telo = user_to_wire(flask.g.store.user(name))
        except ValueError:
            return _bad_request()
        return flask.jsonify(telo)

    @app.get("/v1/users")
    def _users():
        return flask.jsonify({"users": flask.g.store.users()})

    @app.get("/v1/groups")
    def _groups():
        return flask.jsonify({"groups": flask.g.store.groups()})

    @app.get("/v1/groups/<path:name>")
    def _group(name):
        try:
            telo = group_to_wire(name, flask.g.store.group(name))
        except ValueError:
            return _bad_request()
        return flask.jsonify(telo)

    @app.post("/v1/principals/check")
    def _principals_check():
        telo = flask.request.get_json(silent=True)
        if not isinstance(telo, dict) or not isinstance(
            telo.get("principals"), list
        ):
            return _bad_request()
        return flask.jsonify(
            {"unknown": flask.g.store.unknown_principals(telo["principals"])}
        )

    @app.post("/v1/authenticate")
    def _authenticate():
        # Vzdy 200: ctyri tvary verdiktu jsou VYSLEDEK, ne chyba. 400 patri
        # jen volajicimu - spatny JSON, chybejici pole nebo neplatny tvar
        # jmena/ucelu (ValueError z check_identity/check_purpose).
        telo = flask.request.get_json(silent=True)
        if not isinstance(telo, dict):
            return _bad_request()
        username, credentials, purpose = (
            telo.get("username"), telo.get("credentials"), telo.get("purpose"),
        )
        if username is None or credentials is None or purpose is None:
            return _bad_request()
        # JSON dovoli i skalar (cislo, bool, seznam) tam, kde uloziste ceka
        # mapu - bez tehle kontroly by `dict(credentials or {})` uvnitr
        # store spadlo na TypeError misto slusneho 400.
        if not isinstance(credentials, dict):
            return _bad_request()
        try:
            verdikt = flask.g.store.authenticate(
                username, credentials, purpose=purpose,
                component=flask.g.component.name,
            )
        except ValueError:
            return _bad_request()
        return flask.jsonify(
            verdict_to_wire(verdikt, detail=flask.g.component.detail)
        )

    @app.get("/v1/whoami")
    def _whoami():
        return flask.jsonify({
            "component": flask.g.component.name,
            "realm": flask.g.realm,
            "key_id": flask.g.component.key_id,
        })

    @app.get("/v1/generation")
    def _generation():
        return flask.jsonify({"gen": flask.g.store.generation()})

    return app


def main(argv=None):
    """Hlavni vstupni bod sluzby.

    Parsuje argumenty, nacte konfiguraci, spusti reconcile, zalozi Flask
    aplikaci, spusti konzoli v demonskem vlakne a API primo v hlavnim
    vlakne.
    """
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog="python -m access_manager.server",
        description="Spustit sluzbu s danou konfiguraci"
    )
    parser.add_argument("-c", "--config", required=True, help="Adresar s konfiguraci")

    args = parser.parse_args(argv)

    # Nacti konfiguraci
    cfg = load_config(Path(args.config))

    # Instancni defaults se slouci do kazde deklarace, ktera si vlastni
    # hodnotu nerekla sama - deklarace smi prebit instancni defaults,
    # ne naopak.
    deklarace = [
        {**cfg.defaults, **d} for d in cfg.realms
    ]

    # Spusti reconcile a vypise nove zavedeni
    nova = reconcile(cfg.data, deklarace)
    for z in nova:
        print(f"nove zavedeni: {z.directory / 'totp.txt'}")

    # Zaloz aplikace - API i konzole se stavi tady, v hlavnim vlakne;
    # konzole pak jen svou serve() spousti v demonskem vlakne nize.
    app = create_app(cfg)
    console = create_console_app(cfg)

    # Ziskej waitress (lazy import)
    flask, waitress = _require_server()

    # Parsuj listener stringy - "host:port" format
    # Pouzij rsplit(":") jednou - v6 nema podporu
    api_listener = cfg.listeners.get("api", "127.0.0.1:22000")
    console_listener = cfg.listeners.get("console", "127.0.0.1:22001")

    api_host, api_port_str = api_listener.rsplit(":", 1)
    console_host, console_port_str = console_listener.rsplit(":", 1)

    api_port = int(api_port_str)
    console_port = int(console_port_str)

    # Funkce pro spusteni konzole serveru
    def serve_console():
        waitress.serve(console, host=console_host, port=console_port)

    # Konzole je demon - kdyz spadne API (hlavni vlakno), proces skonci
    # cely, nezustane napulku bezici proces bez API. Ctrl+C/SIGTERM ukonci
    # waitress.serve v hlavnim vlakne prirozene, bez zadneho .join().
    konzole_vlakno = threading.Thread(target=serve_console, daemon=True)
    konzole_vlakno.start()

    # API bezi primo v hlavnim vlakne - zadne druhe vlakno, zadny join.
    waitress.serve(app, host=api_host, port=api_port)


if __name__ == "__main__":
    main()
