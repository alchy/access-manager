"""Konzole: Flask app factory, sdileny layout, prihlaseni, strazce relace.

Kazdy pozadavek dostane vlastni `FileStore` (g.store) s `actor` odvozenym od
prihlaseneho spravce - zadna instance uloziste se nesdili mezi pozadavky,
takze auditni stopa vzdy nese, kdo skutecne zapsal.

`flask` se importuje az uvnitr `create_console_app` - modul samotny musi jit
naimportovat bez extras (`pip install 'access-manager[server]'`), stejne jako
`server.py`.
"""
from __future__ import annotations

import functools
import secrets
from pathlib import Path

from ..config import ServiceConfig
from ..files import FileStore
from ..principals import check_realm
from ..realms import realm_root
from . import preklady

#: Sablony jsou soucasti balicku - Flask by je jinak hledal relativne k cwd,
#: ktery se pri spusteni sluzby muze lisit od umisteni modulu.
_TEMPLATES = Path(__file__).parent / "templates"


def _require_flask():
    """Vrat `flask`, nebo rekni JAK to doinstalovat."""
    try:
        import flask
    except ImportError as chybi:
        raise RuntimeError(
            "konzole potrebuje flask: pip install 'access-manager[server]'"
        ) from chybi
    return flask


def _realm_store_kwargs(cfg: ServiceConfig) -> dict[str, dict]:
    """Konstrukcni argumenty `FileStore` pro kazdy realm z `cfg`.

    Zrcadli konstrukci v `server.create_app` - misto hotovych instanci se ale
    drzi jen argumenty, protoze kazdy pozadavek potrebuje `FileStore` s
    vlastnim `actor` (viz `prihlasen`).
    """
    kwargs: dict[str, dict] = {}
    videne: set[str] = set()
    for deklarace in cfg.realms:
        if "name" not in deklarace:
            raise ValueError(f"deklarace realmu bez jmena: {deklarace!r}")
        jmeno = check_realm(deklarace["name"])
        if jmeno in videne:
            msg = f"realm {jmeno!r} je deklarovany dvakrat; konflikt zavira start"
            raise ValueError(msg)
        videne.add(jmeno)
        kwargs[jmeno] = {
            "root": realm_root(cfg.data, jmeno),
            "realm": jmeno,
            "qr_ttl_days": int(
                deklarace.get("qr_ttl_days", cfg.defaults["qr_ttl_days"])
            ),
            "audit_retention_days": int(
                deklarace.get(
                    "audit_retention_days", cfg.defaults["audit_retention_days"]
                )
            ),
            "throttle_attempts": int(cfg.throttle["attempts"]),
            "throttle_window_s": int(cfg.throttle["window_s"]),
        }
    return kwargs


def create_console_app(cfg: ServiceConfig):
    """Postav Flask aplikaci konzole nad realmy z `cfg`.

    Dalsi ukoly (prihlaseni, sprava lidi/skupin/aplikaci/spravcu, audit) na
    tuhle tovarnu stavi dal - pridavaji route a pouzivaji `prihlasen`.
    """
    flask = _require_flask()

    realmy = _realm_store_kwargs(cfg)

    def _store_pro(jmeno_realmu: str, actor: str) -> FileStore:
        parametry = dict(realmy[jmeno_realmu])
        root = parametry.pop("root")
        return FileStore(root, actor=actor, **parametry)

    app = flask.Flask(__name__, template_folder=str(_TEMPLATES))
    # Restart = odhlaseni vsech spravcu - zamer, ne nedopatreni. Zadne
    # tajemstvi se nikam neuklada, klic zije jen po dobu behu procesu.
    app.secret_key = secrets.token_hex(32)
    # HttpOnly je flaskovy vychozi stav - jen SameSite je potreba rict sami.
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    def _prelozit(klic: str) -> str:
        katalog = preklady.nacti(flask.session.get("lang", "cs"))
        return preklady.prelozit(katalog, klic)

    def over_csrf() -> None:
        """Kazda mutace nese `csrf` shodny se session, jinak 400 a zadny zapis.

        POST /login je vyjimka: session (a tedy token) jeste neexistuje, takze
        se overuje az od prvni mutace PO prihlaseni (napr. /logout). Porovnani
        je casove konstantni (`secrets.compare_digest`) - drive nez se na nej
        dostane, jsou oba chybejici stavy (nic poslano/nic v session) osetreny
        rovnou abortem, aby compare_digest vzdycky dostal dva stringy.
        """
        posilany = flask.request.form.get("csrf")
        ulozeny = flask.session.get("csrf")
        if not posilany or not ulozeny or not secrets.compare_digest(posilany, ulozeny):
            flask.abort(400)

    @app.before_request
    def _uloz_jazyk():
        # Prepinac funguje na kterekoli strance, ne jen na /login - staci
        # pridat ?lang=cs|en do libovolneho GETu.
        lang = flask.request.args.get("lang")
        if lang in ("cs", "en"):
            flask.session["lang"] = lang

    @app.context_processor
    def _kontext_prekladu():
        return {"t": _prelozit}

    def prihlasen(view):
        """Strazce relace: bez platne session presmeruje na `/login`.

        Zaroven priprav g.store s actor odvozenym od prihlaseneho spravce -
        pouziva se jen uvnitr chranenych view, ne v `/login` samotnem.
        """

        @functools.wraps(view)
        def obal(*args, **kwargs):
            jmeno_realmu = flask.session.get("realm")
            admin = flask.session.get("admin")
            if not admin or jmeno_realmu not in realmy:
                return flask.redirect(flask.url_for("_prihlasovaci_stranka"))
            flask.g.store = _store_pro(jmeno_realmu, actor=f"admin:{admin}")
            return view(*args, **kwargs)

        return obal

    @app.get("/login")
    def _prihlasovaci_stranka():
        return flask.render_template("login.html")

    @app.post("/login")
    def _prihlasit():
        # POST /login je pred existenci session - neni co porovnat s CSRF
        # tokenem, takze se tady over_csrf() zamerne nevola (viz jeho
        # docstring). Neznamy realm i spatne kody hlasi TOTOZNOU hlasku -
        # zadny postranni kanal, ktery by prozradil, ze realm neexistuje.
        jmeno_realmu = flask.request.form.get("realm", "")
        jmeno = flask.request.form.get("jmeno", "")
        kod1 = flask.request.form.get("kod1", "")
        kod2 = flask.request.form.get("kod2", "")

        if jmeno_realmu not in realmy:
            return flask.render_template("login.html", chyba=_prelozit("login.failed"))

        store = _store_pro(jmeno_realmu, actor=f"admin:{jmeno}")
        verdikt = store.authenticate_admin(jmeno, kod1, kod2)

        if verdikt.outcome == "throttled":
            chyba = _prelozit("login.throttled").format(s=verdikt.retry_after)
            return flask.render_template("login.html", chyba=chyba)
        if not verdikt:
            return flask.render_template("login.html", chyba=_prelozit("login.failed"))

        # Cista relace: zadny stav z doby pred prihlasenim (treba rozdelane
        # necekane klice) neprezije do prihlasene session - jen jazyk se
        # vedome prenese.
        lang = flask.session.get("lang", "cs")
        flask.session.clear()
        flask.session["realm"] = jmeno_realmu
        flask.session["admin"] = jmeno
        flask.session["lang"] = lang
        flask.session["csrf"] = secrets.token_hex(16)
        return flask.redirect(flask.url_for("_uvod"))

    @app.post("/logout")
    @prihlasen
    def _odhlasit():
        over_csrf()
        flask.session.clear()
        return flask.redirect(flask.url_for("_prihlasovaci_stranka"))

    @app.get("/")
    @prihlasen
    def _uvod():
        # /lide prijde az v ukolu 4 - url_for by tu selhalo (endpoint jeste
        # neexistuje), takze cesta je zatim natvrdo.
        return flask.redirect("/lide")

    return app
