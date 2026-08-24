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
import time
from pathlib import Path

from ..config import ServiceConfig
from ..files import FileStore
from ..principals import PUBLIC, USERS, check_identity, check_realm
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
        return flask.redirect(flask.url_for("_lide_seznam"))

    # == lide ===============================================================
    #
    # VZOR pro dalsi stranky (skupiny/aplikace/spravci/audit): kazda mutace
    # je @prihlasen + POST, prvni radek je over_csrf(), knihovni volani bezi
    # v try/except ValueError, uspech i chyba konci flashem a redirectem
    # (Post/Redirect/Get). `_lide_mutace` tenhle tvar nese za vsechny
    # jednoduche akce - vyjimkou je jen `/lide/pridat` s vlastnim GET view
    # (formular), ktere tu neni potreba.

    def _radek_cloveka(store, jmeno: str) -> dict:
        """Jeden radek vypisu: stav (aktivni/zakazany/cekajici na parovani/
        bez povereni) a skupinove chipy z plocheho uzaveru principalu.

        Cteni `totp.secret`/`totp.issued`/`totp.paired` je primo pres
        soubory - jen ke zjisteni stavu parovani, bez zamku (cteni, ne
        zapis; zapis dela vyhradne FileStore).

        Ctyri stavy, v tomto poradi:
        - zakazany: `disable_user` - clovek nesmi, i kdyby povereni mel.
        - bez povereni: zadne `totp.secret` ani `totp.issued` - typicky po
          `revoke_credential`, pred novym parovanim. Bez tohohle vetve by
          takovy clovek spadl do "aktivni", pritom se prihlasit NEMUZE.
        - ceka na parovani: `totp.issued` je, `totp.paired` jeste neni.
        - aktivni: zbytek (typicky `totp.paired`).
        """
        clovek = store.user(jmeno)
        skupiny = sorted(
            principal[len("group:"):]
            for principal in clovek.principals
            if principal.startswith("group:") and principal not in (PUBLIC, USERS)
        )
        if not clovek.enabled:
            stav, stav_text = "disabled", _prelozit("lide.disabled")
        else:
            adresar = store.home / f"user-{jmeno}"
            tajemstvi = adresar / "totp.secret"
            vydano = adresar / "totp.issued"
            sparovano = adresar / "totp.paired"
            if not tajemstvi.is_file() and not vydano.is_file():
                stav, stav_text = "no_credential", _prelozit("lide.no_credential")
            elif vydano.is_file() and not sparovano.is_file():
                try:
                    vydano_ts = int(vydano.read_text(encoding="utf-8").strip())
                except (ValueError, OSError):
                    # Poskozeny soubor - viz stejna uvaha v
                    # FileStore._enrolment_expired.
                    vydano_ts = 0
                zbyva = max(
                    0, int(store.qr_ttl_days - (time.time() - vydano_ts) // 86400)
                )
                stav = "waiting"
                stav_text = _prelozit("lide.waiting").format(dni=zbyva)
            else:
                stav, stav_text = "active", _prelozit("lide.active")
        return {
            "jmeno": jmeno, "stav": stav, "stav_text": stav_text, "skupiny": skupiny,
        }

    @app.get("/lide")
    @prihlasen
    def _lide_seznam():
        store = flask.g.store
        lide = [_radek_cloveka(store, jmeno) for jmeno in store.users()]
        return flask.render_template("lide.html", lide=lide)

    def _lide_mutace(jmeno, akce, presmerovani=None):
        """Spolecny tvar mutaci lidi: CSRF -> knihovni volani -> flash ->
        redirect. `presmerovani(vysledek)` urcuje cil PRI USPECHU (napr. na
        stranku QR) - vychozi je zpet na /lide. Chyba vzdy konci na /lide,
        `presmerovani` se pak nevola."""
        over_csrf()
        try:
            vysledek = akce(jmeno)
        except ValueError as chyba:
            flask.flash(f"{_prelozit('spolecne.error')}: {chyba}", "chyba")
            return flask.redirect(flask.url_for("_lide_seznam"))
        flask.flash(_prelozit("spolecne.done"), "ok")
        cil = presmerovani(vysledek) if presmerovani else flask.url_for("_lide_seznam")
        return flask.redirect(cil)

    @app.post("/lide/pridat")
    @prihlasen
    def _lide_pridat():
        jmeno = flask.request.form.get("jmeno", "")
        return _lide_mutace(
            jmeno, flask.g.store.add_user,
            presmerovani=lambda zavedeni: flask.url_for(
                "_lide_qr", jmeno=zavedeni.name
            ),
        )

    @app.post("/lide/<jmeno>/vypnout")
    @prihlasen
    def _lide_vypnout(jmeno):
        return _lide_mutace(jmeno, flask.g.store.disable_user)

    @app.post("/lide/<jmeno>/zapnout")
    @prihlasen
    def _lide_zapnout(jmeno):
        return _lide_mutace(jmeno, flask.g.store.enable_user)

    @app.post("/lide/<jmeno>/smazat")
    @prihlasen
    def _lide_smazat(jmeno):
        return _lide_mutace(jmeno, flask.g.store.remove_user)

    @app.post("/lide/<jmeno>/odvolat")
    @prihlasen
    def _lide_odvolat(jmeno):
        return _lide_mutace(jmeno, flask.g.store.revoke_credential)

    @app.post("/lide/<jmeno>/parovat")
    @prihlasen
    def _lide_parovat(jmeno):
        return _lide_mutace(
            jmeno, flask.g.store.pair,
            presmerovani=lambda zavedeni: flask.url_for(
                "_lide_qr", jmeno=zavedeni.name
            ),
        )

    @app.get("/lide/qr/<jmeno>")
    @prihlasen
    def _lide_qr(jmeno):
        # Jmeno se sklada do cesty na disku - overit DRIV, nez se ceho
        # dotkne, stejny vzorec jako knihovni metody (check_identity() prvni
        # radek). Zdeformovane jmeno je 404, ne 500 z divneho souboroveho
        # dotazu.
        try:
            jmeno = check_identity(jmeno)
        except ValueError:
            flask.abort(404)
        store = flask.g.store
        adresar = store.home / f"user-{jmeno}"
        cesta = adresar / "totp.txt"
        obrazec = cesta.read_text(encoding="utf-8") if cesta.is_file() else None
        sparovano = (adresar / "totp.paired").is_file()
        stitek = f"{store.realm}-member-{jmeno}"
        return flask.render_template(
            "qr.html", jmeno=jmeno, obrazec=obrazec, sparovano=sparovano,
            stitek=stitek,
        )

    return app
