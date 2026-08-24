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
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ..audit import read_events
from ..config import ServiceConfig
from ..files import FileStore
from ..principals import PUBLIC, USERS, check_identity, check_name, check_realm
from ..realms import realm_root
from . import preklady

#: Sablony jsou soucasti balicku - Flask by je jinak hledal relativne k cwd,
#: ktery se pri spusteni sluzby muze lisit od umisteni modulu.
_TEMPLATES = Path(__file__).parent / "templates"

#: Vychozi sirka okna auditu bez filtru - "nedavne udalosti", ne cela
#: historie (retence je typicky 90 dni, cely vypis by byl neprehledny).
_AUDIT_VYCHOZI_DNI = 7


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
    # Vychozi False (viz config.py) - za TLS terminujici proxy si to
    # provozovatel zapne (spec §3, konfigurace console_secure_cookie).
    app.config["SESSION_COOKIE_SECURE"] = cfg.console_secure_cookie

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
            store = _store_pro(jmeno_realmu, actor=f"admin:{admin}")
            if admin not in store.admins():
                # Spravce mezitim nekdo odebral (remove_admin) - bez tohohle
                # by jeho jiz otevrena relace zustala plne funkcni az do
                # odhlaseni/restartu. POZOR: jen NEEXISTENCE konci relaci -
                # pouhe odvolani tokenu (revoke_admin_credential) session
                # NEKONCI (zamerne, viz ruling opravneho kola) - odvolani
                # konci BUDOUCI prihlaseni, ne roli; zabiti session by
                # rozbilo tok odvolej-vlastni-token -> zobraz novy QR ->
                # znovu sparuj.
                flask.session.clear()
                return flask.redirect(flask.url_for("_prihlasovaci_stranka"))
            flask.g.store = store
            return view(*args, **kwargs)

        return obal

    def _bez_ukladani(vysledek):
        """Obal render_template odpovedi hlavickou `Cache-Control: no-store`.

        Pro stranky, ktere nesou tajemstvi presne jednou (QR kod, klic
        aplikace) - bez tehle hlavicky by je sdilena mezipamet (proxy,
        prohlizec pri Zpet/Vpred) mohla ulozit a zobrazit znovu i po tom,
        co uz je clovek nema videt.
        """
        odpoved = flask.make_response(vysledek)
        odpoved.headers["Cache-Control"] = "no-store"
        return odpoved

    @app.get("/lang")
    def _jazyk():
        """Prepinac jazyka, ktery umi presmerovat ZPET na puvodni stranku.

        Doplnuje starsi mechanismus `?lang=cs|en` (viz `_uloz_jazyk`), ktery
        na strankach vyrenderovanych primo z POST (klic.html) skonci 405
        (jina metoda) a na strankach s vlastnim dotazem (filtrovany /audit,
        /skupiny?skupina=...) dotaz zahodi. `next` se pousti dal JEN kdyz je
        to relativni cesta zacinajici jednim '/' - '//host/...' by prohlizec
        vzal jako absolutni URL na cizi host (open redirect).
        """
        to = flask.request.args.get("to")
        if to in ("cs", "en"):
            flask.session["lang"] = to
        dalsi = flask.request.args.get("next", "")
        if dalsi.startswith("/") and not dalsi.startswith("//"):
            return flask.redirect(dalsi)
        return flask.redirect("/")

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

        # Normalizace DRIV, nez se cokoli porovna nebo ulozi do session:
        # authenticate_admin normalizuje jmeno pres check_identity uvnitr
        # sebe, ale strazce (prihlasen) porovnava syrove session["admin"]
        # proti uz normalizovanym admins() - bez tehle normalizace by
        # "Jindrich " (velke pismeno, mezera navic) prihlaseni uspelo, ale
        # KAZDY dalsi pozadavek by strazce odrazel zpatky na /login. Zdeformo-
        # vane jmeno/realm hlasi STEJNOU hlasku jako spatny kod - zadny
        # postranni kanal.
        try:
            jmeno_realmu = check_realm(jmeno_realmu)
            jmeno = check_identity(jmeno)
        except ValueError:
            return flask.render_template("login.html", chyba=_prelozit("login.failed"))

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
        return _bez_ukladani(flask.render_template(
            "qr.html", jmeno=jmeno, obrazec=obrazec, sparovano=sparovano,
            stitek=stitek, zpet=flask.url_for("_lide_seznam"),
        ))

    # == skupiny =============================================================
    #
    # Na rozdil od `_lide_mutace` bere `_skupiny_mutace` cil presmerovani
    # VZDY explicitne (`cil=`) - mutace clenu/zretezeni maji po chybe
    # i po uspechu zustat na detailu prave upravovane skupiny, ne skocit
    # zpatky na holy vypis (jedina vyjimka je smazani skupiny samotne,
    # po kterem uz detail nedava smysl).

    def _radek_skupiny(store, nazev: str) -> dict:
        skupina = store.group(nazev)
        return {
            "nazev": nazev,
            "pocet_clenu": len(skupina.members),
            "pocet_zahrnuti": len(skupina.includes),
        }

    def _detail_skupiny(store, nazev: str) -> dict | None:
        """Detail jedne skupiny: prime cleny, zahrnute skupiny a kdo do ni
        patri jen pres zretezeni (uzaver principalu minus prime clenstvi -
        cteni bez zamku, stejne jako `_radek_cloveka`)."""
        skupina = store.group(nazev)
        if skupina is None:
            return None
        principal = f"group:{nazev}"
        pres_zretezeni = sorted(
            jmeno for jmeno in store.users()
            if jmeno not in skupina.members
            and principal in store.user(jmeno).principals
        )
        return {
            "nazev": nazev,
            "clenove": skupina.members,
            "zahrnute": skupina.includes,
            "pres_zretezeni": pres_zretezeni,
            "kandidati_clenove": [
                j for j in store.users() if j not in skupina.members
            ],
            "ostatni_skupiny": [
                g for g in store.groups()
                if g != nazev and g not in skupina.includes
            ],
        }

    @app.get("/skupiny")
    @prihlasen
    def _skupiny_seznam():
        store = flask.g.store
        skupiny = [_radek_skupiny(store, nazev) for nazev in store.groups()]
        detail = None
        pozadovana = flask.request.args.get("skupina")
        if pozadovana:
            try:
                pozadovana = check_name(pozadovana)
            except ValueError:
                pozadovana = None
            if pozadovana:
                detail = _detail_skupiny(store, pozadovana)
        return flask.render_template("skupiny.html", skupiny=skupiny, detail=detail)

    def _skupiny_mutace(akce, *args, cil, presmerovani=None):
        """Spolecny tvar mutaci skupin: CSRF -> knihovni volani -> flash ->
        redirect na `cil` (chyba i vychozi uspech) nebo `presmerovani(vysledek)`
        (uspech, kdyz ma jit jinam)."""
        over_csrf()
        try:
            vysledek = akce(*args)
        except ValueError as chyba:
            flask.flash(f"{_prelozit('spolecne.error')}: {chyba}", "chyba")
            return flask.redirect(cil)
        flask.flash(_prelozit("spolecne.done"), "ok")
        return flask.redirect(presmerovani(vysledek) if presmerovani else cil)

    @app.post("/skupiny/pridat")
    @prihlasen
    def _skupiny_pridat():
        nazev = flask.request.form.get("nazev", "")
        return _skupiny_mutace(
            flask.g.store.add_group, nazev,
            cil=flask.url_for("_skupiny_seznam"),
            presmerovani=lambda _: flask.url_for("_skupiny_seznam", skupina=nazev),
        )

    @app.post("/skupiny/<nazev>/smazat")
    @prihlasen
    def _skupiny_smazat(nazev):
        return _skupiny_mutace(
            flask.g.store.remove_group, nazev,
            cil=flask.url_for("_skupiny_seznam"),
        )

    @app.post("/skupiny/<nazev>/clen")
    @prihlasen
    def _skupiny_clen_pridat(nazev):
        clen = flask.request.form.get("clen", "")
        return _skupiny_mutace(
            flask.g.store.add_member, nazev, clen,
            cil=flask.url_for("_skupiny_seznam", skupina=nazev),
        )

    @app.post("/skupiny/<nazev>/clen/<clen>/odebrat")
    @prihlasen
    def _skupiny_clen_odebrat(nazev, clen):
        return _skupiny_mutace(
            flask.g.store.remove_member, nazev, clen,
            cil=flask.url_for("_skupiny_seznam", skupina=nazev),
        )

    @app.post("/skupiny/<nazev>/zretezit")
    @prihlasen
    def _skupiny_zretezit(nazev):
        zahrnuti = flask.request.form.get("zahrnuti", "")
        return _skupiny_mutace(
            flask.g.store.include, nazev, zahrnuti,
            cil=flask.url_for("_skupiny_seznam", skupina=nazev),
        )

    # == aplikace =============================================================
    #
    # Jedina stranka s vyjimkou z PRG: uspesna registrace vraci PLNY klic
    # PRAVE JEDNOU - misto redirectu se rovnou renderuje vysledkova sablona
    # `klic.html` primo z teto POST odpovedi. Klic nikdy nejde do session ani
    # do flashe (obe jsou cookie - klic by tam byl navic a mohl by presahnout
    # limit velikosti cookie). Neuspech (napr. duplicitni jmeno) naopak
    # zustava na PRG + flash, presne jako u ostatnich stranek - znovunacteni
    # po chybe je bezpecne (dalsi pokus zase jen selze na duplicite).

    def _radek_aplikace(komponenta) -> dict:
        return {
            "jmeno": komponenta.name,
            "key_id": komponenta.key_id,
            "otisk": komponenta.key_hash[:12],
            "origins": komponenta.origins,
            "detail": komponenta.detail,
        }

    @app.get("/aplikace")
    @prihlasen
    def _aplikace_seznam():
        aplikace = [_radek_aplikace(k) for k in flask.g.store.components()]
        return flask.render_template("aplikace.html", aplikace=aplikace)

    @app.post("/aplikace/pridat")
    @prihlasen
    def _aplikace_pridat():
        over_csrf()
        jmeno = flask.request.form.get("jmeno", "").strip()
        origins = [
            puvod.strip()
            for puvod in flask.request.form.get("origins", "").split(",")
            if puvod.strip()
        ]
        detail = flask.request.form.get("detail") == "on"
        try:
            klic = flask.g.store.register_component(
                jmeno, origins=origins, detail=detail
            )
        except ValueError as chyba:
            flask.flash(f"{_prelozit('spolecne.error')}: {chyba}", "chyba")
            return flask.redirect(flask.url_for("_aplikace_seznam"))
        return _bez_ukladani(
            flask.render_template("klic.html", jmeno=jmeno, klic=klic)
        )

    def _aplikace_mutace(jmeno, akce):
        """Stejny tvar jako `_lide_mutace`/`_skupiny_mutace`, jen bez
        volitelneho presmerovani - odvolani vzdy konci zpet na vypisu."""
        over_csrf()
        try:
            akce(jmeno)
        except ValueError as chyba:
            flask.flash(f"{_prelozit('spolecne.error')}: {chyba}", "chyba")
        else:
            flask.flash(_prelozit("spolecne.done"), "ok")
        return flask.redirect(flask.url_for("_aplikace_seznam"))

    @app.post("/aplikace/<jmeno>/odvolat")
    @prihlasen
    def _aplikace_odvolat(jmeno):
        return _aplikace_mutace(jmeno, flask.g.store.revoke_component)

    # == spravci ==============================================================
    #
    # Zrcadli lide (`_lide_mutace`/`_radek_cloveka`), jen bez "zakazany" -
    # spravci nemaji disable_admin/enable_admin, takze ten stav pro ne
    # neexistuje. `qr.html` je SDILENA s lide - `_spravci_qr` je tenka route
    # nad stejnou sablonou, jen cte z `admin-<jmeno>` a posila jiny stitek
    # a jiny "zpet" cil.

    def _radek_spravce(store, jmeno: str) -> dict:
        """Jeden radek vypisu spravcu: stitek pro parovani a stav.

        Tri stavy, v tomto poradi (stejna uvaha jako `_radek_cloveka`, jen bez
        vetve "zakazany" - ta pro spravce v konzoli neexistuje):
        - bez povereni: zadne `totp.secret` ani `totp.issued` - typicky po
          `revoke_admin_credential`, pred novym parovanim.
        - ceka na parovani: `totp.issued` je, `totp.paired` jeste neni.
        - sparovano: zbytek (typicky `totp.paired`) - vizualne stejna trida
          jako "aktivni" u lidi (`stav-active`), text z `spravci.paired`.
        """
        adresar = store.home / f"admin-{jmeno}"
        tajemstvi = adresar / "totp.secret"
        vydano = adresar / "totp.issued"
        sparovano = adresar / "totp.paired"
        if not tajemstvi.is_file() and not vydano.is_file():
            stav, stav_text = "no_credential", _prelozit("lide.no_credential")
        elif vydano.is_file() and not sparovano.is_file():
            try:
                vydano_ts = int(vydano.read_text(encoding="utf-8").strip())
            except (ValueError, OSError):
                # Poskozeny soubor - viz stejna uvaha v FileStore._enrolment_expired.
                vydano_ts = 0
            zbyva = max(
                0, int(store.qr_ttl_days - (time.time() - vydano_ts) // 86400)
            )
            stav = "waiting"
            stav_text = _prelozit("lide.waiting").format(dni=zbyva)
        else:
            stav, stav_text = "active", _prelozit("spravci.paired")
        return {
            "jmeno": jmeno, "stitek": f"{store.realm}-admin-{jmeno}",
            "stav": stav, "stav_text": stav_text,
        }

    @app.get("/spravci")
    @prihlasen
    def _spravci_seznam():
        store = flask.g.store
        spravci = [_radek_spravce(store, jmeno) for jmeno in store.admins()]
        return flask.render_template("spravci.html", spravci=spravci)

    def _spravci_mutace(jmeno, akce, presmerovani=None):
        """Stejny tvar jako `_lide_mutace` - CSRF -> knihovni volani -> flash ->
        redirect. Guard posledniho spravce (`_require_not_last_admin`) hlasi
        `ValueError` s presnym textem z knihovny, zobrazenym surove."""
        over_csrf()
        try:
            vysledek = akce(jmeno)
        except ValueError as chyba:
            flask.flash(f"{_prelozit('spolecne.error')}: {chyba}", "chyba")
            return flask.redirect(flask.url_for("_spravci_seznam"))
        flask.flash(_prelozit("spolecne.done"), "ok")
        cil = (
            presmerovani(vysledek) if presmerovani
            else flask.url_for("_spravci_seznam")
        )
        return flask.redirect(cil)

    @app.post("/spravci/pridat")
    @prihlasen
    def _spravci_pridat():
        jmeno = flask.request.form.get("jmeno", "")
        return _spravci_mutace(
            jmeno, flask.g.store.add_admin,
            presmerovani=lambda zavedeni: flask.url_for(
                "_spravci_qr", jmeno=zavedeni.name
            ),
        )

    @app.post("/spravci/<jmeno>/odebrat")
    @prihlasen
    def _spravci_odebrat(jmeno):
        return _spravci_mutace(jmeno, flask.g.store.remove_admin)

    @app.post("/spravci/<jmeno>/odvolat")
    @prihlasen
    def _spravci_odvolat(jmeno):
        return _spravci_mutace(jmeno, flask.g.store.revoke_admin_credential)

    @app.post("/spravci/<jmeno>/parovat")
    @prihlasen
    def _spravci_parovat(jmeno):
        return _spravci_mutace(
            jmeno, flask.g.store.pair_admin,
            presmerovani=lambda zavedeni: flask.url_for(
                "_spravci_qr", jmeno=zavedeni.name
            ),
        )

    @app.get("/spravci/qr/<jmeno>")
    @prihlasen
    def _spravci_qr(jmeno):
        # Stejna uvaha jako u `_lide_qr`: jmeno overit DRIV, nez se ceho na
        # disku dotkne - zdeformovane jmeno je 404, ne 500.
        try:
            jmeno = check_identity(jmeno)
        except ValueError:
            flask.abort(404)
        store = flask.g.store
        adresar = store.home / f"admin-{jmeno}"
        cesta = adresar / "totp.txt"
        obrazec = cesta.read_text(encoding="utf-8") if cesta.is_file() else None
        sparovano = (adresar / "totp.paired").is_file()
        stitek = f"{store.realm}-admin-{jmeno}"
        return _bez_ukladani(flask.render_template(
            "qr.html", jmeno=jmeno, obrazec=obrazec, sparovano=sparovano,
            stitek=stitek, zpet=flask.url_for("_spravci_seznam"),
        ))

    # == audit ================================================================
    #
    # Jedina ciste GET stranka konzole: cte auditni stopu (`read_events`),
    # nic nemutuje - zadny CSRF. Kazde pole udalosti se cte tolerantne pres
    # `.get` - rucne poskozeny/kusy radek (napr. jen {"t": ..., "kind":
    # "weird"}) nesmi stranku shodit, jen se zobrazi prazdne/surove.

    def _validni_den(text: str) -> str | None:
        """`text` jako 'RRRR-MM-DD', jinak None (= pouzij vychozi den).

        HTML date input muze dorazit prazdny nebo rucne poskozeny (upraveny
        dotaz v adresnim radku primo) - nikdy nesmi shodit stranku, jen se
        tise nahradi vychozim oknem.
        """
        if not text:
            return None
        try:
            datetime.strptime(text, "%Y-%m-%d")
        except ValueError:
            return None
        return text

    def _radek_udalosti(udalost: dict) -> dict:
        """Jeden radek auditu - vsechna pole tolerantne pres `.get`.

        `vysledek` ma tri barvy: `ok` zelene, `denied` cervene (+ `reason`
        vedle), zapisy (`kind == "write"`, ktere `outcome` vubec nemaji)
        modre; cokoli jine (`need_factor`, `throttled`, chybejici) neutralne.
        Neznamy `kind` se do udalosti propise surove - zadny seznam znamych
        hodnot, zadna vyjimka.
        """
        kind = udalost.get("kind", "")
        outcome = udalost.get("outcome")
        if outcome == "ok":
            trida, text = "vysledek-ok", outcome
        elif outcome == "denied":
            trida, text = "vysledek-denied", outcome
        elif outcome:
            trida, text = "vysledek-jiny", outcome
        elif kind == "write":
            trida, text = "vysledek-write", kind
        else:
            trida, text = "vysledek-jiny", ""
        udalost_text = " ".join(
            kus for kus in (kind, udalost.get("op") or udalost.get("purpose")) if kus
        )
        kdo = (
            udalost.get("subject") or udalost.get("actor")
            or udalost.get("component") or ""
        )
        return {
            "cas": udalost.get("t", ""),
            "udalost": udalost_text,
            "kdo": kdo,
            "vysledek_text": text,
            "vysledek_trida": trida,
            "reason": udalost.get("reason", ""),
        }

    @app.get("/audit")
    @prihlasen
    def _audit_seznam():
        store = flask.g.store
        dnes = datetime.now(UTC).date()
        vychozi_od = (dnes - timedelta(days=_AUDIT_VYCHOZI_DNI)).isoformat()
        vychozi_do = dnes.isoformat()
        od = _validni_den(flask.request.args.get("od", "")) or vychozi_od
        do = _validni_den(flask.request.args.get("do", "")) or vychozi_do
        subjekt = flask.request.args.get("subjekt", "").strip() or None
        kind = flask.request.args.get("kind", "").strip() or None
        outcome = flask.request.args.get("outcome", "").strip() or None
        udalosti = read_events(
            store.home, day_from=od, day_to=do,
            subject=subjekt, outcome=outcome, kind=kind,
        )
        # Nejnovejsi nahoru - `read_events` vraci chronologicky (soubor po
        # souboru, radek po radku), coz je pro cteni logu pozpatku.
        radky = [_radek_udalosti(u) for u in reversed(udalosti)]
        return flask.render_template(
            "audit.html", udalosti=radky, od=od, do=do,
            subjekt=subjekt or "", kind=kind or "", outcome=outcome or "",
        )

    return app
