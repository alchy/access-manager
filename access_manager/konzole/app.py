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
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .. import log
from ..audit import read_events, recent_by_subject
from ..config import ServiceConfig
from ..files import FileStore
from ..origin import resolve_origin
from ..principals import PUBLIC, USERS, check_identity, check_name, check_realm
from ..realms import realm_root
from . import preklady

#: Sablony jsou soucasti balicku - Flask by je jinak hledal relativne k cwd,
#: ktery se pri spusteni sluzby muze lisit od umisteni modulu.
_TEMPLATES = Path(__file__).parent / "templates"

#: Vychozi sirka okna auditu bez filtru - "nedavne udalosti", ne cela
#: historie (retence je typicky 90 dni, cely vypis by byl neprehledny).
_AUDIT_VYCHOZI_DNI = 7

#: Kolik prihlaseni ukaze roletka u cloveka ve vypisu. Je to "co se delo
#: naposled", ne historie - na tu je stranka auditu s filtrem.
_POSLEDNICH_PRIHLASENI = 5


def _zavedeni_k_opsani(adresar: Path) -> tuple[str | None, str | None]:
    """Vrat (uri, tajemstvi) k rucnimu opsani, nebo (None, None).

    Cte se `totp.uri`, NIKDY `totp.secret` - a je to zamer. Parovanim se
    `totp.uri` i `totp.txt` mazou (`_complete_pairing`), zatimco tajemstvi
    zustava a overuje dal: "mizi jen jeho zobrazitelna podoba". Kdyby se
    string bral z `totp.secret`, tahle podoba by se po sparovani vratila -
    presne to, co mazani artefaktu ma zarusit. Takhle ma string TOTOZNOU
    zivotnost jako QR vedle nej.
    """
    cesta = adresar / "totp.uri"
    if not cesta.is_file():
        return None, None
    uri = cesta.read_text(encoding="utf-8").strip()
    hodnoty = parse_qs(urlparse(uri).query).get("secret")
    return uri, (hodnoty[0] if hodnoty else None)


def _require_flask():
    """Vrat `flask`, nebo rekni JAK to doinstalovat."""
    try:
        import flask
    except ImportError as chybi:
        raise RuntimeError(
            "konzole potrebuje flask: pip install 'access-manager[server]'"
        ) from chybi
    return flask


#: Kolik cislic ma jeden TOTP kod. Sablona podle toho vykresli policka.
DELKA_KODU = 6


def _kod_z_formulare(form, pole: str) -> str:
    """Slozi kod bud z jednoho pole, nebo z policek po cislicich.

    Prihlasovaci stranka vykresluje policko na kazdou cislici
    (`kod1_1`..`kod1_6`), protoze se to lip opisuje z telefonu. Jedno pole
    s celym kodem ale zustava platne - posilaji ho testy i kdokoli, kdo si
    formular odesle sam. Bere se to, co prislo; cele pole ma prednost.
    """
    cely = form.get(pole, "").strip()
    if cely:
        return cely
    return "".join(
        form.get(f"{pole}_{i}", "").strip() for i in range(1, DELKA_KODU + 1)
    )


#: Jadra prohlizecu v poradi, v jakem se musi zkouset. Poradi neni libovolne:
#: Edge i Opera nesou v UA retezci taky "Chrome", Chrome zase "Safari" - kdo
#: hleda obecnejsi znacku driv, oznaci Edge za Chrome a Safari za cokoli.
_JADRA = (
    ("Firefox/", "Firefox (Gecko)"),
    ("Edg/", "Edge (Blink)"),
    ("OPR/", "Opera (Blink)"),
    ("Chrome/", "Chrome (Blink)"),
    ("Safari/", "Safari (WebKit)"),
    ("curl/", "curl"),
    ("Wget/", "Wget"),
)


def _prohlizec(ua: str) -> str:
    """Jadro prohlizece z hlavicky User-Agent, nebo prazdno.

    Nechceme presnou identifikaci - UA retezec je notoricky lzivy a nic se
    podle nej nerozhoduje. Je to jen informace pro cloveka u obrazovky:
    "prihlasuju se odsud a timhle". Nezname UA se radeji nehada.
    """
    for znacka, nazev in _JADRA:
        if znacka in ua:
            return nazev
    return ""


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
            # Do AUDITU, ne do provozniho logu: sem se dojde jen za strazcem,
            # takze realm i spravce jsou znami a je kam zapsat. Zaroven je to
            # presne ta udalost, ktera ma prezit rotaci provozniho logu.
            store = flask.g.get("store")
            if store is not None:
                store.audit_event(
                    kind="session", op="csrf_denied",
                    actor=f"admin:{flask.session.get('admin')}",
                    path=flask.request.path,
                )
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
        return {"t": _prelozit, "delka_kodu": DELKA_KODU}

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
                store.audit_event(
                    kind="session", op="evicted", actor=f"admin:{admin}",
                    reason="admin_removed",
                )
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
        /groups?group=...) dotaz zahodi. `next` se pousti dal JEN kdyz je
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

    def _kontext_pristupu() -> dict:
        """Odkud a cim se clovek diva - vypisuje se pod prihlasovacim formularem.

        Adresa je TA SAMA, kterou meri origin ACL a audit (resolve_origin),
        ne holy remote_addr. Kdyz se tady objevi adresa proxy misto klienta,
        je spatne nastavene trusted_proxies/hops - a je to videt hned, ne az
        z auditu za tri mesice.
        """
        return {
            "klient_ip": resolve_origin(flask.request.environ, cfg),
            "klient_prohlizec": _prohlizec(
                flask.request.headers.get("User-Agent", "")
            ),
        }

    @app.get("/login")
    def _prihlasovaci_stranka():
        return flask.render_template("login.html", **_kontext_pristupu())

    @app.post("/login")
    def _prihlasit():
        # POST /login je pred existenci session - neni co porovnat s CSRF
        # tokenem, takze se tady over_csrf() zamerne nevola (viz jeho
        # docstring). Neznamy realm i spatne kody hlasi TOTOZNOU hlasku -
        # zadny postranni kanal, ktery by prozradil, ze realm neexistuje.
        jmeno_realmu = flask.request.form.get("realm", "")
        jmeno = flask.request.form.get("jmeno", "")
        kod1 = _kod_z_formulare(flask.request.form, "kod1")
        kod2 = _kod_z_formulare(flask.request.form, "kod2")
        # Puvod se meri stejne jako u API a auditu (resolve_origin), ne z
        # holeho remote_addr - jinak by log za proxy ukazoval proxy.
        origin = resolve_origin(flask.request.environ, cfg)

        # Normalizace DRIV, nez se cokoli porovna nebo ulozi do session:
        # authenticate_admin normalizuje jmeno pres check_identity uvnitr
        # sebe, ale strazce (prihlasen) porovnava syrove session["admin"]
        # proti uz normalizovanym admins() - bez tehle normalizace by
        # "Jindrich " (velke pismeno, mezera navic) prihlaseni uspelo, ale
        # KAZDY dalsi pozadavek by strazce odrazel zpatky na /login. Zdeformo-
        # vane jmeno/realm hlasi STEJNOU hlasku jako spatny kod - zadny
        # postranni kanal.
        # Oba nasledujici pripady konci DRIV, nez existuje uloziste, do
        # ktereho by se auditovalo - realm bud neprosel kontrolou tvaru, nebo
        # zadny takovy neni. Auditni stopa je per-realm, takze pro ne neni
        # kam zapsat a provozni log je jejich JEDINA stopa. Bez nej se pokus
        # nezjevi nikde a provozovatel se v konzoli nedopatra, proc se nekdo
        # neprihlasi (presne to stalo hodinu, viz spec §3.1).
        #
        # Loguje se tvar, jak PRISEL - zdeformovany. To je ta informace,
        # kterou clovek hleda; normalizovany by nerekl nic.
        try:
            jmeno_realmu = check_realm(jmeno_realmu)
            jmeno = check_identity(jmeno)
        except ValueError:
            log.info(
                "console_login", outcome="denied", reason="bad_form",
                origin=origin, realm=jmeno_realmu, name=jmeno,
            )
            return flask.render_template(
                "login.html", chyba=_prelozit("login.failed"), **_kontext_pristupu()
            )

        if jmeno_realmu not in realmy:
            log.info(
                "console_login", outcome="denied", reason="unknown_realm",
                origin=origin, realm=jmeno_realmu, name=jmeno,
            )
            return flask.render_template(
                "login.html", chyba=_prelozit("login.failed"), **_kontext_pristupu()
            )

        # Odsud dal je realm znamy - vsechno ostatni (ok, bad_code, replay,
        # throttled, ...) zapise do auditu `authenticate_admin`. Do provozniho
        # logu uz to NEJDE: dve mista teze udalosti by se musela drzet
        # v souladu a jedno z nich by pritom rotace zahodila.

        store = _store_pro(jmeno_realmu, actor=f"admin:{jmeno}")
        verdikt = store.authenticate_admin(jmeno, kod1, kod2, origin=origin)

        if verdikt.outcome == "throttled":
            chyba = _prelozit("login.throttled").format(s=verdikt.retry_after)
            return flask.render_template(
                "login.html", chyba=chyba, **_kontext_pristupu()
            )
        if not verdikt:
            return flask.render_template(
                "login.html", chyba=_prelozit("login.failed"), **_kontext_pristupu()
            )

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
        flask.g.store.audit_event(
            kind="session", op="logout",
            actor=f"admin:{flask.session.get('admin')}",
        )
        flask.session.clear()
        return flask.redirect(flask.url_for("_prihlasovaci_stranka"))

    @app.get("/")
    @prihlasen
    def _uvod():
        return flask.redirect(flask.url_for("_uzivatele_seznam"))

    # == uzivatele ==========================================================
    #
    # VZOR pro dalsi stranky (skupiny/aplikace/spravci/audit): kazda mutace
    # je @prihlasen + POST, prvni radek je over_csrf(), knihovni volani bezi
    # v try/except ValueError, uspech i chyba konci flashem a redirectem
    # (Post/Redirect/Get). `_uzivatele_mutace` tenhle tvar nese za vsechny
    # jednoduche akce - vyjimkou je jen `/users/add` s vlastnim GET view
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
        adresar = store.home / f"user-{jmeno}"
        if not clovek.enabled:
            stav, stav_text = "disabled", _prelozit("uzivatele.disabled")
        else:
            tajemstvi = adresar / "totp.secret"
            vydano = adresar / "totp.issued"
            sparovano = adresar / "totp.paired"
            if not tajemstvi.is_file() and not vydano.is_file():
                stav, stav_text = "no_credential", _prelozit("uzivatele.no_credential")
            elif vydano.is_file() and not sparovano.is_file():
                if store.enrolment_expired(adresar):
                    # Bez tehle vetve spadne vyprsely token do "ceka"
                    # a vypise se jako "plati jeste 0 dni" - tedy jako by
                    # na nej porad slo cekat.
                    stav = "expired"
                    stav_text = _prelozit("uzivatele.expired")
                else:
                    stav = "waiting"
                    stav_text = _prelozit("uzivatele.waiting").format(
                        dni=store.enrolment_days_left(adresar)
                    )
            else:
                stav, stav_text = "active", _prelozit("uzivatele.active")
        return {
            "jmeno": jmeno, "stav": stav, "stav_text": stav_text, "skupiny": skupiny,
            # Kdy bylo zavedeni vydano a kdy se spotrebovalo. `totp.paired`
            # pise `_complete_pairing` v okamziku PRVNIHO uspesneho prihlaseni
            # - je to tedy razitko prave toho pozadavku, ktery QR ze stranky
            # odebral. Nikam se to dopisovat nemusi, uz to na disku je.
            "vydano": _razitko(adresar / "totp.issued"),
            "sparovano": _razitko(adresar / "totp.paired"),
        }

    def _razitko(cesta: Path) -> str | None:
        """Unixove razitko ze souboru jako ISO v UTC, nebo None.

        `totp.issued` a `totp.paired` drzi cislo; audit i provozni log pisou
        ISO v UTC. Prevod je tady, at se v rozhrani nepotkaji dva tvary casu.
        Poskozeny soubor je "nevim" - stejna uvaha jako v
        `FileStore._enrolment_expired`, jen tam je fail-closed a tady staci
        neukazat nic.
        """
        if not cesta.is_file():
            return None
        try:
            razitko = int(cesta.read_text(encoding="utf-8").strip())
        except (ValueError, OSError):
            return None
        return datetime.fromtimestamp(razitko, UTC).isoformat(timespec="seconds")

    def _radek_prihlaseni(udalost: dict) -> dict:
        """Jeden radek roletky. Stejna ctverice a stejne tridy jako stranka
        auditu (`_radek_udalosti`) - je to tyz zaznam, jen uzsi vyber."""
        outcome = udalost.get("outcome")
        if outcome == "ok":
            trida = "vysledek-ok"
        elif outcome == "denied":
            trida = "vysledek-denied"
        else:
            trida = "vysledek-jiny"
        return {
            "cas": udalost.get("t", ""),
            # Chybejici pole je pomlcka, ne prazdno: lokalni volani adresu
            # nema (viz `FileStore.authenticate`) a prazdna bunka by vypadala
            # jako rozbite vykresleni.
            "odkud": udalost.get("origin") or "—",
            "kdo_pozadal": udalost.get("component") or "—",
            "vysledek_text": outcome or "",
            "vysledek_trida": trida,
            "reason": udalost.get("reason", ""),
        }

    def _vyfiltruj(jmena, dotaz):
        """Podretezcovy filtr pres jmeno. Prazdny dotaz nefiltruje.

        Zamerne obycejny podretezec, ne prefix: spravce hleda "novak" a chce
        najit i "jan.novak@example.com".
        """
        if not dotaz:
            return list(jmena)
        return [jmeno for jmeno in jmena if dotaz in jmeno]

    @app.get("/users")
    @prihlasen
    def _uzivatele_seznam():
        store = flask.g.store
        vsichni = store.users()
        dotaz = flask.request.args.get("q", "").strip().lower()
        # Filtruje se PRED stavbou radku. `_radek_cloveka` sahne kazde identite
        # na disk zvlast (stav poverni, zbyvajici platnost QR, skupiny), takze
        # u stovek identit je nefiltrovany vypis stovky cteni na jedno
        # zobrazeni - a vetsinu z nich pak nikdo necte.
        vybrani = _vyfiltruj(vsichni, dotaz)
        uzivatele = [_radek_cloveka(store, jmeno) for jmeno in vybrani]
        # JEDEN pruchod auditem pro celou stranku, ne jeden na kazdeho -
        # `recent_by_subject` cte od nejnovejsiho dne a konci, jakmile ma
        # kazdy dost. Az PO filtru, ze stejneho duvodu jako radky vyse.
        prihlaseni = recent_by_subject(
            store.home,
            [f"user:{jmeno}" for jmeno in vybrani],
            kind="authenticate",
            limit=_POSLEDNICH_PRIHLASENI,
        )
        for radek in uzivatele:
            radek["prihlaseni"] = [
                _radek_prihlaseni(u)
                for u in prihlaseni.get(f"user:{radek['jmeno']}", ())
            ]
        return flask.render_template(
            "uzivatele.html", uzivatele=uzivatele, dotaz=dotaz,
            celkem=len(vsichni), videno=len(vybrani),
        )

    def _uzivatele_mutace(jmeno, akce, presmerovani=None):
        """Spolecny tvar mutaci lidi: CSRF -> knihovni volani -> flash ->
        redirect. `presmerovani(vysledek)` urcuje cil PRI USPECHU (napr. na
        stranku QR) - vychozi je zpet na /users. Chyba vzdy konci na /users,
        `presmerovani` se pak nevola."""
        over_csrf()
        seznam = flask.url_for("_uzivatele_seznam")
        try:
            vysledek = akce(jmeno)
        except ValueError as chyba:
            flask.flash(f"{_prelozit('spolecne.error')}: {chyba}", "chyba")
            return flask.redirect(seznam)
        flask.flash(_prelozit("spolecne.done"), "ok")
        return flask.redirect(presmerovani(vysledek) if presmerovani else seznam)

    @app.post("/users/add")
    @prihlasen
    def _uzivatele_pridat():
        jmeno = flask.request.form.get("jmeno", "")
        return _uzivatele_mutace(
            jmeno, flask.g.store.add_user,
            presmerovani=lambda zavedeni: flask.url_for(
                "_uzivatele_qr", jmeno=zavedeni.name
            ),
        )

    @app.post("/users/<jmeno>/disable")
    @prihlasen
    def _uzivatele_vypnout(jmeno):
        return _uzivatele_mutace(jmeno, flask.g.store.disable_user)

    @app.post("/users/<jmeno>/enable")
    @prihlasen
    def _uzivatele_zapnout(jmeno):
        return _uzivatele_mutace(jmeno, flask.g.store.enable_user)

    @app.post("/users/<jmeno>/delete")
    @prihlasen
    def _uzivatele_smazat(jmeno):
        return _uzivatele_mutace(jmeno, flask.g.store.remove_user)

    @app.post("/users/<jmeno>/revoke")
    @prihlasen
    def _uzivatele_odvolat(jmeno):
        return _uzivatele_mutace(jmeno, flask.g.store.revoke_credential)

    @app.post("/users/<jmeno>/pair")
    @prihlasen
    def _uzivatele_parovat(jmeno):
        return _uzivatele_mutace(
            jmeno, flask.g.store.pair,
            presmerovani=lambda zavedeni: flask.url_for(
                "_uzivatele_qr", jmeno=zavedeni.name
            ),
        )

    @app.get("/users/qr/<jmeno>")
    @prihlasen
    def _uzivatele_qr(jmeno):
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
        # Vyprsele zavedeni uz `authenticate` odmita (`expired`) - ukazovat
        # k nemu dal QR a tajemstvi znamena posilat cloveka opsat neco, co
        # mu stejne neprojde. Artefakty na disku zustavaji; skryva se jen
        # jejich zobrazeni, dokud nekdo nevyda nove.
        vyprselo = store.enrolment_expired(adresar)
        stitek = f"{store.realm}-member-{jmeno}"
        # Tyz obsah jako QR, jen k opsani - kdo sedi u konzole a nema cim
        # skenovat, jinak nema jak zavedeni dokoncit.
        uri, secret = _zavedeni_k_opsani(adresar)
        return _bez_ukladani(flask.render_template(
            "qr.html", jmeno=jmeno, obrazec=obrazec, sparovano=sparovano,
            vyprselo=vyprselo, stitek=stitek, uri=uri, secret=secret,
            zpet=flask.url_for("_uzivatele_seznam"),
        ))

    # == skupiny =============================================================
    #
    # Na rozdil od `_uzivatele_mutace` bere `_skupiny_mutace` cil presmerovani
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

    @app.get("/groups")
    @prihlasen
    def _skupiny_seznam():
        store = flask.g.store
        vsechny = store.groups()
        dotaz = flask.request.args.get("q", "").strip().lower()
        vybrane = _vyfiltruj(vsechny, dotaz)
        skupiny = [_radek_skupiny(store, nazev) for nazev in vybrane]
        detail = None
        pozadovana = flask.request.args.get("group")
        if pozadovana:
            try:
                pozadovana = check_name(pozadovana)
            except ValueError:
                pozadovana = None
            if pozadovana:
                detail = _detail_skupiny(store, pozadovana)
        return flask.render_template(
            "skupiny.html", skupiny=skupiny, detail=detail, dotaz=dotaz,
            celkem=len(vsechny), videno=len(vybrane),
        )

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

    @app.post("/groups/add")
    @prihlasen
    def _skupiny_pridat():
        nazev = flask.request.form.get("nazev", "")
        return _skupiny_mutace(
            flask.g.store.add_group, nazev,
            cil=flask.url_for("_skupiny_seznam"),
            presmerovani=lambda _: flask.url_for("_skupiny_seznam", group=nazev),
        )

    @app.post("/groups/<nazev>/delete")
    @prihlasen
    def _skupiny_smazat(nazev):
        return _skupiny_mutace(
            flask.g.store.remove_group, nazev,
            cil=flask.url_for("_skupiny_seznam"),
        )

    @app.post("/groups/<nazev>/member")
    @prihlasen
    def _skupiny_clen_pridat(nazev):
        clen = flask.request.form.get("clen", "")
        return _skupiny_mutace(
            flask.g.store.add_member, nazev, clen,
            cil=flask.url_for("_skupiny_seznam", group=nazev),
        )

    @app.post("/groups/<nazev>/member/<clen>/remove")
    @prihlasen
    def _skupiny_clen_odebrat(nazev, clen):
        return _skupiny_mutace(
            flask.g.store.remove_member, nazev, clen,
            cil=flask.url_for("_skupiny_seznam", group=nazev),
        )

    @app.post("/groups/<nazev>/chain")
    @prihlasen
    def _skupiny_zretezit(nazev):
        zahrnuti = flask.request.form.get("zahrnuti", "")
        return _skupiny_mutace(
            flask.g.store.include, nazev, zahrnuti,
            cil=flask.url_for("_skupiny_seznam", group=nazev),
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

    @app.get("/applications")
    @prihlasen
    def _aplikace_seznam():
        aplikace = [_radek_aplikace(k) for k in flask.g.store.components()]
        return flask.render_template("aplikace.html", aplikace=aplikace)

    @app.post("/applications/add")
    @prihlasen
    def _aplikace_pridat():
        """Prvni krok: vznikne aplikace a klic. Rozsahy se pridavaji zvlast.

        Jedno pole na cárkami oddeleny seznam CIDR bylo nesrozumitelne a
        neslo z nej po zalozeni nic ubrat, aniz by se vymenil klic. Registrace
        proto rozsahy nebere; druhy krok (`_aplikace_rozsah_pridat`) je pridava
        po jednom a umi je i odebrat.
        """
        over_csrf()
        jmeno = flask.request.form.get("jmeno", "").strip()
        detail = flask.request.form.get("detail") == "on"
        try:
            klic = flask.g.store.register_component(
                jmeno, origins=(), detail=detail
            )
        except ValueError as chyba:
            flask.flash(f"{_prelozit('spolecne.error')}: {chyba}", "chyba")
            return flask.redirect(flask.url_for("_aplikace_seznam"))
        return _bez_ukladani(
            flask.render_template("klic.html", jmeno=jmeno, klic=klic)
        )

    def _aplikace_mutace(jmeno, akce):
        """Stejny tvar jako `_uzivatele_mutace`/`_skupiny_mutace`, jen bez
        volitelneho presmerovani - odvolani vzdy konci zpet na vypisu."""
        over_csrf()
        try:
            akce(jmeno)
        except ValueError as chyba:
            flask.flash(f"{_prelozit('spolecne.error')}: {chyba}", "chyba")
        else:
            flask.flash(_prelozit("spolecne.done"), "ok")
        return flask.redirect(flask.url_for("_aplikace_seznam"))

    @app.post("/applications/<jmeno>/revoke")
    @prihlasen
    def _aplikace_odvolat(jmeno):
        return _aplikace_mutace(jmeno, flask.g.store.revoke_component)

    @app.post("/applications/<jmeno>/detail")
    @prihlasen
    def _aplikace_detail(jmeno):
        # Cilovy stav chodi formularem, ne prepinacem "obrat to": dva
        # soubezne otevrene vypisy by se jinak prehazovaly navzajem.
        chce = flask.request.form.get("detail") == "on"
        return _aplikace_mutace(
            jmeno, lambda n: flask.g.store.set_detail(n, chce)
        )

    def _aplikace_rozsah(jmeno, akce):
        """Spolecny tvar pro pridani i odebrani rozsahu.

        Rozsah chodi FORMULAREM, ne v ceste: CIDR obsahuje lomitko a v ceste
        by se rozpadl na dva segmenty. Jmeno uz v ceste byt MUZE - formular
        stoji primo v radku sve aplikace, takze cil je dany radkem a nevybira
        se ze seznamu. Drive tu seznam byl a jmeno muselo chodit s nim.
        """
        over_csrf()
        rozsah = flask.request.form.get("rozsah", "").strip()
        if not jmeno or not rozsah:
            flask.flash(
                f"{_prelozit('spolecne.error')}: {_prelozit('aplikace.range_empty')}",
                "chyba",
            )
            return flask.redirect(flask.url_for("_aplikace_seznam"))
        try:
            akce(jmeno, rozsah)
        except ValueError as chyba:
            flask.flash(f"{_prelozit('spolecne.error')}: {chyba}", "chyba")
        else:
            flask.flash(_prelozit("spolecne.done"), "ok")
        return flask.redirect(flask.url_for("_aplikace_seznam"))

    @app.post("/applications/<jmeno>/ranges/add")
    @prihlasen
    def _aplikace_rozsah_pridat(jmeno):
        return _aplikace_rozsah(jmeno, flask.g.store.add_origin)

    @app.post("/applications/<jmeno>/ranges/remove")
    @prihlasen
    def _aplikace_rozsah_odebrat(jmeno):
        return _aplikace_rozsah(jmeno, flask.g.store.remove_origin)

    # == spravci ==============================================================
    #
    # Zrcadli uzivatele (`_uzivatele_mutace`/`_radek_cloveka`), jen bez "zakazany" -
    # spravci nemaji disable_admin/enable_admin, takze ten stav pro ne
    # neexistuje. `qr.html` je SDILENA s uzivateli - `_spravci_qr` je tenka route
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
            stav, stav_text = "no_credential", _prelozit("uzivatele.no_credential")
        elif vydano.is_file() and not sparovano.is_file():
            if store.enrolment_expired(adresar):
                # Viz `_radek_cloveka` - stejna past s "plati jeste 0 dni".
                stav = "expired"
                stav_text = _prelozit("uzivatele.expired")
            else:
                stav = "waiting"
                stav_text = _prelozit("uzivatele.waiting").format(
                    dni=store.enrolment_days_left(adresar)
                )
        else:
            stav, stav_text = "active", _prelozit("spravci.paired")
        return {
            "jmeno": jmeno, "stitek": f"{store.realm}-admin-{jmeno}",
            "stav": stav, "stav_text": stav_text,
            "vydano": _razitko(vydano),
            "sparovano": _razitko(sparovano),
        }

    @app.get("/admins")
    @prihlasen
    def _spravci_seznam():
        store = flask.g.store
        jmena = store.admins()
        spravci = [_radek_spravce(store, jmeno) for jmeno in jmena]
        # Jeden pruchod auditem pro celou stranku - viz `_uzivatele_seznam`.
        # Lisi se jen prefix subjektu: spravce a clen stejneho jmena jsou
        # dve ruzne identity (viz `Enrolment.principal`).
        prihlaseni = recent_by_subject(
            store.home,
            [f"admin:{jmeno}" for jmeno in jmena],
            kind="authenticate",
            limit=_POSLEDNICH_PRIHLASENI,
        )
        for radek in spravci:
            radek["prihlaseni"] = [
                _radek_prihlaseni(u)
                for u in prihlaseni.get(f"admin:{radek['jmeno']}", ())
            ]
        return flask.render_template("spravci.html", spravci=spravci)

    def _spravci_mutace(jmeno, akce, presmerovani=None):
        """Stejny tvar jako `_uzivatele_mutace` - CSRF -> knihovni volani -> flash ->
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

    @app.post("/admins/add")
    @prihlasen
    def _spravci_pridat():
        jmeno = flask.request.form.get("jmeno", "")
        return _spravci_mutace(
            jmeno, flask.g.store.add_admin,
            presmerovani=lambda zavedeni: flask.url_for(
                "_spravci_qr", jmeno=zavedeni.name
            ),
        )

    @app.post("/admins/<jmeno>/remove")
    @prihlasen
    def _spravci_odebrat(jmeno):
        return _spravci_mutace(jmeno, flask.g.store.remove_admin)

    @app.post("/admins/<jmeno>/revoke")
    @prihlasen
    def _spravci_odvolat(jmeno):
        return _spravci_mutace(jmeno, flask.g.store.revoke_admin_credential)

    @app.post("/admins/<jmeno>/pair")
    @prihlasen
    def _spravci_parovat(jmeno):
        return _spravci_mutace(
            jmeno, flask.g.store.pair_admin,
            presmerovani=lambda zavedeni: flask.url_for(
                "_spravci_qr", jmeno=zavedeni.name
            ),
        )

    @app.get("/admins/qr/<jmeno>")
    @prihlasen
    def _spravci_qr(jmeno):
        # Stejna uvaha jako u `_uzivatele_qr`: jmeno overit DRIV, nez se ceho na
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
        # Vyprsele zavedeni uz `authenticate` odmita (`expired`) - ukazovat
        # k nemu dal QR a tajemstvi znamena posilat cloveka opsat neco, co
        # mu stejne neprojde. Artefakty na disku zustavaji; skryva se jen
        # jejich zobrazeni, dokud nekdo nevyda nove.
        vyprselo = store.enrolment_expired(adresar)
        stitek = f"{store.realm}-admin-{jmeno}"
        # Tyz obsah jako QR, jen k opsani - kdo sedi u konzole a nema cim
        # skenovat, jinak nema jak zavedeni dokoncit.
        uri, secret = _zavedeni_k_opsani(adresar)
        return _bez_ukladani(flask.render_template(
            "qr.html", jmeno=jmeno, obrazec=obrazec, sparovano=sparovano,
            vyprselo=vyprselo, stitek=stitek, uri=uri, secret=secret,
            zpet=flask.url_for("_spravci_seznam"),
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
        # `component` uz do "kdo" NEPATRI - ma vlastni sloupec. Zustava
        # subjekt (koho se ptalo) nebo akter (kdo zapsal); pozadavek odmitnuty
        # origin ACL zadneho nema, protoze padl driv, nez do hry vstoupila
        # jakakoli identita.
        kdo = udalost.get("subject") or udalost.get("actor") or "—"
        return {
            "cas": udalost.get("t", ""),
            "udalost": udalost_text,
            "kdo": kdo,
            # Chybejici pole je pomlcka, ne prazdno: lokalni volani adresu
            # nema a prazdna bunka by vypadala jako rozbite vykresleni.
            "odkud": udalost.get("origin") or "—",
            "aplikace": udalost.get("component") or "—",
            "key_id": udalost.get("key_id", ""),
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
        # Jmena MUSI sedet s `name=` ve formulari (audit.html). Drive tu
        # stalo "from"/"to"/"subject", zatimco formular posilal
        # "od"/"do"/"subjekt" - tri z peti filtru proto tise nedelaly nic
        # a datova pole se po odeslani vracela na vychozi rozsah.
        od = _validni_den(flask.request.args.get("od", "")) or vychozi_od
        do = _validni_den(flask.request.args.get("do", "")) or vychozi_do
        # `.lower()` jako u filtru nad vypisem lidi - `read_events` porovnava
        # podretezec proti male variante, takze dotaz musi prijit stejne.
        kdo = flask.request.args.get("kdo", "").strip().lower() or None
        kind = flask.request.args.get("kind", "").strip() or None
        odkud = flask.request.args.get("odkud", "").strip() or None
        aplikace = flask.request.args.get("aplikace", "").strip() or None
        outcome = flask.request.args.get("outcome", "").strip() or None
        udalosti = read_events(
            store.home, day_from=od, day_to=do,
            who=kdo, outcome=outcome, kind=kind,
            origin=odkud, component=aplikace,
        )
        # Nejnovejsi nahoru - `read_events` vraci chronologicky (soubor po
        # souboru, radek po radku), coz je pro cteni logu pozpatku.
        radky = [_radek_udalosti(u) for u in reversed(udalosti)]
        return flask.render_template(
            "audit.html", udalosti=radky, od=od, do=do,
            kdo=kdo or "", kind=kind or "", outcome=outcome or "",
            odkud=odkud or "", aplikace=aplikace or "",
        )

    return app
