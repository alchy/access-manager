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
import re
import secrets
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .. import log
from ..audit import odpovida, read_events, recent_by
from ..config import ServiceConfig
from ..files import FileStore
from ..origin import resolve_origin
from ..principals import AUTOMATIC_GROUPS, check_identity, check_name, check_realm
from ..realms import realm_root
from . import audit_views, preklady

#: Sablony jsou soucasti balicku - Flask by je jinak hledal relativne k cwd,
#: ktery se pri spusteni sluzby muze lisit od umisteni modulu.
_TEMPLATES = Path(__file__).parent / "templates"

#: Kam smi `/lang` presmerovat: cesta na TOMTO serveru a nic jineho. Zacina
#: jednim lomitkem, za nim nesmi byt druhe lomitko ani zpetne lomitko, a cela
#: se sklada jen z tisknutelnych znaku ASCII bez mezery a bez zpetneho lomitka.
#: Samotny test "zacina '/' a ne '//'" nestacil: tabulator a konec radku
#: prohlizec z adresy vypusti, takze z "/<TAB>/cizi.example" je
#: "//cizi.example" - tedy cizi server. Konec radku navic shodil odpoved na
#: 500. Stranky konzole si `next` skladaji z `request.full_path`, ktery je
#: zakodovany do ASCII, takze poctive cile tudy projdou vsechny.
_LOCAL_PATH = re.compile(r"/(?![/\\])[\x21-\x5b\x5d-\x7e]*")


def _local_target(target: str) -> str:
    """`target`, je-li to cesta na tomto serveru; jinak uvodni stranka."""
    return target if _LOCAL_PATH.fullmatch(target) else "/"


#: Vychozi sirka okna auditu bez filtru - "nedavne udalosti", ne cela
#: historie (retence je typicky 90 dni, cely vypis by byl neprehledny).
_AUDIT_DEFAULT_DAYS = 7

#: Kolik udalosti ukaze roletka u cloveka, spravce i aplikace ve vypisu. Je
#: to "co se delo naposled", ne historie - na tu je stranka auditu s filtrem.
_RECENT_LIMIT = 5


def _enrolment_text(directory: Path) -> tuple[str | None, str | None]:
    """Vrat (uri, tajemstvi) k rucnimu opsani, nebo (None, None).

    Cte se `totp.uri`, NIKDY `totp.secret` - a je to zamer. Parovanim se
    `totp.uri` i `totp.txt` mazou (`_complete_pairing`), zatimco tajemstvi
    zustava a overuje dal: "mizi jen jeho zobrazitelna podoba". Kdyby se
    string bral z `totp.secret`, tahle podoba by se po sparovani vratila -
    presne to, co mazani artefaktu ma zarusit. Takhle ma string TOTOZNOU
    zivotnost jako QR vedle nej.
    """
    path = directory / "totp.uri"
    if not path.is_file():
        return None, None
    uri = path.read_text(encoding="utf-8").strip()
    values = parse_qs(urlparse(uri).query).get("secret")
    return uri, (values[0] if values else None)


def _require_flask():
    """Vrat `flask`, nebo rekni JAK to doinstalovat."""
    try:
        import flask
    except ImportError as missing:
        raise RuntimeError(
            "konzole potrebuje flask: pip install 'access-manager[server]'"
        ) from missing
    return flask


#: Kolik cislic ma jeden TOTP kod. Sablona podle toho vykresli policka.
CODE_LENGTH = 6


def _code_from_form(form, field: str) -> str:
    """Slozi kod bud z jednoho pole, nebo z policek po cislicich.

    Prihlasovaci stranka vykresluje policko na kazdou cislici
    (`kod1_1`..`kod1_6`), protoze se to lip opisuje z telefonu. Jedno pole
    s celym kodem ale zustava platne - posilaji ho testy i kdokoli, kdo si
    formular odesle sam. Bere se to, co prislo; cele pole ma prednost.
    """
    whole = form.get(field, "").strip()
    if whole:
        return whole
    return "".join(
        form.get(f"{field}_{i}", "").strip() for i in range(1, CODE_LENGTH + 1)
    )


#: Jadra prohlizecu v poradi, v jakem se musi zkouset. Poradi neni libovolne:
#: Edge i Opera nesou v UA retezci taky "Chrome", Chrome zase "Safari" - kdo
#: hleda obecnejsi znacku driv, oznaci Edge za Chrome a Safari za cokoli.
_ENGINES = (
    ("Firefox/", "Firefox (Gecko)"),
    ("Edg/", "Edge (Blink)"),
    ("OPR/", "Opera (Blink)"),
    ("Chrome/", "Chrome (Blink)"),
    ("Safari/", "Safari (WebKit)"),
    ("curl/", "curl"),
    ("Wget/", "Wget"),
)


def _browser(ua: str) -> str:
    """Jadro prohlizece z hlavicky User-Agent, nebo prazdno.

    Nechceme presnou identifikaci - UA retezec je notoricky lzivy a nic se
    podle nej nerozhoduje. Je to jen informace pro cloveka u obrazovky:
    "prihlasuju se odsud a timhle". Nezname UA se radeji nehada.
    """
    for marker, name in _ENGINES:
        if marker in ua:
            return name
    return ""


def _realm_store_kwargs(cfg: ServiceConfig) -> dict[str, dict]:
    """Konstrukcni argumenty `FileStore` pro kazdy realm z `cfg`.

    Zrcadli konstrukci v `server.create_app` - misto hotovych instanci se ale
    drzi jen argumenty, protoze kazdy pozadavek potrebuje `FileStore` s
    vlastnim `actor` (viz `login_required`).
    """
    kwargs: dict[str, dict] = {}
    seen: set[str] = set()
    for declaration in cfg.realms:
        if "name" not in declaration:
            raise ValueError(f"deklarace realmu bez jmena: {declaration!r}")
        name = check_realm(declaration["name"])
        if name in seen:
            msg = f"realm {name!r} je deklarovany dvakrat; konflikt zavira start"
            raise ValueError(msg)
        seen.add(name)
        kwargs[name] = {
            "root": realm_root(cfg.data, name),
            "realm": name,
            "qr_ttl_days": int(
                declaration.get("qr_ttl_days", cfg.defaults["qr_ttl_days"])
            ),
            "audit_retention_days": int(
                declaration.get(
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
    tuhle tovarnu stavi dal - pridavaji route a pouzivaji `login_required`.
    """
    flask = _require_flask()

    realms = _realm_store_kwargs(cfg)

    def _store_for(realm_name: str, actor: str) -> FileStore:
        # Adresa spravce jde s aktorem do kazde udalosti, kterou uloziste
        # jeho jmenem zapise - zapisy, relace. Meri se stejne jako u API
        # a prihlaseni (resolve_origin), ne z holeho remote_addr.
        params = dict(realms[realm_name])
        root = params.pop("root")
        return FileStore(
            root, actor=actor,
            origin=resolve_origin(flask.request.environ, cfg), **params,
        )

    app = flask.Flask(__name__, template_folder=str(_TEMPLATES))
    log.adopt(app.logger)
    # Restart = odhlaseni vsech spravcu - zamer, ne nedopatreni. Zadne
    # tajemstvi se nikam neuklada, klic zije jen po dobu behu procesu.
    app.secret_key = secrets.token_hex(32)
    # HttpOnly je flaskovy vychozi stav - jen SameSite je potreba rict sami.
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    # Vychozi False (viz config.py) - za TLS terminujici proxy si to
    # provozovatel zapne (spec §3, konfigurace console_secure_cookie).
    app.config["SESSION_COOKIE_SECURE"] = cfg.console_secure_cookie

    def _translate(key: str) -> str:
        catalog = preklady.nacti(flask.session.get("lang", "cs"))
        return preklady.prelozit(catalog, key)

    def verify_csrf() -> None:
        """Kazda mutace nese `csrf` shodny se session, jinak 400 a zadny zapis.

        POST /login je vyjimka: session (a tedy token) jeste neexistuje, takze
        se overuje az od prvni mutace PO prihlaseni (napr. /logout). Porovnani
        je casove konstantni (`secrets.compare_digest`) - drive nez se na nej
        dostane, jsou oba chybejici stavy (nic poslano/nic v session) osetreny
        rovnou abortem. Porovnavaji se BAJTY: na textu s ne-ASCII znakem
        `compare_digest` nevrati False, ale hodi TypeError, a z odmitnuti by
        byla chyba 500 bez zaznamu v auditu.
        """
        sent = flask.request.form.get("csrf")
        stored = flask.session.get("csrf")
        if not sent or not stored or not secrets.compare_digest(
            sent.encode("utf-8"), stored.encode("utf-8")
        ):
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
    def _save_language():
        # Prepinac funguje na kterekoli strance, ne jen na /login - staci
        # pridat ?lang=cs|en do libovolneho GETu.
        lang = flask.request.args.get("lang")
        if lang in ("cs", "en"):
            flask.session["lang"] = lang

    @app.context_processor
    def _translation_context():
        return {"t": _translate, "code_length": CODE_LENGTH}

    def login_required(view):
        """Strazce relace: bez platne session presmeruje na `/login`.

        Zaroven priprav g.store s actor odvozenym od prihlaseneho spravce -
        pouziva se jen uvnitr chranenych view, ne v `/login` samotnem.
        """

        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            realm_name = flask.session.get("realm")
            admin = flask.session.get("admin")
            if not admin or realm_name not in realms:
                return flask.redirect(flask.url_for("_login_page"))
            store = _store_for(realm_name, actor=f"admin:{admin}")
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
                return flask.redirect(flask.url_for("_login_page"))
            flask.g.store = store
            return view(*args, **kwargs)

        return wrapper

    def _no_store(result):
        """Obal render_template odpovedi hlavickou `Cache-Control: no-store`.

        Pro stranky, ktere nesou tajemstvi presne jednou (QR kod, klic
        aplikace) - bez tehle hlavicky by je sdilena mezipamet (proxy,
        prohlizec pri Zpet/Vpred) mohla ulozit a zobrazit znovu i po tom,
        co uz je clovek nema videt.
        """
        response = flask.make_response(result)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/lang")
    def _language():
        """Prepinac jazyka, ktery umi presmerovat ZPET na puvodni stranku.

        Doplnuje starsi mechanismus `?lang=cs|en` (viz `_save_language`), ktery
        na strankach vyrenderovanych primo z POST (key.html) skonci 405
        (jina metoda) a na strankach s vlastnim dotazem (filtrovany /audit,
        /groups?group=...) dotaz zahodi. `next` se pousti dal JEN kdyz je
        to cesta na tomto serveru (viz `_LOCAL_PATH`) - '//host/...' i
        '/<TAB>/host' by prohlizec vzal jako adresu ciziho serveru.
        """
        to = flask.request.args.get("to")
        if to in ("cs", "en"):
            flask.session["lang"] = to
        next_url = flask.request.args.get("next", "")
        return flask.redirect(_local_target(next_url))

    def _access_context() -> dict:
        """Odkud a cim se clovek diva - vypisuje se pod prihlasovacim formularem.

        Adresa je TA SAMA, kterou meri origin ACL a audit (resolve_origin),
        ne holy remote_addr. Kdyz se tady objevi adresa proxy misto klienta,
        je spatne nastavene trusted_proxies/hops - a je to videt hned, ne az
        z auditu za tri mesice.
        """
        return {
            "client_ip": resolve_origin(flask.request.environ, cfg),
            "client_browser": _browser(
                flask.request.headers.get("User-Agent", "")
            ),
        }

    @app.get("/login")
    def _login_page():
        return flask.render_template("login.html", **_access_context())

    @app.post("/login")
    def _login():
        # POST /login je pred existenci session - neni co porovnat s CSRF
        # tokenem, takze se tady verify_csrf() zamerne nevola (viz jeho
        # docstring). Neznamy realm i spatne kody hlasi TOTOZNOU hlasku -
        # zadny postranni kanal, ktery by prozradil, ze realm neexistuje.
        realm_name = flask.request.form.get("realm", "")
        name = flask.request.form.get("jmeno", "")
        code1 = _code_from_form(flask.request.form, "kod1")
        code2 = _code_from_form(flask.request.form, "kod2")
        # Puvod se meri stejne jako u API a auditu (resolve_origin), ne z
        # holeho remote_addr - jinak by log za proxy ukazoval proxy.
        origin = resolve_origin(flask.request.environ, cfg)

        # Normalizace DRIV, nez se cokoli porovna nebo ulozi do session:
        # authenticate_admin normalizuje jmeno pres check_identity uvnitr
        # sebe, ale strazce (login_required) porovnava syrove session["admin"]
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
            realm_name = check_realm(realm_name)
            name = check_identity(name)
        except ValueError:
            log.info(
                "console_login", outcome="denied", reason="bad_form",
                origin=origin, realm=realm_name, name=name,
            )
            return flask.render_template(
                "login.html", error=_translate("login.failed"), **_access_context()
            )

        if realm_name not in realms:
            log.info(
                "console_login", outcome="denied", reason="unknown_realm",
                origin=origin, realm=realm_name, name=name,
            )
            return flask.render_template(
                "login.html", error=_translate("login.failed"), **_access_context()
            )

        # Odsud dal je realm znamy - vsechno ostatni (ok, bad_code, replay,
        # throttled, ...) zapise do auditu `authenticate_admin`. Do provozniho
        # logu uz to NEJDE: dve mista teze udalosti by se musela drzet
        # v souladu a jedno z nich by pritom rotace zahodila.

        store = _store_for(realm_name, actor=f"admin:{name}")
        verdict = store.authenticate_admin(name, code1, code2, origin=origin)

        if verdict.outcome == "throttled":
            error = _translate("login.throttled").format(s=verdict.retry_after)
            return flask.render_template(
                "login.html", error=error, **_access_context()
            )
        if not verdict:
            return flask.render_template(
                "login.html", error=_translate("login.failed"), **_access_context()
            )

        # Cista relace: zadny stav z doby pred prihlasenim (treba rozdelane
        # necekane klice) neprezije do prihlasene session - jen jazyk se
        # vedome prenese.
        lang = flask.session.get("lang", "cs")
        flask.session.clear()
        flask.session["realm"] = realm_name
        flask.session["admin"] = name
        flask.session["lang"] = lang
        flask.session["csrf"] = secrets.token_hex(16)
        return flask.redirect(flask.url_for("_home"))

    @app.post("/logout")
    @login_required
    def _logout():
        verify_csrf()
        flask.g.store.audit_event(
            kind="session", op="logout",
            actor=f"admin:{flask.session.get('admin')}",
        )
        flask.session.clear()
        return flask.redirect(flask.url_for("_login_page"))

    @app.get("/")
    @login_required
    def _home():
        return flask.redirect(flask.url_for("_users_list"))

    # == uzivatele ==========================================================
    #
    # VZOR pro dalsi stranky (skupiny/aplikace/spravci/audit): kazda mutace
    # je @login_required + POST, prvni radek je verify_csrf(), knihovni volani bezi
    # v try/except ValueError, uspech i chyba konci flashem a redirectem
    # (Post/Redirect/Get). `_users_mutation` tenhle tvar nese za vsechny
    # jednoduche akce - vyjimkou je jen `/users/add` s vlastnim GET view
    # (formular), ktere tu neni potreba.

    def _user_row(store, name: str) -> dict:
        """Jeden radek vypisu: stav (aktivni/zakazany/cekajici na parovani/
        bez povereni) a skupinove chipy z plocheho uzaveru principalu.

        Chipy nesou VSECHNY skupiny, ktere clovek ma - vcetne automatickych.
        Driv se `group:public` (a `group:users`) z vypisu vyhazovaly, takze
        spravce videl prazdno u cloveka, ktery tri principaly mel: pravo,
        o kterem se z konzole nedalo dozvedet. Automaticke se proto ukazuji,
        jen jsou odlisene `vychozi` - aby bylo poznat, ze se neprideluji
        a odebrat nejdou.

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
        user = store.user(name)
        # Vychozi napred, pak zbytek abecedne: automaticke skupiny jsou
        # kontext ("tohle ma kazdy"), prirazene jsou rozhodnuti spravce.
        groups = sorted(
            (
                {"name": group_name, "default": group_name in AUTOMATIC_GROUPS}
                for principal in user.principals
                if principal.startswith("group:")
                for group_name in (principal[len("group:"):],)
            ),
            key=lambda s: (not s["default"], s["name"]),
        )
        directory = store.home / f"user-{name}"
        if not user.enabled:
            state, state_text = "disabled", _translate("uzivatele.disabled")
        else:
            secret_file = directory / "totp.secret"
            issued = directory / "totp.issued"
            paired = directory / "totp.paired"
            if not secret_file.is_file() and not issued.is_file():
                state = "no_credential"
                state_text = _translate("uzivatele.no_credential")
            elif issued.is_file() and not paired.is_file():
                if store.enrolment_expired(directory):
                    # Bez tehle vetve spadne vyprsely token do "ceka"
                    # a vypise se jako "plati jeste 0 dni" - tedy jako by
                    # na nej porad slo cekat.
                    state = "expired"
                    state_text = _translate("uzivatele.expired")
                else:
                    state = "waiting"
                    state_text = _translate("uzivatele.waiting").format(
                        dni=store.enrolment_days_left(directory)
                    )
            else:
                state, state_text = "active", _translate("uzivatele.active")
        return {
            "name": name, "state": state, "state_text": state_text, "groups": groups,
            # Kdy bylo zavedeni vydano a kdy se spotrebovalo. `totp.paired`
            # pise `_complete_pairing` v okamziku PRVNIHO uspesneho prihlaseni
            # - je to tedy razitko prave toho pozadavku, ktery QR ze stranky
            # odebral. Nikam se to dopisovat nemusi, uz to na disku je.
            "issued_at": _file_stamp(directory / "totp.issued"),
            "paired_at": _file_stamp(directory / "totp.paired"),
        }

    def _file_stamp(path: Path) -> str | None:
        """Unixove razitko ze souboru jako `2026-10-01 16:12:05 UTC`, nebo None.

        `totp.issued` a `totp.paired` drzi cislo; konzole ukazuje kazdy cas
        v UTC a s oznacenim. Prevod je tady, at se v rozhrani nepotkaji dva
        tvary casu.
        Poskozeny soubor je "nevim" - stejna uvaha jako v
        `FileStore._enrolment_expired`, jen tam je fail-closed a tady staci
        neukazat nic.
        """
        if not path.is_file():
            return None
        try:
            stamp = int(path.read_text(encoding="utf-8").strip())
        except (ValueError, OSError):
            return None
        return audit_views.format_stamp(datetime.fromtimestamp(stamp, UTC))

    def _reason(event: dict) -> str:
        """Co stoji vedle vysledku: `reason`, u pozadavku aplikace HTTP stav.

        Radek `access` zadny `reason` nema - neuspech je tam 400/404 a to je
        ta informace, kterou clovek hleda. U uspechu se stav nepise, "200"
        vedle "ok" nerika nic.
        """
        if event.get("reason"):
            return str(event["reason"])
        if event.get("outcome") != "ok" and "status" in event:
            return str(event["status"])
        return ""

    def _request_text(event: dict) -> str:
        """Co aplikace chtela - sloupec roletky u aplikace.

        U overeni je to koho overovala, u ostatnich metoda a cesta. Klic je
        vpredu, protoze po vymene klice zustava jmeno aplikace stejne a bez
        nej by stary a novy klic v roletce splynuly.
        """
        if event.get("kind") == "authenticate":
            what = f"authenticate {event.get('subject') or ''}".strip()
        elif event.get("path"):
            what = " ".join(
                part for part in (event.get("method"), event["path"]) if part
            )
        else:
            what = event.get("kind", "")
        return " · ".join(part for part in (event.get("key_id"), what) if part)

    def _recent_row(event: dict, counterpart: str) -> dict:
        """Jeden radek roletky. Stejna ctverice a stejne tridy jako stranka
        auditu (`_event_row`) - je to tyz zaznam, jen uzsi vyber.

        Treti sloupec je "druha strana" udalosti: u cloveka aplikace, ktera
        se ptala, u aplikace to, na co se ptala.
        """
        outcome = event.get("outcome")
        if outcome == "ok":
            css_class = "vysledek-ok"
        elif outcome == "denied":
            css_class = "vysledek-denied"
        else:
            css_class = "vysledek-jiny"
        return {
            "time": audit_views.utc_stamp(event),
            # Chybejici pole je pomlcka, ne prazdno: lokalni volani adresu
            # nema (viz `FileStore.authenticate`) a prazdna bunka by vypadala
            # jako rozbite vykresleni.
            "origin": event.get("origin") or "—",
            "counterpart": counterpart or "—",
            "result_text": outcome or "",
            "result_class": css_class,
            "reason": _reason(event),
        }

    def _filter_names(names, query):
        """Podretezcovy filtr pres jmeno. Prazdny dotaz nefiltruje.

        Zamerne obycejny podretezec, ne prefix: spravce hleda "novak" a chce
        najit i "jan.novak@example.com".
        """
        if not query:
            return list(names)
        return [name for name in names if query in name]

    @app.get("/users")
    @login_required
    def _users_list():
        store = flask.g.store
        all_users = store.users()
        query = flask.request.args.get("q", "").strip().lower()
        # Filtruje se PRED stavbou radku. `_user_row` sahne kazde identite
        # na disk zvlast (stav poverni, zbyvajici platnost QR, skupiny), takze
        # u stovek identit je nefiltrovany vypis stovky cteni na jedno
        # zobrazeni - a vetsinu z nich pak nikdo necte.
        selected = _filter_names(all_users, query)
        users = [_user_row(store, name) for name in selected]
        # JEDEN pruchod auditem pro celou stranku, ne jeden na kazdeho -
        # `recent_by` cte od nejnovejsiho dne a konci, jakmile ma
        # kazdy dost. Az PO filtru, ze stejneho duvodu jako radky vyse.
        recent = recent_by(
            store.home, "subject",
            [f"user:{name}" for name in selected],
            kind="authenticate",
            limit=_RECENT_LIMIT,
        )
        for row in users:
            row["recent"] = [
                _recent_row(u, u.get("component"))
                for u in recent.get(f"user:{row['name']}", ())
            ]
        return flask.render_template(
            "users.html", users=users, query=query,
            total=len(all_users), shown=len(selected),
        )

    def _users_mutation(name, action, redirect_to=None):
        """Spolecny tvar mutaci lidi: CSRF -> knihovni volani -> flash ->
        redirect. `redirect_to(result)` urcuje cil PRI USPECHU (napr. na
        stranku QR) - vychozi je zpet na /users. Chyba vzdy konci na /users,
        `redirect_to` se pak nevola."""
        verify_csrf()
        listing = flask.url_for("_users_list")
        try:
            result = action(name)
        except ValueError as error:
            flask.flash(f"{_translate('spolecne.error')}: {error}", "chyba")
            return flask.redirect(listing)
        flask.flash(_translate("spolecne.done"), "ok")
        return flask.redirect(redirect_to(result) if redirect_to else listing)

    @app.post("/users/add")
    @login_required
    def _users_add():
        name = flask.request.form.get("jmeno", "")
        return _users_mutation(
            name, flask.g.store.add_user,
            redirect_to=lambda enrolment: flask.url_for(
                "_users_qr", name=enrolment.name
            ),
        )

    @app.post("/users/<name>/disable")
    @login_required
    def _users_disable(name):
        return _users_mutation(name, flask.g.store.disable_user)

    @app.post("/users/<name>/enable")
    @login_required
    def _users_enable(name):
        return _users_mutation(name, flask.g.store.enable_user)

    @app.post("/users/<name>/delete")
    @login_required
    def _users_delete(name):
        return _users_mutation(name, flask.g.store.remove_user)

    @app.post("/users/<name>/revoke")
    @login_required
    def _users_revoke(name):
        return _users_mutation(name, flask.g.store.revoke_credential)

    @app.post("/users/<name>/pair")
    @login_required
    def _users_pair(name):
        return _users_mutation(
            name, flask.g.store.pair,
            redirect_to=lambda enrolment: flask.url_for(
                "_users_qr", name=enrolment.name
            ),
        )

    @app.get("/users/qr/<name>")
    @login_required
    def _users_qr(name):
        # Jmeno se sklada do cesty na disku - overit DRIV, nez se ceho
        # dotkne, stejny vzorec jako knihovni metody (check_identity() prvni
        # radek). Zdeformovane jmeno je 404, ne 500 z divneho souboroveho
        # dotazu.
        try:
            name = check_identity(name)
        except ValueError:
            flask.abort(404)
        store = flask.g.store
        directory = store.home / f"user-{name}"
        path = directory / "totp.txt"
        qr_art = path.read_text(encoding="utf-8") if path.is_file() else None
        paired = (directory / "totp.paired").is_file()
        # Vyprsele zavedeni uz `authenticate` odmita (`expired`) - ukazovat
        # k nemu dal QR a tajemstvi znamena posilat cloveka opsat neco, co
        # mu stejne neprojde. Artefakty na disku zustavaji; skryva se jen
        # jejich zobrazeni, dokud nekdo nevyda nove.
        expired = store.enrolment_expired(directory)
        label = f"{store.realm}-member-{name}"
        # Tyz obsah jako QR, jen k opsani - kdo sedi u konzole a nema cim
        # skenovat, jinak nema jak zavedeni dokoncit.
        uri, secret = _enrolment_text(directory)
        return _no_store(flask.render_template(
            "qr.html", name=name, qr_art=qr_art, paired=paired,
            expired=expired, label=label, uri=uri, secret=secret,
            back_url=flask.url_for("_users_list"),
        ))

    # == skupiny =============================================================
    #
    # Na rozdil od `_users_mutation` bere `_groups_mutation` cil presmerovani
    # VZDY explicitne (`target=`) - mutace clenu/zretezeni maji po chybe
    # i po uspechu zustat na detailu prave upravovane skupiny, ne skocit
    # zpatky na holy vypis (jedina vyjimka je smazani skupiny samotne,
    # po kterem uz detail nedava smysl).

    def _group_row(store, name: str) -> dict:
        group = store.group(name)
        return {
            "name": name,
            "member_count": len(group.members),
            "include_count": len(group.includes),
        }

    def _group_detail(store, name: str) -> dict | None:
        """Detail jedne skupiny: prime cleny, zahrnute skupiny a kdo do ni
        patri jen pres zretezeni (uzaver principalu minus prime clenstvi -
        cteni bez zamku, stejne jako `_user_row`)."""
        group = store.group(name)
        if group is None:
            return None
        principal = f"group:{name}"
        via_chain = sorted(
            user_name for user_name in store.users()
            if user_name not in group.members
            and principal in store.user(user_name).principals
        )
        return {
            "name": name,
            "members": group.members,
            "includes": group.includes,
            "via_chain": via_chain,
            "member_candidates": [
                j for j in store.users() if j not in group.members
            ],
            "other_groups": [
                g for g in store.groups()
                if g != name and g not in group.includes
            ],
        }

    @app.get("/groups")
    @login_required
    def _groups_list():
        store = flask.g.store
        all_groups = store.groups()
        query = flask.request.args.get("q", "").strip().lower()
        selected = _filter_names(all_groups, query)
        groups = [_group_row(store, name) for name in selected]
        detail = None
        requested = flask.request.args.get("group")
        if requested:
            try:
                requested = check_name(requested)
            except ValueError:
                requested = None
            if requested:
                detail = _group_detail(store, requested)
        return flask.render_template(
            "groups.html", groups=groups, detail=detail, query=query,
            total=len(all_groups), shown=len(selected),
        )

    def _group_detail_url(name: str) -> str:
        """Vypis skupin s otevrenym detailem `name`, rovnou u jeho panelu.

        Kotva patri jen k USPECHU. Po chybe se presmerovava bez ni: hlaska
        stoji nahore nad vypisem a skok k panelu by ji odsunul z obrazu -
        spravce by videl jen to, ze se nic nestalo.
        """
        return flask.url_for("_groups_list", group=name, _anchor="group-detail")

    def _groups_mutation(action, *args, target, redirect_to=None):
        """Spolecny tvar mutaci skupin: CSRF -> knihovni volani -> flash ->
        redirect na `target` (chyba i vychozi uspech) nebo `redirect_to(result)`
        (uspech, kdyz ma jit jinam)."""
        verify_csrf()
        try:
            result = action(*args)
        except ValueError as error:
            flask.flash(f"{_translate('spolecne.error')}: {error}", "chyba")
            return flask.redirect(target)
        flask.flash(_translate("spolecne.done"), "ok")
        return flask.redirect(redirect_to(result) if redirect_to else target)

    @app.post("/groups/add")
    @login_required
    def _groups_add():
        name = flask.request.form.get("nazev", "")
        return _groups_mutation(
            flask.g.store.add_group, name,
            target=flask.url_for("_groups_list"),
            redirect_to=lambda _: _group_detail_url(name),
        )

    @app.post("/groups/<name>/delete")
    @login_required
    def _groups_delete(name):
        return _groups_mutation(
            flask.g.store.remove_group, name,
            target=flask.url_for("_groups_list"),
        )

    @app.post("/groups/<name>/member")
    @login_required
    def _groups_member_add(name):
        member = flask.request.form.get("clen", "")
        return _groups_mutation(
            flask.g.store.add_member, name, member,
            target=flask.url_for("_groups_list", group=name),
            redirect_to=lambda _: _group_detail_url(name),
        )

    @app.post("/groups/<name>/member/<member>/remove")
    @login_required
    def _groups_member_remove(name, member):
        return _groups_mutation(
            flask.g.store.remove_member, name, member,
            target=flask.url_for("_groups_list", group=name),
            redirect_to=lambda _: _group_detail_url(name),
        )

    @app.post("/groups/<name>/chain")
    @login_required
    def _groups_chain(name):
        included = flask.request.form.get("zahrnuti", "")
        return _groups_mutation(
            flask.g.store.include, name, included,
            target=flask.url_for("_groups_list", group=name),
            redirect_to=lambda _: _group_detail_url(name),
        )

    # == aplikace =============================================================
    #
    # Jedina stranka s vyjimkou z PRG: uspesna registrace vraci PLNY klic
    # PRAVE JEDNOU - misto redirectu se rovnou renderuje vysledkova sablona
    # `key.html` primo z teto POST odpovedi. Klic nikdy nejde do session ani
    # do flashe (obe jsou cookie - klic by tam byl navic a mohl by presahnout
    # limit velikosti cookie). Neuspech (napr. duplicitni jmeno) naopak
    # zustava na PRG + flash, presne jako u ostatnich stranek - znovunacteni
    # po chybe je bezpecne (dalsi pokus zase jen selze na duplicite).

    def _app_row(component) -> dict:
        return {
            "name": component.name,
            "key_id": component.key_id,
            "fingerprint": component.key_hash[:12],
            "origins": component.origins,
            "detail": component.detail,
        }

    @app.get("/applications")
    @login_required
    def _apps_list():
        store = flask.g.store
        apps = [_app_row(k) for k in store.components()]
        # Tataz roletka jako u lidi a spravcu, nad tymz auditem a stejnym
        # jednim pruchodem - jen se hleda podle `component` misto `subject`
        # a bez filtru na `kind`: aplikaci patri kazdy jeji pozadavek
        # (`authenticate`, `access`, `origin_denied`).
        usage = recent_by(
            store.home, "component",
            [row["name"] for row in apps],
            limit=_RECENT_LIMIT,
        )
        for row in apps:
            row["recent"] = [
                _recent_row(u, _request_text(u))
                for u in usage.get(row["name"], ())
            ]
        return flask.render_template("applications.html", apps=apps)

    @app.post("/applications/add")
    @login_required
    def _apps_add():
        """Prvni krok: vznikne aplikace a klic. Rozsahy se pridavaji zvlast.

        Jedno pole na cárkami oddeleny seznam CIDR bylo nesrozumitelne a
        neslo z nej po zalozeni nic ubrat, aniz by se vymenil klic. Registrace
        proto rozsahy nebere; druhy krok (`_apps_range_add`) je pridava
        po jednom a umi je i odebrat.
        """
        verify_csrf()
        name = flask.request.form.get("jmeno", "").strip()
        detail = flask.request.form.get("detail") == "on"
        try:
            key = flask.g.store.register_component(
                name, origins=(), detail=detail
            )
        except ValueError as error:
            flask.flash(f"{_translate('spolecne.error')}: {error}", "chyba")
            return flask.redirect(flask.url_for("_apps_list"))
        return _no_store(
            flask.render_template("key.html", name=name, key=key)
        )

    def _apps_mutation(name, action):
        """Stejny tvar jako `_users_mutation`/`_groups_mutation`, jen bez
        volitelneho presmerovani - odvolani vzdy konci zpet na vypisu."""
        verify_csrf()
        try:
            action(name)
        except ValueError as error:
            flask.flash(f"{_translate('spolecne.error')}: {error}", "chyba")
        else:
            flask.flash(_translate("spolecne.done"), "ok")
        return flask.redirect(flask.url_for("_apps_list"))

    @app.post("/applications/<name>/revoke")
    @login_required
    def _apps_revoke(name):
        return _apps_mutation(name, flask.g.store.revoke_component)

    @app.post("/applications/<name>/detail")
    @login_required
    def _apps_detail(name):
        # Cilovy stav chodi formularem, ne prepinacem "obrat to": dva
        # soubezne otevrene vypisy by se jinak prehazovaly navzajem.
        wanted = flask.request.form.get("detail") == "on"
        return _apps_mutation(
            name, lambda n: flask.g.store.set_detail(n, wanted)
        )

    def _apps_range(name, action):
        """Spolecny tvar pro pridani i odebrani rozsahu.

        Rozsah chodi FORMULAREM, ne v ceste: CIDR obsahuje lomitko a v ceste
        by se rozpadl na dva segmenty. Jmeno uz v ceste byt MUZE - formular
        stoji primo v radku sve aplikace, takze cil je dany radkem a nevybira
        se ze seznamu. Drive tu seznam byl a jmeno muselo chodit s nim.
        """
        verify_csrf()
        cidr = flask.request.form.get("rozsah", "").strip()
        if not name or not cidr:
            flask.flash(
                f"{_translate('spolecne.error')}: {_translate('aplikace.range_empty')}",
                "chyba",
            )
            return flask.redirect(flask.url_for("_apps_list"))
        try:
            action(name, cidr)
        except ValueError as error:
            flask.flash(f"{_translate('spolecne.error')}: {error}", "chyba")
        else:
            flask.flash(_translate("spolecne.done"), "ok")
        return flask.redirect(flask.url_for("_apps_list"))

    @app.post("/applications/<name>/ranges/add")
    @login_required
    def _apps_range_add(name):
        return _apps_range(name, flask.g.store.add_origin)

    @app.post("/applications/<name>/ranges/remove")
    @login_required
    def _apps_range_remove(name):
        return _apps_range(name, flask.g.store.remove_origin)

    # == spravci ==============================================================
    #
    # Zrcadli uzivatele (`_users_mutation`/`_user_row`), jen bez "zakazany" -
    # spravci nemaji disable_admin/enable_admin, takze ten stav pro ne
    # neexistuje. `qr.html` je SDILENA s uzivateli - `_admins_qr` je tenka route
    # nad stejnou sablonou, jen cte z `admin-<jmeno>` a posila jiny stitek
    # a jiny "zpet" cil.

    def _admin_row(store, name: str) -> dict:
        """Jeden radek vypisu spravcu: stitek pro parovani a stav.

        Tri stavy, v tomto poradi (stejna uvaha jako `_user_row`, jen bez
        vetve "zakazany" - ta pro spravce v konzoli neexistuje):
        - bez povereni: zadne `totp.secret` ani `totp.issued` - typicky po
          `revoke_admin_credential`, pred novym parovanim.
        - ceka na parovani: `totp.issued` je, `totp.paired` jeste neni.
        - sparovano: zbytek (typicky `totp.paired`) - vizualne stejna trida
          jako "aktivni" u lidi (`stav-active`), text z `spravci.paired`.
        """
        directory = store.home / f"admin-{name}"
        secret_file = directory / "totp.secret"
        issued = directory / "totp.issued"
        paired = directory / "totp.paired"
        if not secret_file.is_file() and not issued.is_file():
            state, state_text = "no_credential", _translate("uzivatele.no_credential")
        elif issued.is_file() and not paired.is_file():
            if store.enrolment_expired(directory):
                # Viz `_user_row` - stejna past s "plati jeste 0 dni".
                state = "expired"
                state_text = _translate("uzivatele.expired")
            else:
                state = "waiting"
                state_text = _translate("uzivatele.waiting").format(
                    dni=store.enrolment_days_left(directory)
                )
        else:
            state, state_text = "active", _translate("spravci.paired")
        return {
            "name": name, "label": f"{store.realm}-admin-{name}",
            "state": state, "state_text": state_text,
            "issued_at": _file_stamp(issued),
            "paired_at": _file_stamp(paired),
        }

    @app.get("/admins")
    @login_required
    def _admins_list():
        store = flask.g.store
        names = store.admins()
        admins = [_admin_row(store, name) for name in names]
        # Jeden pruchod auditem pro celou stranku - viz `_users_list`.
        # Lisi se jen prefix subjektu: spravce a clen stejneho jmena jsou
        # dve ruzne identity (viz `Enrolment.principal`).
        recent = recent_by(
            store.home, "subject",
            [f"admin:{name}" for name in names],
            kind="authenticate",
            limit=_RECENT_LIMIT,
        )
        for row in admins:
            row["recent"] = [
                _recent_row(u, u.get("component"))
                for u in recent.get(f"admin:{row['name']}", ())
            ]
        return flask.render_template("admins.html", admins=admins)

    def _admins_mutation(name, action, redirect_to=None):
        """Stejny tvar jako `_users_mutation` - CSRF -> knihovni volani -> flash ->
        redirect. Guard posledniho spravce (`_require_not_last_admin`) hlasi
        `ValueError` s presnym textem z knihovny, zobrazenym surove."""
        verify_csrf()
        try:
            result = action(name)
        except ValueError as error:
            flask.flash(f"{_translate('spolecne.error')}: {error}", "chyba")
            return flask.redirect(flask.url_for("_admins_list"))
        flask.flash(_translate("spolecne.done"), "ok")
        target = (
            redirect_to(result) if redirect_to
            else flask.url_for("_admins_list")
        )
        return flask.redirect(target)

    @app.post("/admins/add")
    @login_required
    def _admins_add():
        name = flask.request.form.get("jmeno", "")
        return _admins_mutation(
            name, flask.g.store.add_admin,
            redirect_to=lambda enrolment: flask.url_for(
                "_admins_qr", name=enrolment.name
            ),
        )

    @app.post("/admins/<name>/remove")
    @login_required
    def _admins_remove(name):
        return _admins_mutation(name, flask.g.store.remove_admin)

    @app.post("/admins/<name>/revoke")
    @login_required
    def _admins_revoke(name):
        return _admins_mutation(name, flask.g.store.revoke_admin_credential)

    @app.post("/admins/<name>/pair")
    @login_required
    def _admins_pair(name):
        return _admins_mutation(
            name, flask.g.store.pair_admin,
            redirect_to=lambda enrolment: flask.url_for(
                "_admins_qr", name=enrolment.name
            ),
        )

    @app.get("/admins/qr/<name>")
    @login_required
    def _admins_qr(name):
        # Stejna uvaha jako u `_users_qr`: jmeno overit DRIV, nez se ceho na
        # disku dotkne - zdeformovane jmeno je 404, ne 500.
        try:
            name = check_identity(name)
        except ValueError:
            flask.abort(404)
        store = flask.g.store
        directory = store.home / f"admin-{name}"
        path = directory / "totp.txt"
        qr_art = path.read_text(encoding="utf-8") if path.is_file() else None
        paired = (directory / "totp.paired").is_file()
        # Vyprsele zavedeni uz `authenticate` odmita (`expired`) - ukazovat
        # k nemu dal QR a tajemstvi znamena posilat cloveka opsat neco, co
        # mu stejne neprojde. Artefakty na disku zustavaji; skryva se jen
        # jejich zobrazeni, dokud nekdo nevyda nove.
        expired = store.enrolment_expired(directory)
        label = f"{store.realm}-admin-{name}"
        # Tyz obsah jako QR, jen k opsani - kdo sedi u konzole a nema cim
        # skenovat, jinak nema jak zavedeni dokoncit.
        uri, secret = _enrolment_text(directory)
        return _no_store(flask.render_template(
            "qr.html", name=name, qr_art=qr_art, paired=paired,
            expired=expired, label=label, uri=uri, secret=secret,
            back_url=flask.url_for("_admins_list"),
        ))

    # == audit ================================================================
    #
    # Jedina ciste GET stranka konzole: cte auditni stopu (`read_events`),
    # nic nemutuje - zadny CSRF. Kazde pole udalosti se cte tolerantne pres
    # `.get` - rucne poskozeny/kusy radek (napr. jen {"t": ..., "kind":
    # "weird"}) nesmi stranku shodit, jen se zobrazi prazdne/surove.

    def _valid_day(text: str) -> str | None:
        """`text` jako 'RRRR-MM-DD', jinak None (= pouzij vychozi den).

        HTML date input muze dorazit prazdny nebo rucne poskozeny (upraveny
        dotaz v adresnim radku primo) - nikdy nesmi shodit stranku, jen se
        tise nahradi vychozim oknem.
        """
        if not text:
            return None
        try:
            day = datetime.strptime(text, "%Y-%m-%d").date()
        except ValueError:
            return None
        # Kanonicky tvar, ne puvodni text: `strptime` vezme i "2026-1-5",
        # ale obdobi se porovnava se jmeny souboru jako retezec a tam by
        # "2026-1-5" neznamenalo paty leden.
        return day.isoformat()

    def _event_row(event: dict) -> dict:
        """Jeden radek auditu - vsechna pole tolerantne pres `.get`.

        Vysledek ma tri barvy: `ok` zelene, `denied` cervene (+ `reason`
        vedle), zapisy (`kind == "write"`, ktere `outcome` vubec nemaji)
        modre; cokoli jine (`need_factor`, `throttled`, chybejici) neutralne.
        Neznamy `kind` se do udalosti propise surove - zadny seznam znamych
        hodnot, zadna vyjimka.
        """
        kind = event.get("kind", "")
        outcome = event.get("outcome")
        if outcome == "ok":
            css_class, text = "vysledek-ok", outcome
        elif outcome == "denied":
            css_class, text = "vysledek-denied", outcome
        elif outcome:
            css_class, text = "vysledek-jiny", outcome
        elif kind == "write":
            css_class, text = "vysledek-write", kind
        else:
            css_class, text = "vysledek-jiny", ""
        event_text = " ".join(
            part for part in (
                kind,
                event.get("op") or event.get("purpose") or event.get("path"),
            ) if part
        )
        # `component` uz do "kdo" NEPATRI - ma vlastni sloupec. Zustava
        # subjekt (koho se ptalo) nebo akter (kdo zapsal); pozadavek odmitnuty
        # origin ACL zadneho nema, protoze padl driv, nez do hry vstoupila
        # jakakoli identita.
        who = event.get("subject") or event.get("actor") or "—"
        return {
            "time": audit_views.utc_stamp(event),
            "event": event_text,
            "who": who,
            # Chybejici pole je pomlcka, ne prazdno: lokalni volani adresu
            # nema a prazdna bunka by vypadala jako rozbite vykresleni.
            "origin": event.get("origin") or "—",
            "app": event.get("component") or "—",
            "key_id": event.get("key_id", ""),
            "result_text": text,
            "result_class": css_class,
            "reason": _reason(event),
        }

    # -- spolecne vsem auditnim pohledum -------------------------------------

    #: Rychle volby obdobi -> kolik dni zpet (vcetne dneska).
    _PERIODS = {"dnes": 1, "7": 7, "30": 30, "90": 90}

    def _utc_today() -> date:
        """Dnesek v UTC - tyz den, pod kterym audit prave zapisuje."""
        return datetime.now(UTC).date()

    def _period() -> tuple[str, str, str]:
        """(od, do, rychla volba) - dny jsou v UTC, stejne jako soubory auditu.

        Explicitni `od`/`do` z formulare maji prednost pred rychlou volbou.
        Volba, ktera obdobi presne odpovida, se oznaci i tehdy, kdyz prislo
        jako dvojice dat.
        """
        today = _utc_today()
        choice = flask.request.args.get("obdobi", "")
        days = _PERIODS.get(choice, _AUDIT_DEFAULT_DAYS)
        default_from = (today - timedelta(days=days - 1)).isoformat()
        # Jmena MUSI sedet s `name=` ve formulari. Drive tu stalo
        # "from"/"to"/"subject", zatimco formular posilal "od"/"do"/"subjekt"
        # - tri z peti filtru proto tise nedelaly nic.
        date_from = _valid_day(flask.request.args.get("od", "")) or default_from
        date_to = _valid_day(flask.request.args.get("do", "")) or today.isoformat()
        marked = ""
        if date_to == today.isoformat():
            for key, count in _PERIODS.items():
                if date_from == (today - timedelta(days=count - 1)).isoformat():
                    marked = key
        return date_from, date_to, marked

    def _period_events(store, date_from: str, date_to: str) -> list[dict]:
        """Vsechny udalosti obdobi, chronologicky, podle dne v UTC.

        Soubory auditu jsou po dnech v UTC a obdobi se vybira take v UTC,
        takze zvolene dny jsou primo soubory, ktere se prectou. Nic se
        neprepocitava a zadna udalost nepreskoci do sousedniho dne.
        """
        return read_events(store.home, day_from=date_from, day_to=date_to)

    def _link(**changes) -> str:
        """Tataz stranka se stejnymi filtry, jen se `changes` (None = pryc)."""
        # Parametry zacinajici podtrzitkem jsou pro `url_for` RIDICI
        # (`_external`, `_method`, `_scheme`, `_anchor`): z dotazu se do nej
        # nesmi dostat, jinak `?_method=POST` shodi stranku a `?_external=1`
        # prepise odkazy na absolutni.
        arguments = {
            key: value for key, value in flask.request.args.to_dict().items()
            if not key.startswith("_")
        }
        for key, value in changes.items():
            if value in (None, ""):
                arguments.pop(key, None)
            else:
                arguments[key] = value
        return flask.url_for(flask.request.endpoint, **arguments)

    def _filters(names) -> dict[str, str]:
        return {
            name: flask.request.args.get(name, "").strip().lower()
            for name in names
        }

    def _frame(view: str, events, date_from: str, date_to: str, period: str) -> dict:
        """Kontext hlavicky, ktery maji vsechny pohledy stejny."""
        return {
            "view": view, "counts": audit_views.counts(events),
            "date_from": date_from, "date_to": date_to, "period": period,
            "quick_periods": list(_PERIODS),
            "refreshed_at": audit_views.format_clock(datetime.now(UTC)),
            "link": _link,
            "detail_id": flask.request.args.get("detail", ""),
            "limit": audit_views.ROW_LIMIT,
        }

    def _detail(row) -> dict | None:
        if row is None:
            return None
        u = row["event"]
        return {
            "id": row["id"],
            "fields": audit_views.detail_fields(u, _translate),
            "raw": audit_views.raw_line(u),
            "count": row.get("count", 1),
            "since": row.get("since", ""),
        }

    # -- Spravci --------------------------------------------------------------

    @app.get("/audit/admins")
    @login_required
    def _audit_admins():
        store = flask.g.store
        date_from, date_to, period = _period()
        events = _period_events(store, date_from, date_to)
        filters = _filters(("spravce", "odkud", "co", "vysledek"))
        groups = audit_views.admin_groups(events, filters, _translate)
        today = _utc_today()
        total = sum(len(grp["rows"]) for grp in groups)
        entries, rendered, last_day = [], 0, None
        for group in groups:
            if rendered >= audit_views.ROW_LIMIT:
                break
            group_day = audit_views.utc_day(group["last"])
            if group_day != last_day:
                entries.append({
                    "day": audit_views.day_label(group_day, today, _translate),
                })
                last_day = group_day
            rows = group["rows"][: audit_views.ROW_LIMIT - rendered]
            rendered += len(rows)
            entries.append({
                "group": group,
                "header": audit_views.group_header(group, _translate),
                "rows": rows,
            })
        all_rows = [r for grp in groups for r in grp["rows"]]
        return flask.render_template(
            "audit_admins.html", entries=entries, filters=filters,
            total=total, rendered=rendered,
            detail=_detail(
                audit_views.find_row(all_rows, flask.request.args.get("detail"))
            ),
            **_frame("spravci", events, date_from, date_to, period),
        )

    # -- Uzivatele ------------------------------------------------------------

    @app.get("/audit/users")
    @login_required
    def _audit_users():
        store = flask.g.store
        date_from, date_to, period = _period()
        events = _period_events(store, date_from, date_to)
        filters = _filters(("uzivatel", "klient", "aplikace", "ucel", "vysledek"))
        rows = audit_views.user_rows(events, filters, _translate)
        today = _utc_today()
        return flask.render_template(
            "audit_users.html",
            entries=audit_views.with_days(
                rows[: audit_views.ROW_LIMIT], today, _translate
            ),
            filters=filters, total=len(rows),
            rendered=min(len(rows), audit_views.ROW_LIMIT),
            detail=_detail(
                audit_views.find_row(rows, flask.request.args.get("detail"))
            ),
            **_frame("uzivatele", events, date_from, date_to, period),
        )

    # -- Aplikace -------------------------------------------------------------

    @app.get("/audit/apps")
    @login_required
    def _audit_apps():
        store = flask.g.store
        date_from, date_to, period = _period()
        events = _period_events(store, date_from, date_to)
        filters = _filters(("aplikace", "klic", "odkud", "pozadavek", "vysledek"))
        rows = audit_views.app_rows(events, filters, _translate)
        today = _utc_today()
        return flask.render_template(
            "audit_apps.html",
            entries=audit_views.with_days(
                rows[: audit_views.ROW_LIMIT], today, _translate
            ),
            filters=filters, total=len(rows),
            rendered=min(len(rows), audit_views.ROW_LIMIT),
            detail=_detail(
                audit_views.find_row(rows, flask.request.args.get("detail"))
            ),
            **_frame("aplikace", events, date_from, date_to, period),
        )

    # -- Vse: puvodni tabulka pro vysetrovani napric -------------------------

    @app.get("/audit")
    @login_required
    def _audit_all():
        store = flask.g.store
        date_from, date_to, period = _period()
        events = _period_events(store, date_from, date_to)
        # `.lower()` jako u filtru nad vypisem lidi - `odpovida` porovnava
        # podretezec proti male variante, takze dotaz musi prijit stejne.
        who = flask.request.args.get("kdo", "").strip().lower() or None
        kind = flask.request.args.get("kind", "").strip() or None
        origin = flask.request.args.get("odkud", "").strip() or None
        component = flask.request.args.get("aplikace", "").strip() or None
        outcome = flask.request.args.get("outcome", "").strip() or None
        selected = [
            u for u in events
            if odpovida(u, who=who, outcome=outcome, kind=kind,
                        origin=origin, component=component)
        ]
        # Nejnovejsi nahoru - audit je chronologicky, coz je pro cteni logu
        # pozpatku.
        rows = [_event_row(u) for u in reversed(selected)]
        return flask.render_template(
            "audit.html", events=rows[: audit_views.ROW_LIMIT],
            total=len(rows), rendered=min(len(rows), audit_views.ROW_LIMIT),
            who=who or "", kind=kind or "", outcome=outcome or "",
            origin=origin or "", component=component or "",
            **_frame("vse", events, date_from, date_to, period),
        )

    return app
