"""Auditni pohledy konzole: kdo jednal, ne jaky je to radek.

Auditni stopa je jedna a na disku zustava, jak je. Tady se z ni stavi tri
pohledy podle toho, KDO jednal - spravce, uzivatel, aplikace - protoze kazdy
z nich odpovida na jinou otazku a ma jina pole:

    spravci    odkud byl pripojen, co menil, s jakym vysledkem
    uzivatele  odkud se prihlasil, pres kterou aplikaci, s jakym vysledkem
    aplikace   odkud sel pozadavek, ceho se tykal, s jakym vysledkem

Ctvrty pohled, "vse", je puvodni tabulka pro vysetrovani napric.

Jeden radek stopy smi byt ve dvou pohledech: overeni uzivatele pres API je
zaroven pozadavek aplikace. Na disku je jednou, pocita se v kazdem pohledu
zvlast.

Modul NEZNA flask - dostava udalosti a prekladovou funkci `t` a vraci
slovniky pro sablonu. Kazde pole udalosti se cte pres `.get`: rucne
pripsany nebo starsi radek (pred `origin` u zapisu, pred `range`) nesmi
stranku shodit, jen se ukaze s pomlckou.
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, date, datetime

VIEWS = ("spravci", "uzivatele", "aplikace", "vse")

#: Kolik radku pohled vykresli nejvys. Aplikace, ktera se pta kazdou minutu,
#: ma za tyden deset tisic radku; vic nez tohle se neda precist a jen by se
#: dlouho renderovalo. Zbytek je za filtrem.
ROW_LIMIT = 500

#: Operace, u kterych `origin` ve STARSICH zaznamech neznamena adresu
#: aktora, ale rozsah aplikace. Nove zaznamy maji rozsah v `range`.
_RANGE_OPS = ("add_origin", "remove_origin")

DASH = "—"

#: Slucovani je pro DOTAZOVANI (`/v1/generation` kazdou minutu), ne pro
#: samostatne udalosti. Samostatna overeni klice sloucit nesmi - kazde nove
#: by jen posunulo cas a pocet v jednom radku a vypadalo by to, ze nepribylo
#: nic (presne tak se schovalo sedm `whoami` aplikace soc za "7x od
#: 12:13:38"). Proto dve podminky: mezera mezi sousedy nejvys
#: `MERGE_GAP_S` a rada aspon `MIN_RUN` pozadavku. Dve rucni
#: overeni minutu po sobe jsou dva radky; rada deseti dotazu je jeden.
MERGE_GAP_S = 90
MIN_RUN = 3


# == trideni do pohledu =====================================================


def is_admin(u: dict) -> bool:
    kind = u.get("kind")
    if kind in ("write", "session"):
        return True
    return kind == "authenticate" and u.get("purpose") == "admin"


def is_user(u: dict) -> bool:
    return u.get("kind") == "authenticate" and u.get("purpose") != "admin"


def is_app(u: dict) -> bool:
    kind = u.get("kind")
    if kind in ("access", "origin_denied"):
        return True
    # Overeni patri aplikaci jen tehdy, kdyz o nej aplikace pozadala.
    # `Access.local` na serveru zadnou komponentu nema.
    return kind == "authenticate" and bool(u.get("component"))


BELONGS = {
    "spravci": is_admin,
    "uzivatele": is_user,
    "aplikace": is_app,
    "vse": lambda _event: True,
}


def counts(events) -> dict[str, int]:
    """Kolik udalosti obdobi patri kteremu pohledu - cisla na zalozkach."""
    result = dict.fromkeys(VIEWS, 0)
    for u in events:
        for view in VIEWS:
            if BELONGS[view](u):
                result[view] += 1
    return result


# == spolecne: cas, identita radku, vysledek ================================


#: Kazdy cas, ktery konzole vypise, je v UTC a nese to u sebe. Stejne to ma
#: SOC portal na temze serveru - spravce cte obe obrazovky vedle sebe a casy
#: musi jit porovnat bez prepocitavani. Pasmo procesu (TZ kontejneru) na
#: zobrazeni NEMA vliv.
UTC_LABEL = "UTC"


def utc_time(t) -> datetime | None:
    """ISO razitko z auditu jako cas v UTC, nebo None.

    Audit pise UTC a konzole ho v UTC i ukazuje - dny v hlavickach jsou
    tytez dny, podle kterych se jmenuji soubory `audit/RRRR-MM-DD.jsonl`.
    Razitko bez pasma (rucne pripsany radek) se bere jako UTC, protoze
    v auditu nic jineho byt nema.
    """
    if not isinstance(t, str) or not t:
        return None
    try:
        parsed = datetime.fromisoformat(t)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def format_clock(moment: datetime) -> str:
    """`16:12:05 UTC` - cas radku pod hlavickou dne."""
    return f"{moment.astimezone(UTC):%H:%M:%S} {UTC_LABEL}"


def format_stamp(moment: datetime) -> str:
    """`2026-10-01 16:12:05 UTC` - cas tam, kde nad radkem neni hlavicka dne."""
    return f"{moment.astimezone(UTC):%Y-%m-%d %H:%M:%S} {UTC_LABEL}"


def utc_clock(u: dict) -> str:
    """Cas udalosti jako `16:12:05 UTC`; necitelne razitko se ukaze surove."""
    moment = utc_time(u.get("t"))
    return format_clock(moment) if moment else str(u.get("t") or DASH)


def utc_stamp(u: dict) -> str:
    """Den i cas udalosti jako `2026-10-01 16:12:05 UTC`; necitelne surove."""
    moment = utc_time(u.get("t"))
    return format_stamp(moment) if moment else str(u.get("t") or DASH)


def utc_day(u: dict) -> date | None:
    """Den udalosti v UTC - tyz den, pod kterym lezi v auditni stope."""
    moment = utc_time(u.get("t"))
    return moment.date() if moment else None


def day_label(d: date | None, today: date, t) -> str:
    """"Dnes · pondeli 14. zari 2026 (UTC)", "Vcera · ...", jinak jen datum.

    `d` i `today` jsou dny v UTC a hlavicka to rika - "dnes" v UTC neni mezi
    pulnoci a druhou hodinou rano stredoevropskeho casu tyz den jako mistni.
    """
    if d is None:
        return DASH
    date_text = t("pohled.datum").format(
        den=t(f"pohled.den.{d.weekday()}"), d=d.day,
        mesic=t(f"pohled.mesic.{d.month}"), rok=d.year,
    )
    delta = (today - d).days
    if delta == 0:
        description = f"{t('pohled.dnes')} · {date_text}"
    elif delta == 1:
        description = f"{t('pohled.vcera')} · {date_text}"
    else:
        description = date_text[:1].upper() + date_text[1:]
    return f"{description} ({UTC_LABEL})"


def event_id(u: dict) -> str:
    """Stabilni oznaceni radku pro odkaz na detail.

    Radky nemaji vlastni id. Otisk kanonickeho JSON staci: dva uplne stejne
    radky (vcetne vterinoveho razitka) jsou pro detail totez.
    """
    canonical = json.dumps(u, sort_keys=True, ensure_ascii=False)
    return hashlib.sha1(canonical.encode("utf-8")).hexdigest()[:12]


def raw_line(u: dict) -> str:
    """Radek, jak lezi v audit/RRRR-MM-DD.jsonl (tytez parametry jako zapis)."""
    return json.dumps(u, ensure_ascii=False, sort_keys=True)


def result_badge(u: dict, t) -> tuple[str, str, str]:
    """(trida stitku, text, duvod) - tytez tridy jako zbytek konzole."""
    kind = u.get("kind")
    outcome = u.get("outcome")
    if kind == "write":
        if outcome == "denied":
            return "vysledek-denied", t("pohled.vysledek.write_denied"), ""
        return "vysledek-write", t("pohled.vysledek.write"), ""
    if kind == "access":
        status = str(u.get("status", ""))
        if outcome == "ok":
            return "vysledek-ok", status or "ok", ""
        return "vysledek-jiny", status or t("pohled.vysledek.error"), ""
    if kind == "origin_denied":
        return "vysledek-denied", "403", t("pohled.mimo_rozsah")
    reason = str(u.get("reason") or "")
    if outcome == "ok":
        return "vysledek-ok", "ok", reason
    if outcome == "denied":
        return "vysledek-denied", t("pohled.vysledek.denied"), reason
    if outcome:
        return "vysledek-jiny", t(f"pohled.vysledek.{outcome}"), reason
    if kind == "session" and u.get("op") == "csrf_denied":
        return "vysledek-denied", t("pohled.vysledek.denied"), ""
    return "vysledek-jiny", DASH, reason


def _strip_prefix(value, prefix: str) -> str:
    text = str(value or "")
    return text[len(prefix):] if text.startswith(prefix) else text


def actor_origin(u: dict) -> str:
    """Adresa, odkud jednal aktor. Starsi zapis rozsahu mel v `origin` rozsah."""
    if u.get("op") in _RANGE_OPS and "range" not in u:
        return DASH
    return str(u.get("origin") or DASH)


def _contains(query: str, *parts) -> bool:
    return query in " ".join(str(k) for k in parts if k).lower()


# == spravci ================================================================


def what_changed(u: dict, t) -> tuple[str, str]:
    """(popis operace, cil) pro sloupec "Co zmenil"."""
    kind = u.get("kind")
    op = u.get("op") or ""
    if kind == "authenticate":
        return t("pohled.op.login"), ""
    if kind == "session":
        return t(f"pohled.op.session.{op}"), str(u.get("path") or "")
    description = t(f"pohled.op.{op}")
    if description == f"pohled.op.{op}":
        description = op or DASH              # neznama operace: surove jmeno
    name = str(u.get("name") or "")
    key = t("pohled.klic")
    if op in ("add_member", "remove_member"):
        member = u.get("member") or (name if u.get("group") else "")
        target = f"{u.get('group', '')} ← {member}"
    elif op == "include":
        target = f"{u.get('parent', '')} ⊃ {u.get('child', '')}"
    elif op in _RANGE_OPS:
        cidr = u.get("range") or u.get("origin") or ""
        target = f"{name}  {cidr}".strip()
    elif op == "register_component" and u.get("key_id"):
        target = f"{name} · {key} {u['key_id']}"
    elif op == "set_detail":
        enabled = str(u.get("detail")).lower() in ("true", "1")
        target = f"{name} → {t('pohled.zapnuto' if enabled else 'pohled.vypnuto')}"
    elif op == "share_admin_credential":
        target = f"{name} ← {u.get('source_realm', '')}"
    else:
        target = name
    return description, target


def _admin_row(u: dict, t) -> dict:
    css_class, text, reason = result_badge(u, t)
    description, target = what_changed(u, t)
    who = u.get("actor") or u.get("subject") or ""
    return {
        "id": event_id(u), "event": u, "time": utc_clock(u),
        "admin": _strip_prefix(who, "admin:") or DASH,
        "origin": actor_origin(u), "action": description, "target": target,
        "result_class": css_class, "result_text": text, "reason": reason,
    }


def _admin_filter(u: dict, filters: dict, t) -> bool:
    description, target = what_changed(u, t)
    css_class, text, reason = result_badge(u, t)
    return all((
        _contains(filters.get("spravce", ""), u.get("actor"), u.get("subject")),
        _contains(filters.get("odkud", ""), actor_origin(u)),
        _contains(filters.get("co", ""), description, target, u.get("op")),
        _contains(filters.get("vysledek", ""), text, reason, u.get("outcome")),
    ))


def admin_groups(events, filters: dict, t) -> list[dict]:
    """Udalosti spravcu seskupene do relaci, nejnovejsi skupina prvni.

    Relace zacina uspesnym prihlasenim a konci odhlasenim (nebo vyrazenim);
    zmena spravce, jehoz prihlaseni je pred zvolenym obdobim, ma skupinu
    bez zacatku. Neuspesne pokusy tehoz spravce z tehoz mista jsou vlastni
    skupina - relace z nich nevznikla. Zmena mimo konzoli (operator na
    serveru) je skupina "mimo konzoli".

    Seskupuje se nad CELYM obdobim a az potom filtruje: filtr na "co zmenil"
    nesmi relaci utrhnout hlavicku s tim, kdo a odkud se prihlasil.
    """
    chronological = [u for u in events if is_admin(u)]
    groups: list[dict] = []
    open_sessions: dict[str, dict] = {}
    failures: dict[tuple[str, str], dict] = {}

    def new_group(kind, admin="", origin="", start=None):
        group = {"kind": kind, "admin": admin, "origin": origin,
                   "start": start, "end": None, "events": []}
        groups.append(group)
        return group

    for u in chronological:
        kind = u.get("kind")
        if kind == "authenticate":
            name = _strip_prefix(u.get("subject"), "admin:")
            origin = str(u.get("origin") or "")
            if u.get("outcome") == "ok":
                failures = {k: v for k, v in failures.items() if k[0] != name}
                group = new_group("relace", name, origin, start=u)
                open_sessions[name] = group
            else:
                group = failures.get((name, origin))
                if group is None or group is not groups[-1]:
                    group = new_group("neuspech", name, origin)
                    failures[(name, origin)] = group
            group["events"].append(u)
            continue
        actor = str(u.get("actor") or "")
        if actor.startswith("admin:"):
            name = actor[len("admin:"):]
            group = open_sessions.get(name)
            if group is None:
                group = new_group("bez_zacatku", name, actor_origin(u))
                open_sessions[name] = group
            group["events"].append(u)
            if kind == "session" and u.get("op") in ("logout", "evicted"):
                group["end"] = u
                open_sessions.pop(name, None)
        else:
            last = groups[-1] if groups else None
            if last is None or last["kind"] != "mimo":
                last = new_group("mimo", actor)
            last["events"].append(u)

    grouped = []
    for group in groups:
        selected = [u for u in group["events"] if _admin_filter(u, filters, t)]
        if not selected:
            continue
        changes = sum(1 for u in group["events"] if u.get("kind") == "write")
        grouped.append({
            **group,
            "changes": changes,
            "attempts": len(group["events"]),
            "last": selected[-1],
            "rows": [_admin_row(u, t) for u in reversed(selected)],
        })
    grouped.sort(key=lambda s: str(s["last"].get("t", "")), reverse=True)
    return grouped


def group_header(group: dict, t) -> str:
    kind = group["kind"]
    if kind == "relace":
        text = t("pohled.relace").format(
            spravce=group["admin"], cas=utc_clock(group["start"]),
            odkud=group["origin"] or DASH,
        )
        if group["end"] is not None:
            end = utc_clock(group["end"])
            text += " · " + t("pohled.relace_konec").format(cas=end)
        return text + " · " + t("pohled.zmen").format(n=group["changes"])
    if kind == "bez_zacatku":
        return t("pohled.relace_bez_zacatku").format(
            spravce=group["admin"], n=group["changes"],
        )
    if kind == "neuspech":
        return t("pohled.neuspech").format(
            spravce=group["admin"], odkud=group["origin"] or DASH,
            n=group["attempts"],
        )
    return t("pohled.mimo_konzoli")


# == uzivatele ==============================================================


def purpose_label(u: dict, t) -> tuple[str, str]:
    """(popis, doplnek) - "prihlaseni", nebo "odemceni" s kusem cile."""
    purpose = str(u.get("purpose") or "")
    if purpose == "login":
        return t("pohled.ucel.login"), ""
    if purpose.startswith("unlock:"):
        return t("pohled.ucel.unlock"), purpose[len("unlock:"):][:8] + "…"
    return purpose or DASH, ""


def _user_row(u: dict, t) -> dict:
    css_class, text, reason = result_badge(u, t)
    description, extra = purpose_label(u, t)
    return {
        "id": event_id(u), "event": u, "time": utc_clock(u), "day": utc_day(u),
        "user": _strip_prefix(u.get("subject"), "user:") or DASH,
        "client": str(u.get("client_origin") or DASH),
        "app": str(u.get("component") or DASH),
        "key_id": str(u.get("key_id") or ""),
        "server": str(u.get("origin") or ""),
        "purpose": description, "purpose_extra": extra,
        "result_class": css_class, "result_text": text, "reason": reason,
    }


def user_rows(events, filters: dict, t) -> list[dict]:
    rows = []
    for u in reversed(events):
        if not is_user(u):
            continue
        description, extra = purpose_label(u, t)
        css_class, text, reason = result_badge(u, t)
        if not all((
            _contains(filters.get("uzivatel", ""), u.get("subject")),
            _contains(filters.get("klient", ""), u.get("client_origin")),
            _contains(filters.get("aplikace", ""), u.get("component"),
                      u.get("key_id"), u.get("origin")),
            _contains(filters.get("ucel", ""), description, u.get("purpose")),
            _contains(filters.get("vysledek", ""), text, reason, u.get("outcome")),
        )):
            continue
        rows.append(_user_row(u, t))
    return rows


# == aplikace ===============================================================


def request_info(u: dict, t) -> dict:
    """Ceho se pozadavek tykal: metoda, cesta a u overeni koho a k cemu."""
    kind = u.get("kind")
    if kind == "authenticate":
        description, _ = purpose_label(u, t)
        return {"method": "POST", "path": "/v1/authenticate",
                "subject": str(u.get("subject") or ""), "purpose": description}
    return {"method": str(u.get("method") or ""), "path": str(u.get("path") or ""),
            "subject": "", "purpose": ""}


def _merge_key(u: dict):
    """Co musi sedet, aby se dva pozadavky v pohledu sloucily do jednoho.

    Jen `access`: overeni i zamitnuty rozsah jsou udalosti, ktere clovek
    chce videt kazdou zvlast.
    """
    if u.get("kind") != "access":
        return None
    return tuple(u.get(k) for k in
                 ("component", "key_id", "origin", "method", "path", "status"))


def _close_together(older: dict, newer: dict) -> bool:
    """Jsou dva pozadavky od sebe nejvys `MERGE_GAP_S`?

    Bez citelneho casu se neslucuje - radeji dva radky nez jeden, ktery
    schova udalost.
    """
    a, b = utc_time(older.get("t")), utc_time(newer.get("t"))
    if a is None or b is None:
        return False
    return 0 <= (b - a).total_seconds() <= MERGE_GAP_S


def app_rows(events, filters: dict, t) -> list[dict]:
    """Nejnovejsi prvni; stejne pozadavky tesne po sobe jako jeden radek.

    Slucuje se AZ PO filtru: sloucit se smi jen to, co clovek po filtru
    skutecne vidi vedle sebe.
    """
    rows: list[dict] = []
    for u in reversed(events):
        if not is_app(u):
            continue
        p = request_info(u, t)
        css_class, text, reason = result_badge(u, t)
        if not all((
            _contains(filters.get("aplikace", ""), u.get("component")),
            _contains(filters.get("klic", ""), u.get("key_id")),
            _contains(filters.get("odkud", ""), u.get("origin")),
            _contains(filters.get("pozadavek", ""), p["method"], p["path"],
                      p["subject"], p["purpose"]),
            _contains(filters.get("vysledek", ""), text, reason, u.get("outcome"),
                      u.get("status")),
        )):
            continue
        key = _merge_key(u)
        previous = rows[-1] if rows else None
        if (key is not None and previous is not None
                and previous["merge_key"] == key
                and _close_together(u, previous["members"][-1])):
            previous["members"].append(u)
            continue
        rows.append({
            "id": event_id(u), "event": u, "time": utc_clock(u), "day": utc_day(u),
            "app": str(u.get("component") or DASH),
            "key_id": str(u.get("key_id") or DASH),
            "origin": str(u.get("origin") or DASH),
            **p,
            "result_class": css_class, "result_text": text, "reason": reason,
            "merge_key": key, "members": [u],
        })
    return [row for run in rows for row in _expand_run(run, t)]


def _expand_run(run: dict, t) -> list[dict]:
    """Rada dost dlouha na dotazovani je jeden radek, kratsi zase jednotlive."""
    members = run.pop("members")
    if len(members) >= MIN_RUN:
        return [{**run, "count": len(members), "since": utc_clock(members[-1])}]
    output = []
    for u in members:
        css_class, text, reason = result_badge(u, t)
        output.append({
            **run, "id": event_id(u), "event": u, "time": utc_clock(u),
            "day": utc_day(u), "result_class": css_class, "result_text": text,
            "reason": reason, "count": 1, "since": "",
        })
    return output


# == dny a detail ===========================================================


def with_days(rows, today: date, t) -> list[dict]:
    """Proloz radky hlavickami dne: [{"day": "..."}, {"row": ...}, ...]."""
    output = []
    last = object()
    for row in rows:
        d = row["day"] if "day" in row else utc_day(row["event"])
        if d != last:
            output.append({"day": day_label(d, today, t)})
            last = d
        output.append({"row": row})
    return output


#: Poradi poli v detailu: nejdriv to, podle ceho se hleda, pak zbytek abecedne.
_FIELD_ORDER = (
    "t", "kind", "subject", "actor", "op", "purpose", "outcome", "reason",
    "status", "error", "origin", "client_origin", "component", "key_id",
    "method", "path", "name", "group", "member", "range", "gen",
)


def detail_fields(u: dict, t) -> list[tuple[str, str, str]]:
    """(klic, popisek, hodnota) pro vsechna pole zaznamu, nic nevynechat."""
    order = {k: i for i, k in enumerate(_FIELD_ORDER)}
    keys = sorted(u, key=lambda k: (order.get(k, len(order)), k))
    output = []
    for key in keys:
        caption = t(f"pohled.pole.{key}")
        if caption == f"pohled.pole.{key}":
            caption = key
        output.append((key, caption, str(u[key])))
    return output


def find_row(rows, wanted_id: str | None):
    """Radek s danym id (u sloucenych jen ten nejnovejsi), nebo None."""
    if not wanted_id:
        return None
    for row in rows:
        if row["id"] == wanted_id:
            return row
    return None
