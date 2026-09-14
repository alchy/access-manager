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
from datetime import date, datetime

POHLEDY = ("spravci", "uzivatele", "aplikace", "vse")

#: Kolik radku pohled vykresli nejvys. Aplikace, ktera se pta kazdou minutu,
#: ma za tyden deset tisic radku; vic nez tohle se neda precist a jen by se
#: dlouho renderovalo. Zbytek je za filtrem.
LIMIT_RADKU = 500

#: Operace, u kterych `origin` ve STARSICH zaznamech neznamena adresu
#: aktora, ale rozsah aplikace. Nove zaznamy maji rozsah v `range`.
_OPERACE_S_ROZSAHEM = ("add_origin", "remove_origin")

POMLCKA = "—"

#: Slucovani je pro DOTAZOVANI (`/v1/generation` kazdou minutu), ne pro
#: samostatne udalosti. Samostatna overeni klice sloucit nesmi - kazde nove
#: by jen posunulo cas a pocet v jednom radku a vypadalo by to, ze nepribylo
#: nic (presne tak se schovalo sedm `whoami` aplikace soc za "7x od
#: 12:13:38"). Proto dve podminky: mezera mezi sousedy nejvys
#: `MEZERA_SLOUCENI_S` a rada aspon `NEJMENSI_RADA` pozadavku. Dve rucni
#: overeni minutu po sobe jsou dva radky; rada deseti dotazu je jeden.
MEZERA_SLOUCENI_S = 90
NEJMENSI_RADA = 3


# == trideni do pohledu =====================================================


def je_spravce(u: dict) -> bool:
    druh = u.get("kind")
    if druh in ("write", "session"):
        return True
    return druh == "authenticate" and u.get("purpose") == "admin"


def je_uzivatel(u: dict) -> bool:
    return u.get("kind") == "authenticate" and u.get("purpose") != "admin"


def je_aplikace(u: dict) -> bool:
    druh = u.get("kind")
    if druh in ("access", "origin_denied"):
        return True
    # Overeni patri aplikaci jen tehdy, kdyz o nej aplikace pozadala.
    # `Access.local` na serveru zadnou komponentu nema.
    return druh == "authenticate" and bool(u.get("component"))


PATRI = {
    "spravci": je_spravce,
    "uzivatele": je_uzivatel,
    "aplikace": je_aplikace,
    "vse": lambda _u: True,
}


def pocty(udalosti) -> dict[str, int]:
    """Kolik udalosti obdobi patri kteremu pohledu - cisla na zalozkach."""
    vysledek = dict.fromkeys(POHLEDY, 0)
    for u in udalosti:
        for pohled in POHLEDY:
            if PATRI[pohled](u):
                vysledek[pohled] += 1
    return vysledek


# == spolecne: cas, identita radku, vysledek ================================


def mistni_cas(t) -> datetime | None:
    """ISO razitko z auditu v casovem pasmu procesu (kontejner ma TZ).

    Audit pise UTC, clovek u konzole mysli mistne. Presne UTC zustava
    v detailu zaznamu.
    """
    if not isinstance(t, str) or not t:
        return None
    try:
        return datetime.fromisoformat(t).astimezone()
    except ValueError:
        return None


def hodiny(u: dict) -> str:
    cas = mistni_cas(u.get("t"))
    return cas.strftime("%H:%M:%S") if cas else (u.get("t") or POMLCKA)


def den(u: dict) -> date | None:
    cas = mistni_cas(u.get("t"))
    return cas.date() if cas else None


def popis_dne(d: date | None, dnes: date, t) -> str:
    """"Dnes · pondeli 14. zari 2026", "Vcera · ...", jinak jen datum."""
    if d is None:
        return POMLCKA
    datum = t("pohled.datum").format(
        den=t(f"pohled.den.{d.weekday()}"), d=d.day,
        mesic=t(f"pohled.mesic.{d.month}"), rok=d.year,
    )
    rozdil = (dnes - d).days
    if rozdil == 0:
        return f"{t('pohled.dnes')} · {datum}"
    if rozdil == 1:
        return f"{t('pohled.vcera')} · {datum}"
    return datum[:1].upper() + datum[1:]


def id_udalosti(u: dict) -> str:
    """Stabilni oznaceni radku pro odkaz na detail.

    Radky nemaji vlastni id. Otisk kanonickeho JSON staci: dva uplne stejne
    radky (vcetne vterinoveho razitka) jsou pro detail totez.
    """
    kanon = json.dumps(u, sort_keys=True, ensure_ascii=False)
    return hashlib.sha1(kanon.encode("utf-8")).hexdigest()[:12]


def surovy_radek(u: dict) -> str:
    """Radek, jak lezi v audit/RRRR-MM-DD.jsonl (tytez parametry jako zapis)."""
    return json.dumps(u, ensure_ascii=False, sort_keys=True)


def vysledek(u: dict, t) -> tuple[str, str, str]:
    """(trida stitku, text, duvod) - tytez tridy jako zbytek konzole."""
    druh = u.get("kind")
    outcome = u.get("outcome")
    if druh == "write":
        if outcome == "denied":
            return "vysledek-denied", t("pohled.vysledek.write_denied"), ""
        return "vysledek-write", t("pohled.vysledek.write"), ""
    if druh == "access":
        stav = str(u.get("status", ""))
        if outcome == "ok":
            return "vysledek-ok", stav or "ok", ""
        return "vysledek-jiny", stav or t("pohled.vysledek.error"), ""
    if druh == "origin_denied":
        return "vysledek-denied", "403", t("pohled.mimo_rozsah")
    duvod = str(u.get("reason") or "")
    if outcome == "ok":
        return "vysledek-ok", "ok", duvod
    if outcome == "denied":
        return "vysledek-denied", t("pohled.vysledek.denied"), duvod
    if outcome:
        return "vysledek-jiny", t(f"pohled.vysledek.{outcome}"), duvod
    if druh == "session" and u.get("op") == "csrf_denied":
        return "vysledek-denied", t("pohled.vysledek.denied"), ""
    return "vysledek-jiny", POMLCKA, duvod


def _bez_prefixu(hodnota, prefix: str) -> str:
    text = str(hodnota or "")
    return text[len(prefix):] if text.startswith(prefix) else text


def odkud_aktora(u: dict) -> str:
    """Adresa, odkud jednal aktor. Starsi zapis rozsahu mel v `origin` rozsah."""
    if u.get("op") in _OPERACE_S_ROZSAHEM and "range" not in u:
        return POMLCKA
    return str(u.get("origin") or POMLCKA)


def _obsahuje(dotaz: str, *kusy) -> bool:
    return dotaz in " ".join(str(k) for k in kusy if k).lower()


# == spravci ================================================================


def co_zmenil(u: dict, t) -> tuple[str, str]:
    """(popis operace, cil) pro sloupec "Co zmenil"."""
    druh = u.get("kind")
    op = u.get("op") or ""
    if druh == "authenticate":
        return t("pohled.op.login"), ""
    if druh == "session":
        return t(f"pohled.op.session.{op}"), str(u.get("path") or "")
    popis = t(f"pohled.op.{op}")
    if popis == f"pohled.op.{op}":
        popis = op or POMLCKA              # neznama operace: surove jmeno
    jmeno = str(u.get("name") or "")
    klic = t("pohled.klic")
    if op in ("add_member", "remove_member"):
        clen = u.get("member") or (jmeno if u.get("group") else "")
        cil = f"{u.get('group', '')} ← {clen}"
    elif op == "include":
        cil = f"{u.get('parent', '')} ⊃ {u.get('child', '')}"
    elif op in _OPERACE_S_ROZSAHEM:
        rozsah = u.get("range") or u.get("origin") or ""
        cil = f"{jmeno}  {rozsah}".strip()
    elif op == "register_component" and u.get("key_id"):
        cil = f"{jmeno} · {klic} {u['key_id']}"
    elif op == "set_detail":
        zapnuto = str(u.get("detail")).lower() in ("true", "1")
        cil = f"{jmeno} → {t('pohled.zapnuto' if zapnuto else 'pohled.vypnuto')}"
    elif op == "share_admin_credential":
        cil = f"{jmeno} ← {u.get('source_realm', '')}"
    else:
        cil = jmeno
    return popis, cil


def _radek_spravce(u: dict, t) -> dict:
    trida, text, duvod = vysledek(u, t)
    popis, cil = co_zmenil(u, t)
    kdo = u.get("actor") or u.get("subject") or ""
    return {
        "id": id_udalosti(u), "udalost": u, "cas": hodiny(u),
        "spravce": _bez_prefixu(kdo, "admin:") or POMLCKA,
        "odkud": odkud_aktora(u), "co": popis, "cil": cil,
        "vysledek_trida": trida, "vysledek_text": text, "reason": duvod,
    }


def _filtr_spravce(u: dict, filtry: dict, t) -> bool:
    popis, cil = co_zmenil(u, t)
    trida, text, duvod = vysledek(u, t)
    return all((
        _obsahuje(filtry.get("spravce", ""), u.get("actor"), u.get("subject")),
        _obsahuje(filtry.get("odkud", ""), odkud_aktora(u)),
        _obsahuje(filtry.get("co", ""), popis, cil, u.get("op")),
        _obsahuje(filtry.get("vysledek", ""), text, duvod, u.get("outcome")),
    ))


def skupiny_spravcu(udalosti, filtry: dict, t) -> list[dict]:
    """Udalosti spravcu seskupene do relaci, nejnovejsi skupina prvni.

    Relace zacina uspesnym prihlasenim a konci odhlasenim (nebo vyrazenim);
    zmena spravce, jehoz prihlaseni je pred zvolenym obdobim, ma skupinu
    bez zacatku. Neuspesne pokusy tehoz spravce z tehoz mista jsou vlastni
    skupina - relace z nich nevznikla. Zmena mimo konzoli (operator na
    serveru) je skupina "mimo konzoli".

    Seskupuje se nad CELYM obdobim a az potom filtruje: filtr na "co zmenil"
    nesmi relaci utrhnout hlavicku s tim, kdo a odkud se prihlasil.
    """
    chronologicky = [u for u in udalosti if je_spravce(u)]
    skupiny: list[dict] = []
    otevrene: dict[str, dict] = {}
    neuspechy: dict[tuple[str, str], dict] = {}

    def nova(druh, spravce="", origin="", zacatek=None):
        skupina = {"druh": druh, "spravce": spravce, "origin": origin,
                   "zacatek": zacatek, "konec": None, "udalosti": []}
        skupiny.append(skupina)
        return skupina

    for u in chronologicky:
        druh = u.get("kind")
        if druh == "authenticate":
            jmeno = _bez_prefixu(u.get("subject"), "admin:")
            origin = str(u.get("origin") or "")
            if u.get("outcome") == "ok":
                neuspechy = {k: v for k, v in neuspechy.items() if k[0] != jmeno}
                skupina = nova("relace", jmeno, origin, zacatek=u)
                otevrene[jmeno] = skupina
            else:
                skupina = neuspechy.get((jmeno, origin))
                if skupina is None or skupina is not skupiny[-1]:
                    skupina = nova("neuspech", jmeno, origin)
                    neuspechy[(jmeno, origin)] = skupina
            skupina["udalosti"].append(u)
            continue
        aktor = str(u.get("actor") or "")
        if aktor.startswith("admin:"):
            jmeno = aktor[len("admin:"):]
            skupina = otevrene.get(jmeno)
            if skupina is None:
                skupina = nova("bez_zacatku", jmeno, odkud_aktora(u))
                otevrene[jmeno] = skupina
            skupina["udalosti"].append(u)
            if druh == "session" and u.get("op") in ("logout", "evicted"):
                skupina["konec"] = u
                otevrene.pop(jmeno, None)
        else:
            posledni = skupiny[-1] if skupiny else None
            if posledni is None or posledni["druh"] != "mimo":
                posledni = nova("mimo", aktor)
            posledni["udalosti"].append(u)

    vysledek_skupin = []
    for skupina in skupiny:
        vybrane = [u for u in skupina["udalosti"] if _filtr_spravce(u, filtry, t)]
        if not vybrane:
            continue
        zmen = sum(1 for u in skupina["udalosti"] if u.get("kind") == "write")
        vysledek_skupin.append({
            **skupina,
            "zmen": zmen,
            "pokusu": len(skupina["udalosti"]),
            "posledni": vybrane[-1],
            "radky": [_radek_spravce(u, t) for u in reversed(vybrane)],
        })
    vysledek_skupin.sort(key=lambda s: str(s["posledni"].get("t", "")), reverse=True)
    return vysledek_skupin


def hlavicka_skupiny(skupina: dict, t) -> str:
    druh = skupina["druh"]
    if druh == "relace":
        text = t("pohled.relace").format(
            spravce=skupina["spravce"], cas=hodiny(skupina["zacatek"]),
            odkud=skupina["origin"] or POMLCKA,
        )
        if skupina["konec"] is not None:
            konec = hodiny(skupina["konec"])
            text += " · " + t("pohled.relace_konec").format(cas=konec)
        return text + " · " + t("pohled.zmen").format(n=skupina["zmen"])
    if druh == "bez_zacatku":
        return t("pohled.relace_bez_zacatku").format(
            spravce=skupina["spravce"], n=skupina["zmen"],
        )
    if druh == "neuspech":
        return t("pohled.neuspech").format(
            spravce=skupina["spravce"], odkud=skupina["origin"] or POMLCKA,
            n=skupina["pokusu"],
        )
    return t("pohled.mimo_konzoli")


# == uzivatele ==============================================================


def ucel(u: dict, t) -> tuple[str, str]:
    """(popis, doplnek) - "prihlaseni", nebo "odemceni" s kusem cile."""
    purpose = str(u.get("purpose") or "")
    if purpose == "login":
        return t("pohled.ucel.login"), ""
    if purpose.startswith("unlock:"):
        return t("pohled.ucel.unlock"), purpose[len("unlock:"):][:8] + "…"
    return purpose or POMLCKA, ""


def _radek_uzivatele(u: dict, t) -> dict:
    trida, text, duvod = vysledek(u, t)
    popis, doplnek = ucel(u, t)
    return {
        "id": id_udalosti(u), "udalost": u, "cas": hodiny(u), "den": den(u),
        "uzivatel": _bez_prefixu(u.get("subject"), "user:") or POMLCKA,
        "klient": str(u.get("client_origin") or POMLCKA),
        "aplikace": str(u.get("component") or POMLCKA),
        "key_id": str(u.get("key_id") or ""),
        "server": str(u.get("origin") or ""),
        "ucel": popis, "ucel_doplnek": doplnek,
        "vysledek_trida": trida, "vysledek_text": text, "reason": duvod,
    }


def radky_uzivatelu(udalosti, filtry: dict, t) -> list[dict]:
    radky = []
    for u in reversed(udalosti):
        if not je_uzivatel(u):
            continue
        popis, doplnek = ucel(u, t)
        trida, text, duvod = vysledek(u, t)
        if not all((
            _obsahuje(filtry.get("uzivatel", ""), u.get("subject")),
            _obsahuje(filtry.get("klient", ""), u.get("client_origin")),
            _obsahuje(filtry.get("aplikace", ""), u.get("component"),
                      u.get("key_id"), u.get("origin")),
            _obsahuje(filtry.get("ucel", ""), popis, u.get("purpose")),
            _obsahuje(filtry.get("vysledek", ""), text, duvod, u.get("outcome")),
        )):
            continue
        radky.append(_radek_uzivatele(u, t))
    return radky


# == aplikace ===============================================================


def pozadavek(u: dict, t) -> dict:
    """Ceho se pozadavek tykal: metoda, cesta a u overeni koho a k cemu."""
    druh = u.get("kind")
    if druh == "authenticate":
        popis, _ = ucel(u, t)
        return {"metoda": "POST", "cesta": "/v1/authenticate",
                "subjekt": str(u.get("subject") or ""), "ucel": popis}
    return {"metoda": str(u.get("method") or ""), "cesta": str(u.get("path") or ""),
            "subjekt": "", "ucel": ""}


def _klic_slouceni(u: dict):
    """Co musi sedet, aby se dva pozadavky v pohledu sloucily do jednoho.

    Jen `access`: overeni i zamitnuty rozsah jsou udalosti, ktere clovek
    chce videt kazdou zvlast.
    """
    if u.get("kind") != "access":
        return None
    return tuple(u.get(k) for k in
                 ("component", "key_id", "origin", "method", "path", "status"))


def _tesne_po_sobe(starsi: dict, novejsi: dict) -> bool:
    """Jsou dva pozadavky od sebe nejvys `MEZERA_SLOUCENI_S`?

    Bez citelneho casu se neslucuje - radeji dva radky nez jeden, ktery
    schova udalost.
    """
    a, b = mistni_cas(starsi.get("t")), mistni_cas(novejsi.get("t"))
    if a is None or b is None:
        return False
    return 0 <= (b - a).total_seconds() <= MEZERA_SLOUCENI_S


def radky_aplikaci(udalosti, filtry: dict, t) -> list[dict]:
    """Nejnovejsi prvni; stejne pozadavky tesne po sobe jako jeden radek.

    Slucuje se AZ PO filtru: sloucit se smi jen to, co clovek po filtru
    skutecne vidi vedle sebe.
    """
    radky: list[dict] = []
    for u in reversed(udalosti):
        if not je_aplikace(u):
            continue
        p = pozadavek(u, t)
        trida, text, duvod = vysledek(u, t)
        if not all((
            _obsahuje(filtry.get("aplikace", ""), u.get("component")),
            _obsahuje(filtry.get("klic", ""), u.get("key_id")),
            _obsahuje(filtry.get("odkud", ""), u.get("origin")),
            _obsahuje(filtry.get("pozadavek", ""), p["metoda"], p["cesta"],
                      p["subjekt"], p["ucel"]),
            _obsahuje(filtry.get("vysledek", ""), text, duvod, u.get("outcome"),
                      u.get("status")),
        )):
            continue
        klic = _klic_slouceni(u)
        predchozi = radky[-1] if radky else None
        if (klic is not None and predchozi is not None
                and predchozi["klic_slouceni"] == klic
                and _tesne_po_sobe(u, predchozi["clenove"][-1])):
            predchozi["clenove"].append(u)
            continue
        radky.append({
            "id": id_udalosti(u), "udalost": u, "cas": hodiny(u), "den": den(u),
            "aplikace": str(u.get("component") or POMLCKA),
            "key_id": str(u.get("key_id") or POMLCKA),
            "odkud": str(u.get("origin") or POMLCKA),
            **p,
            "vysledek_trida": trida, "vysledek_text": text, "reason": duvod,
            "klic_slouceni": klic, "clenove": [u],
        })
    return [radek for rada in radky for radek in _rozbal_radu(rada, t)]


def _rozbal_radu(rada: dict, t) -> list[dict]:
    """Rada dost dlouha na dotazovani je jeden radek, kratsi zase jednotlive."""
    clenove = rada.pop("clenove")
    if len(clenove) >= NEJMENSI_RADA:
        return [{**rada, "pocet": len(clenove), "od": hodiny(clenove[-1])}]
    vystup = []
    for u in clenove:
        trida, text, duvod = vysledek(u, t)
        vystup.append({
            **rada, "id": id_udalosti(u), "udalost": u, "cas": hodiny(u),
            "den": den(u), "vysledek_trida": trida, "vysledek_text": text,
            "reason": duvod, "pocet": 1, "od": "",
        })
    return vystup


# == dny a detail ===========================================================


def se_dny(radky, dnes: date, t) -> list[dict]:
    """Proloz radky hlavickami dne: [{"den": "..."}, {"radek": ...}, ...]."""
    vystup = []
    posledni = object()
    for radek in radky:
        d = radek["den"] if "den" in radek else den(radek["udalost"])
        if d != posledni:
            vystup.append({"den": popis_dne(d, dnes, t)})
            posledni = d
        vystup.append({"radek": radek})
    return vystup


#: Poradi poli v detailu: nejdriv to, podle ceho se hleda, pak zbytek abecedne.
_PORADI_POLI = (
    "t", "kind", "subject", "actor", "op", "purpose", "outcome", "reason",
    "status", "error", "origin", "client_origin", "component", "key_id",
    "method", "path", "name", "group", "member", "range", "gen",
)


def pole_detailu(u: dict, t) -> list[tuple[str, str, str]]:
    """(klic, popisek, hodnota) pro vsechna pole zaznamu, nic nevynechat."""
    poradi = {k: i for i, k in enumerate(_PORADI_POLI)}
    klice = sorted(u, key=lambda k: (poradi.get(k, len(poradi)), k))
    vystup = []
    for klic in klice:
        popisek = t(f"pohled.pole.{klic}")
        if popisek == f"pohled.pole.{klic}":
            popisek = klic
        vystup.append((klic, popisek, str(u[klic])))
    return vystup


def najdi(radky, hledane_id: str | None):
    """Radek s danym id (u sloucenych jen ten nejnovejsi), nebo None."""
    if not hledane_id:
        return None
    for radek in radky:
        if radek["id"] == hledane_id:
            return radek
    return None
