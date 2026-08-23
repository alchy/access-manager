# Refaktoring klientské knihovny — implementační plán

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Srovnat hotovou souborovou vrstvu se závazným návrhem (docs/design.md): veřejný tvar verdiktu, generace, životní cyklus identit a pověření, zámky nad zápisy — aby na ni šla položit služba a `Access.remote` bez pozdější změny tvaru API.

**Architecture:** Vše zůstává v plochém balíčku `access_manager` se souborovým úložištěm `FileStore` a fasádami `Access` (čtení + ověření) / `Admin` (zápis). Refaktoring nemění rozvrstvení, jen doplňuje chybějící povrch a opravuje sdílené zápisy. Žádná síť, žádné nové zdrojové moduly.

**Tech Stack:** Python ≥ 3.12, pytest. Volitelná extra `[totp]` = pyotp + qrcode, lazy-importovaná. Žádné povinné závislosti.

**Spec:** `docs/design.md` — je závazný; README: „knihovna se píše podle něj, ne naopak“.

## Global Constraints

- `dependencies = []` v pyproject — žádné povinné závislosti; pyotp/qrcode jen lazy-importem uvnitř `[totp]` cest.
- `requires-python = ">=3.12"`.
- Existující tajemství se NIKDY nepřepíše (`test_an_existing_user_is_never_overwritten` musí projít v každém úkolu).
- Tajemství se nesmí dostat do repr, výjimky ani logu.
- Práva na disku: soubory `0o600`, adresáře `0o700`.
- Všechny testy běží bez sítě a bez serveru: `python -m pytest` (před začátkem: `python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'`; dál v plánu znamená `pytest` spuštění z tohoto venvu).
- Komentáře a docstringy česky bez diakritiky (jako zbytek kódu), jména testů anglicky ve stylu `test_a_..._is_...`.
- Commity česky, malými písmeny, stylem repa (`zapisova pulka, rozdeleni Access/Admin a textovy QR`), bez conventional-commits prefixů. Každý commit končí `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- `group:users` a `group:public` se z balíčku neexportují (viz docstring `__init__.py`).
- Veřejné tvary verdiktu jsou přesně čtyři z návrhu §3.1: `ok`, `denied`, `need_factor`, `throttled`. Podrobné důvody jsou audit/detail, ne tvar.

## Struktura souborů po refaktoringu

| Soubor | Odpovědnost | Změna |
|---|---|---|
| `access_manager/verdicts.py` | tvar odpovědi: `outcome` + `reason` + `gen` | přepis (úkol 2) |
| `access_manager/files.py` | souborové úložiště: čtení, ověření, anti-replay, zápisy, zámek, generace | rozšíření (úkoly 3–9) |
| `access_manager/principals.py` | jména, záznamy, vyhrazené skupiny | +`RESERVED_GROUPS` (úkol 5) |
| `access_manager/access.py` | čtecí fasáda | +`generation`, `unknown_principals`, `ready` (úkoly 4, 9) |
| `access_manager/admin.py` | zapisovací fasáda | +životní cyklus (úkoly 6, 7) |
| `tests/helpers.py` | společné ruce testů (nový) | úkol 1 |
| `tests/test_locking.py` | souběžné zápisy (nový) | úkol 3 |
| `tests/test_generation.py` | generace (nový) | úkol 4 |
| `tests/test_lifecycle.py` | disable/enable/remove/revoke/pair (nový) | úkoly 6, 7 |

Mimo rozsah tohoto plánu (návazná feature práce, ne refaktoring): HTTP služba, `Access.remote`, omezování pokusů (`throttled` — otevřený bod §7.3), origin ACL (§2b), fragmentovaná konfigurace (§7.2), audit log (patří ke službě).

Jedno rozhodnutí, které plán dělá vědomě: `expired` zůstává ve výčtu důvodů (`REASONS`), protože ho jmenuje závazný návrh §3.1 — ale nic ho zatím nevyrábí, což je v napětí se zásadou §3.1b („jméno pro stav, který nemůže nastat, je slib“). Až se bude sahat na návrh, patří to rozhodnout tam; kód se drží návrhu.

---

### Úkol 1: Společné ruce testů do `tests/helpers.py`

Testy dnes importují pomocné funkce z jiného testovacího modulu (`from test_files_identity import skupiny, zaloz`) — funguje to jen díky tomu, jak pytest vkládá adresáře do `sys.path`, a `test_files_identity.py` tím dostal druhou roli. Navíc `test_login_and_unlock_with_a_target_are_the_two_shapes` nic neassertuje.

**Files:**
- Create: `tests/helpers.py`
- Modify: `tests/test_files_identity.py`, `tests/test_files_authenticate.py`, `tests/test_files_groups.py`, `tests/test_admin.py`

**Interfaces:**
- Produces: `helpers.zaloz(home, name, secret=TAJEMSTVI) -> Path`, `helpers.skupiny(home, table) -> None`, `helpers.kod(secret=TAJEMSTVI, at=None) -> str`, `helpers.principaly(home, name) -> frozenset[str]`, konstanty `helpers.TAJEMSTVI`, `helpers.PUBLIC`, `helpers.USERS`. Všechny další úkoly je importují `from helpers import ...`.

- [ ] **Krok 1: Napiš `tests/helpers.py`**

```python
"""Spolecne ruce testu. Nejsou to testy - jen zakladani stavu.

Konstanty PUBLIC/USERS jsou tu ZNOVU, ne importem z balicku: balicek je
schvalne neexportuje a testy maji drzet jmena PROTOKOLU nezavisle na kodu.
"""
import json

PUBLIC = "group:public"
USERS = "group:users"
TAJEMSTVI = "JBSWY3DPEHPK3PXP"


def zaloz(home, name, secret=TAJEMSTVI):
    directory = home / f"user-{name}"
    directory.mkdir(parents=True)
    (directory / "totp.secret").write_text(secret + "\n", encoding="utf-8")
    return directory


def skupiny(home, table):
    (home / "groups.json").write_text(json.dumps(table), encoding="utf-8")


def kod(secret=TAJEMSTVI, at=None):
    import pyotp

    totp = pyotp.TOTP(secret)
    return totp.now() if at is None else totp.at(at)


def principaly(home, name):
    from access_manager import Access

    return Access.local(home).user(name).principals
```

- [ ] **Krok 2: Přepni importy v testech**

  - `tests/test_files_identity.py`: smaž definice `zaloz`, `skupiny` a konstant `PUBLIC`, `USERS` (řádky 20–32) i nepoužívaný `import json`; nahoru přidej `from helpers import PUBLIC, USERS, zaloz`.
  - `tests/test_files_authenticate.py`: smaž `TAJEMSTVI` a funkci `kod` (řádky 22–27), `import json`; nahraď `from test_files_identity import skupiny, zaloz` za `from helpers import TAJEMSTVI, kod, skupiny, zaloz`.
  - `tests/test_files_groups.py`: smaž lokální `principaly` (řádky 22–23), `import json`; nahraď import z `test_files_identity` za `from helpers import principaly, skupiny, zaloz`.
  - `tests/test_admin.py`: smaž lokální `principaly` (řádky 24–25), `import json`; nahraď import z `test_files_identity` za `from helpers import principaly, zaloz` (import `skupiny` byl stejně nepoužitý).

- [ ] **Krok 3: Zpevni bezassertový test**

V `tests/test_files_authenticate.py` nahraď:

```python
def test_login_and_unlock_with_a_target_are_the_two_shapes(tmp_path):
    zaloz(tmp_path, "hana")
    access = Access.local(tmp_path)
    access.authenticate("hana", {"totp": "000000"}, purpose="login")
    access.authenticate("hana", {"totp": "000000"}, purpose="unlock:screen.provoz/mzdy")
```

za:

```python
def test_login_and_unlock_with_a_target_are_the_two_shapes(tmp_path):
    # Oba tvary uceli projdou kontrolou tvaru - odmitne je az spatny kod,
    # ne ValueError. Bez assertu tenhle test nedrzel nic.
    zaloz(tmp_path, "hana")
    access = Access.local(tmp_path)
    prvni = access.authenticate("hana", {"totp": "000000"}, purpose="login")
    druhy = access.authenticate("hana", {"totp": "000000"}, purpose="unlock:screen.provoz/mzdy")
    assert prvni.outcome == "bad_code"
    assert druhy.outcome == "bad_code"
```

(Pozn.: v úkolu 2 se tyhle dva asserty změní z `outcome` na `reason` — tady zatím platí `outcome`.)

- [ ] **Krok 4: Ověř** — `pytest`; očekávání: 64 passed.
- [ ] **Krok 5: Commit** — `git add tests/ && git commit -m "testy: spolecne ruce do helpers.py"`

---

### Úkol 2: Verdikt — ven čtyři tvary, důvod zvlášť pro audit

Návrh §3.1: na drát jdou přesně čtyři tvary (`ok`, `denied`, `need_factor`, `throttled`); podrobný důvod (`bad_code`, `unknown_user`, …) patří do auditu a důvěryhodným klientům. Dnešní `Verdict.outcome` vrací rovnou podrobný důvod — kód napsaný proti `Access.local` (`outcome == "bad_code"`) by proti `Access.remote` nikdy nefungoval a slib „tytéž testy proti oběma zapojením“ by padl. Rozdělit teď, dokud je uživatelů málo.

**Files:**
- Modify: `access_manager/verdicts.py` (přepis), `access_manager/files.py:116` (need_factor), `tests/test_verdict.py` (přepis), `tests/test_files_authenticate.py` (asserty na důvod)

**Interfaces:**
- Produces: `Verdict(outcome, reason=None, subject_id=None, principals=frozenset(), required=(), gen=None)`; `Verdict.ok(subject_id, principals, gen=None)`; `Verdict.refused(reason, gen=None)` → `outcome="denied"`; `Verdict.need_factor(required, gen=None)`. Konstanty `OUTCOMES` (4 tvary), `REASONS` (`bad_code`, `replay`, `no_secret`, `unknown_user`, `disabled`, `expired`). Úkoly 4, 6, 7 na tohle staví.

- [ ] **Krok 1: Přepiš `tests/test_verdict.py` (failing testy)**

```python
"""Odpoved na "jsi to ty?" je VERDIKT, ne bool.

Ven jdou presne ctyri tvary z navrhu (par. 3.1): `ok`, `denied`,
`need_factor`, `throttled`. Podrobny duvod je pole `reason` - patri do
auditu a duveryhodnym volajicim. Kdyby duvod nesel oddelit od tvaru, umel
by kazdy klient rozlisit `unknown_user` od `bad_code` - a vypsat si
uzivatele tymz postrannim kanalem jako `404`.
"""
import pytest

from access_manager import Verdict


def test_an_ok_verdict_is_truthy():
    assert Verdict.ok(subject_id="user:hana", principals=["user:hana"])


def test_a_refused_verdict_is_falsy():
    # `if access.authenticate(...)` musi propustit jen `ok`.
    assert not Verdict.refused("bad_code")


def test_a_refusal_shows_denied_and_keeps_the_reason_for_the_audit():
    verdikt = Verdict.refused("bad_code")
    assert verdikt.outcome == "denied"
    assert verdikt.reason == "bad_code"


def test_need_factor_is_an_outcome_of_its_own():
    # Komponenta rika CO chybi, ne kolikate to je - a neni to `denied`.
    verdikt = Verdict.need_factor(("totp",))
    assert not verdikt
    assert verdikt.outcome == "need_factor"
    assert verdikt.required == ("totp",)
    assert verdikt.reason is None


def test_a_refusal_cannot_accidentally_say_ok():
    with pytest.raises(ValueError):
        Verdict.refused("ok")


def test_an_unknown_reason_is_refused_at_the_source():
    # `bad_cde` by bylo falsy, takze by `if` prosel spravne - a v auditu by
    # zustal nesmysl, ktery nikdo nikdy nedohleda.
    with pytest.raises(ValueError):
        Verdict.refused("bad_cde")


def test_an_unknown_outcome_is_refused_at_the_source():
    with pytest.raises(ValueError):
        Verdict(outcome="tak-napul")


def test_a_reason_cannot_ride_on_an_ok_verdict():
    with pytest.raises(ValueError):
        Verdict(outcome="ok", subject_id="user:hana", reason="bad_code")


def test_an_ok_verdict_without_an_identity_is_refused():
    # "Prosel, ale nevim kdo" neni odpoved, se kterou jde neco delat.
    with pytest.raises(ValueError):
        Verdict.ok(subject_id=None, principals=["group:users"])
```

- [ ] **Krok 2: Spusť a ověř pád** — `pytest tests/test_verdict.py -v`; očekávání: FAIL (`reason` neexistuje, `need_factor` konstruktor neexistuje).

- [ ] **Krok 3: Přepiš `access_manager/verdicts.py`**

```python
"""Verdikt: co access-manager odpovedel a proc."""
from __future__ import annotations

from dataclasses import dataclass, field

#: Ctyri tvary, ktere jdou VEN - presne ty z navrhu, par. 3.1. Nic dalsiho
#: ven nejde: kdo umi rozlisit `unknown_user` od `bad_code`, umi si vypsat
#: uzivatele.
OUTCOMES = frozenset({"ok", "denied", "need_factor", "throttled"})

#: Podrobny duvod odmitnuti - patri do AUDITU a duveryhodnym volajicim.
#: Ve viewBase2 se tri ruzne priciny hlasily stejnou hlaskou a stalo to
#: hodinu hledani (chyba 3.6); ta hodina se hledala v logu, takze rozdil
#: musi byt tam. `expired` jmenuje navrh par. 3.1; zatim ho nic nevyrabi.
REASONS = frozenset({
    "bad_code",
    "replay",
    "no_secret",
    "unknown_user",
    "disabled",
    "expired",
})


@dataclass(frozen=True, slots=True)
class Verdict:
    """Odpoved na "jsi to ty?".

    Pravdivy je JEN `ok`. `outcome` je jeden ze ctyr verejnych tvaru;
    `reason` je podrobnost pro audit. Lokalni zapojeni je duveryhodne cele,
    takze `reason` plni vzdycky - vzdaleny klient ho jednou dostane, jen
    kdyz to jeho zaznam povoli (`"detail": true`, navrh par. 3.1).
    """

    outcome: str
    reason: str | None = None
    subject_id: str | None = None
    principals: frozenset[str] = field(default_factory=frozenset)
    required: tuple[str, ...] = ()
    gen: int | None = None

    def __post_init__(self) -> None:
        if self.outcome not in OUTCOMES:
            raise ValueError(
                f"neznamy tvar verdiktu {self.outcome!r}; zname: "
                f"{', '.join(sorted(OUTCOMES))}"
            )
        if self.reason is not None:
            if self.outcome != "denied":
                raise ValueError(
                    f"duvod {self.reason!r} patri jen k `denied`, "
                    f"ne k {self.outcome!r}"
                )
            if self.reason not in REASONS:
                raise ValueError(
                    f"neznamy duvod {self.reason!r}; zname: "
                    f"{', '.join(sorted(REASONS))}"
                )
        if self.outcome == "ok" and not self.subject_id:
            raise ValueError("verdikt `ok` bez subject_id: nevim, kdo prosel")

    def __bool__(self) -> bool:
        return self.outcome == "ok"

    @classmethod
    def ok(cls, subject_id: str | None, principals, gen: int | None = None) -> "Verdict":
        return cls(
            outcome="ok",
            subject_id=subject_id,
            principals=frozenset(principals),
            gen=gen,
        )

    @classmethod
    def refused(cls, reason: str, gen: int | None = None) -> "Verdict":
        """Odmitnuti s duvodem. Ven jde `denied`; duvod je pro audit."""
        return cls(outcome="denied", reason=reason, gen=gen)

    @classmethod
    def need_factor(cls, required, gen: int | None = None) -> "Verdict":
        return cls(outcome="need_factor", required=tuple(required), gen=gen)
```

- [ ] **Krok 4: Oprav volání ve `files.py`**

Řádek 116 (`authenticate`): `return Verdict.refused("need_factor", required=("totp",))` → `return Verdict.need_factor(("totp",))`. Ostatní `Verdict.refused("...")` volání zůstávají beze změny (jsou to důvody).

- [ ] **Krok 5: Přepni asserty v `tests/test_files_authenticate.py`**

  - ř. 44: `assert verdikt.outcome == "bad_code"` → `assert verdikt.reason == "bad_code"`
  - ř. 59: `assert verdikt.outcome == "unknown_user"` → `assert verdikt.reason == "unknown_user"`
  - ř. 67: `assert verdikt.outcome == "no_secret"` → `assert verdikt.reason == "no_secret"`
  - ř. 76: `assert verdikt.outcome == "disabled"` → `assert verdikt.reason == "disabled"`
  - ř. 112: `.outcome == "replay"` → `.reason == "replay"`
  - v testu z úkolu 1 (`..._are_the_two_shapes`): oba asserty `outcome == "bad_code"` → `reason == "bad_code"`
  - asserty na `need_factor` (ř. 87, 99) zůstávají na `outcome`.

- [ ] **Krok 6: Ověř** — `pytest`; očekávání: vše zelené (68 testů).
- [ ] **Krok 7: Commit** — `git add access_manager/verdicts.py access_manager/files.py tests/ && git commit -m "verdikt: ven ctyri tvary, duvod zvlast pro audit"`

---

### Úkol 3: Výhradní zámek nad čtení-úprava-zápis

`_consume` (anti-replay) i zápisy do `groups.json` jsou čtení-úprava-zápis bez zámku. Dva procesy nad týmž adresářem (služba + admin CLI; dvě repliky se sdíleným svazkem) můžou tentýž kód spotřebovat oba — anti-replay pak neplatí — nebo si navzájem ztratit zápis členství. `_replace` chrání před poškozeným souborem, ne před ztraceným zápisem.

**Files:**
- Modify: `access_manager/files.py` (nový `_locked`, obalení `_consume`, `add_group`, `add_member`, `include`)
- Test: `tests/test_locking.py` (nový)

**Interfaces:**
- Produces: kontextový manažer `_locked(home: Path)` na úrovni modulu `files.py`; konstanta `LOCK = ".lock"`. NENÍ reentrantní — nic pod ním nesmí zamykat znovu. Úkoly 4, 6, 7 ho používají.

- [ ] **Krok 1: Napiš `tests/test_locking.py`**

```python
"""Dva procesy nad tymz adresarem si nesmi slapat po zapisech.

Anti-replay i clenstvi jsou cteni-uprava-zapis: bez zamku tyz kod projde
dvakrat (kazdy proces si precte prazdny seznam) a pomalejsi zapisujici
prepise rychlejsiho. `_replace` chrani pred poskozenym souborem, ne pred
ztracenym zapisem.
"""
import threading
import time

from access_manager import Access, Admin
from access_manager.files import _locked

from helpers import kod, zaloz


def test_the_lock_is_exclusive(tmp_path):
    poradi = []
    drzim = threading.Event()

    def drzitel():
        with _locked(tmp_path):
            drzim.set()
            time.sleep(0.2)
            poradi.append("drzitel")

    def cekatel():
        drzim.wait()
        with _locked(tmp_path):
            poradi.append("cekatel")

    vlakna = [threading.Thread(target=drzitel), threading.Thread(target=cekatel)]
    for v in vlakna:
        v.start()
    for v in vlakna:
        v.join()
    assert poradi == ["drzitel", "cekatel"]


def test_a_burst_of_the_same_code_passes_exactly_once(tmp_path):
    zaloz(tmp_path, "hana")
    access = Access.local(tmp_path)
    stejny = kod()
    zavora = threading.Barrier(8)
    verdikty = []

    def utocnik():
        zavora.wait()
        verdikty.append(
            access.authenticate("hana", {"totp": stejny}, purpose="login")
        )

    vlakna = [threading.Thread(target=utocnik) for _ in range(8)]
    for v in vlakna:
        v.start()
    for v in vlakna:
        v.join()
    assert sum(1 for v in verdikty if v) == 1


def test_two_writers_do_not_lose_each_others_members(tmp_path):
    admin = Admin.local(tmp_path)
    admin.add_group("ucetni")
    admin.add_user("hana")
    admin.add_user("petr")
    zavora = threading.Barrier(2)

    def pridej(jmeno):
        zavora.wait()
        admin.add_member("ucetni", jmeno)

    vlakna = [
        threading.Thread(target=pridej, args=("hana",)),
        threading.Thread(target=pridej, args=("petr",)),
    ]
    for v in vlakna:
        v.start()
    for v in vlakna:
        v.join()
    assert Access.local(tmp_path).group("ucetni").members == ("hana", "petr")
```

- [ ] **Krok 2: Spusť a ověř pád** — `pytest tests/test_locking.py -v`; očekávání: FAIL už při importu (`_locked` neexistuje). (Oba zátěžové testy jsou po implementaci deterministicky zelené; PŘED ní by padaly jen občas — závod je úzký. Import-fail stačí jako červená.)

- [ ] **Krok 3: Implementuj `_locked` ve `files.py`**

Nahoru k importům přidej `import fcntl` a `from contextlib import contextmanager`. Ke konstantám přidej:

```python
#: Zamek vedle dat. Jeden na cely adresar: sporu je malo a spravnost je
#: videt na prvni pohled. fcntl je POSIXovy - Windows tu nikdy nebyl cil.
LOCK = ".lock"
```

Na úroveň modulu (do sekce Pomocne) přidej:

```python
@contextmanager
def _locked(home: Path):
    """Vyhradni zamek nad celym ulozistem.

    Kazde cteni-uprava-zapis (`used.json`, `groups.json`, `gen`) musi bezet
    pod nim: dva procesy nad tymz adresarem si jinak ztrati zapis toho
    pomalejsiho - a u anti-replay by tyz kod prosel dvakrat.

    NENI reentrantni: nic, co bezi pod zamkem, nesmi zamykat znovu.
    Zavrenim deskriptoru se zamek pousti.
    """
    home.mkdir(parents=True, mode=DIR_MODE, exist_ok=True)
    os.chmod(home, DIR_MODE)
    handle = os.open(home / LOCK, os.O_WRONLY | os.O_CREAT, FILE_MODE)
    try:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield
    finally:
        os.close(handle)
```

- [ ] **Krok 4: Obal kritické sekce**

  - `_consume`: celé tělo za řádkem `path = ...` obal do `with _locked(self.home):` (včetně `return False` / `return True`).
  - `add_group`, `add_member`, `include`: vše od prvního `table = self._table()` po `self._write_table(table)` obal do `with _locked(self.home):` (kontroly `check_name` nech před zámkem).

- [ ] **Krok 5: Ověř** — `pytest`; očekávání: vše zelené (71 testů).
- [ ] **Krok 6: Commit** — `git add access_manager/files.py tests/test_locking.py && git commit -m "uloziste: vyhradni zamek nad cteni-uprava-zapis"`

---

### Úkol 4: Generace — každý zápis zvedne číslo, verdikt ho nese

Návrh: `gen` je přibalené ke každé odpovědi (§3.1), `GET /v1/generation` existuje (§3.4) a knihovna má `access.generation()` (§6). V kódu není nic z toho — klientská cache podle `gen` by neměla co číst.

**Files:**
- Modify: `access_manager/files.py` (konstanta `GEN`, `generation()`, `_bump_gen()`, bump ve všech zápisech, `gen` ve verdiktech), `access_manager/access.py` (+`generation`)
- Test: `tests/test_generation.py` (nový)

**Interfaces:**
- Consumes: `_locked` (úkol 3), `Verdict(..., gen=...)` (úkol 2).
- Produces: `FileStore.generation() -> int` (0 pro čerstvý adresář), `FileStore._bump_gen() -> None` (volat jen pod zámkem), `Access.generation() -> int`. Úkoly 6, 7 bumpují taky.

- [ ] **Krok 1: Napiš `tests/test_generation.py`**

```python
"""Generace: nezmenene cislo znamena, ze cache plati dal.

Resi napeti mezi "odvolani je okamzite" a "expiraci si hlida kazdy
komponent sam" (navrh par. 3.4) - jeden trivialni dotaz misto push kanalu.
"""
from access_manager import Access, Admin

from helpers import kod, zaloz


def test_a_fresh_home_is_generation_zero(tmp_path):
    assert Access.local(tmp_path).generation() == 0


def test_every_write_moves_the_generation(tmp_path):
    admin = Admin.local(tmp_path)
    access = Access.local(tmp_path)
    admin.add_user("hana")
    prvni = access.generation()
    admin.add_group("ucetni")
    druha = access.generation()
    admin.add_member("ucetni", "hana")
    treti = access.generation()
    assert 0 < prvni < druha < treti


def test_reading_does_not_move_the_generation(tmp_path):
    zaloz(tmp_path, "hana")
    access = Access.local(tmp_path)
    pred = access.generation()
    access.user("hana")
    access.users()
    access.groups()
    assert access.generation() == pred


def test_a_verdict_carries_the_generation(tmp_path):
    zaloz(tmp_path, "hana")
    access = Access.local(tmp_path)
    verdikt = access.authenticate("hana", {"totp": kod()}, purpose="login")
    assert verdikt.gen == access.generation()


def test_a_refusal_carries_the_generation_too(tmp_path):
    # Navrh par. 3.1: gen je pribalene ke KAZDE odpovedi, ne jen k `ok`.
    zaloz(tmp_path, "hana")
    verdikt = Access.local(tmp_path).authenticate(
        "hana", {"totp": "000000"}, purpose="login"
    )
    assert verdikt.gen == Access.local(tmp_path).generation()
```

- [ ] **Krok 2: Spusť a ověř pád** — `pytest tests/test_generation.py -v`; očekávání: FAIL (`generation` neexistuje).

- [ ] **Krok 3: Implementuj ve `files.py`**

Ke konstantám: `GEN = "gen"` (s komentářem `#: Cislo generace. Zvedne ho kazdy zapis; cteni ho jen cte.`). Do třídy `FileStore` (sekce cteni):

```python
    def generation(self) -> int:
        """Cislo generace: zvedne ho kazdy zapis. Cache plati, dokud se nehne."""
        path = self.home / GEN
        return int(path.read_text(encoding="utf-8")) if path.is_file() else 0
```

Do sekce zapisu:

```python
    def _bump_gen(self) -> None:
        # Volat JEN pod _locked - jinak se dva zapisy sejdou na temz cisle.
        _replace(self.home / GEN, str(self.generation() + 1))
```

- [ ] **Krok 4: Zaveď bump do všech zápisů**

  - `add_group`, `add_member`, `include`: uvnitř `with _locked(...)` přidej `self._bump_gen()` hned za `self._write_table(table)`.
  - `add_user` přepiš (mkdir domova řeší `_locked`, proto bez `parents=True`):

```python
    def add_user(self, name: str) -> Enrolment:
        name = check_name(name)
        with _locked(self.home):
            directory = self.home / f"user-{name}"
            if directory.exists():
                raise ValueError(
                    f"uzivatel {name!r} uz existuje ({directory}); prepsat jeho "
                    f"tajemstvi by ho zamklo ven"
                )
            directory.mkdir(mode=DIR_MODE)
            os.chmod(directory, DIR_MODE)  # mkdir podleha umask, chmod ne
            enrolment = self._pair(name, directory)
            self._bump_gen()
        return enrolment
```

  - `pair_missing`: obal smyčku do `with _locked(self.home):` a před `return` (uvnitř zámku) přidej:

```python
            if doplneno:
                self._bump_gen()
```

- [ ] **Krok 5: Přibal gen k verdiktům** — přepiš `authenticate` (jen doplnění `gen`, logika beze změny):

```python
    def authenticate(self, username: str, credentials, *, purpose: str) -> Verdict:
        """Odpoved na "jsi to ty?" - nikdy na "smis to?"."""
        purpose = check_purpose(purpose)
        name = check_name(username)
        directory = self.home / f"user-{name}"
        gen = self.generation()

        if not directory.is_dir():
            return Verdict.refused("unknown_user", gen=gen)
        if (directory / "disabled").exists():
            return Verdict.refused("disabled", gen=gen)

        secret = directory / "totp.secret"
        if not secret.is_file():
            # Zalozeny adresar bez tajemstvi neni "spatny kod": je to
            # nedokoncene zavedeni a spravce to ma poznat z auditu.
            return Verdict.refused("no_secret", gen=gen)

        # Co je potreba, rozhoduje KOMPONENTA. Nezname jmeno mechanismu se
        # chova, jako by neprislo - jinak si klient vybere ten slabsi.
        code = dict(credentials or {}).get("totp")
        if not code:
            return Verdict.need_factor(("totp",), gen=gen)

        step = _matching_step(secret.read_text(encoding="utf-8").strip(), code)
        if step is None:
            return Verdict.refused("bad_code", gen=gen)
        if not self._consume(name, purpose, step):
            return Verdict.refused("replay", gen=gen)

        user = self.user(name)
        return Verdict.ok(user.subject_id, user.principals, gen=gen)
```

- [ ] **Krok 6: Vystav v `access.py`** — do sekce identita přidej:

```python
    def generation(self) -> int:
        """Cislo generace: nezmenene znamena, ze drzena odpoved plati dal."""
        return self._store.generation()
```

- [ ] **Krok 7: Ověř** — `pytest`; očekávání: vše zelené (76 testů).
- [ ] **Krok 8: Commit** — `git add access_manager/ tests/test_generation.py && git commit -m "generace: kazdy zapis zvedne cislo, verdikt ho nese"`

---

### Úkol 5: Vyhrazené skupiny nejdou založit

README i návrh: `group:users` a `group:public` jsou vyhrazené — každý je dostane automaticky a nejdou odebrat. Dnes ale `add_group("users")` normálně projde a vznikne druhá pravda o témž jménu (spravovatelné členství ve skupině, která má být automatická).

**Files:**
- Modify: `access_manager/principals.py` (+`RESERVED_GROUPS`), `access_manager/files.py` (`add_group` odmítá)
- Test: `tests/test_admin.py`

**Interfaces:**
- Produces: `principals.RESERVED_GROUPS = frozenset({"users", "public"})` (interní, neexportuje se z balíčku — stejný důvod jako u `PUBLIC`/`USERS`).

- [ ] **Krok 1: Failing test** — do `tests/test_admin.py`, sekce Skupiny:

```python
@pytest.mark.parametrize("jmeno", ["users", "public"])
def test_a_reserved_group_cannot_be_created(tmp_path, jmeno):
    # `group:users` a `group:public` dostava kazdy automaticky. Zalozit je
    # jako obycejne skupiny znamena dve pravdy o temz jmene.
    with pytest.raises(ValueError):
        Admin.local(tmp_path).add_group(jmeno)
```

- [ ] **Krok 2: Ověř pád** — `pytest tests/test_admin.py -v -k reserved`; očekávání: FAIL (skupina se založí).

- [ ] **Krok 3: Implementuj** — do `principals.py` pod konstantu `USERS`:

```python
#: Vyhrazena jmena skupin - hola, bez prefixu. Kazdy je dostava automaticky
#: (viz `USERS` a `PUBLIC`), takze zalozit je jako obycejne skupiny znamena
#: dve pravdy o temz jmene.
RESERVED_GROUPS = frozenset({"users", "public"})
```

Ve `files.py` přidej `RESERVED_GROUPS` do importu z `.principals` a na začátek `add_group` (za `check_name`):

```python
        if name in RESERVED_GROUPS:
            raise ValueError(
                f"skupina {name!r} je vyhrazena: clenstvi v ni je automaticke "
                f"a nejde spravovat"
            )
```

- [ ] **Krok 4: Ověř** — `pytest`; očekávání: vše zelené (78 testů).
- [ ] **Krok 5: Commit** — `git add access_manager/ tests/test_admin.py && git commit -m "vyhrazene skupiny nejdou zalozit"`

---

### Úkol 6: Životní cyklus — disable, enable, remove_member, remove_user

Návrh §3.2c jmenuje `POST .../disable`, `POST .../enable`, `DELETE /v1/users/hana` a `DELETE .../members/hana`. V knihovně není nic z toho: soubor `disabled` umí `authenticate` číst, ale nikdo ho neumí založit; členství nejde odebrat; smazání uživatele neexistuje, přestože „právě to dělá ze smazání účinný zásah“ (§3.2).

**Files:**
- Modify: `access_manager/files.py` (+4 metody, `import shutil`), `access_manager/admin.py` (+4 metody), `tests/test_split.py` (rozšířit `ZAPISOVE`)
- Test: `tests/test_lifecycle.py` (nový)

**Interfaces:**
- Consumes: `_locked`, `_bump_gen` (úkoly 3, 4), `Verdict.reason` (úkol 2).
- Produces: `FileStore.disable_user(name)`, `enable_user(name)`, `remove_member(group, name)`, `remove_user(name)` — všechny `-> None`, na `Admin` stejná jména delegující 1:1. Neznámý uživatel/skupina → `ValueError`; opakované volání (už vypnutý, člen už pryč) je neškodné a generaci nezvedá.

- [ ] **Krok 1: Napiš `tests/test_lifecycle.py`**

```python
"""Zivotni cyklus: vypnout, zapnout, odebrat clenstvi, smazat cloveka.

Zablokovat cloveka na tri dny je bezny ukon; smazat ho kvuli tomu znamena
prijit o jeho clenstvi i o auditni stopu (navrh par. 3.1). Proto jsou
disable a remove dva ruzne ukony a oba tu musi byt.
"""
import pytest

from access_manager import Access, Admin

from helpers import kod, skupiny, zaloz


def test_a_disabled_user_stops_authenticating(tmp_path):
    zaloz(tmp_path, "hana")
    Admin.local(tmp_path).disable_user("hana")
    verdikt = Access.local(tmp_path).authenticate(
        "hana", {"totp": kod()}, purpose="login"
    )
    assert verdikt.reason == "disabled"


def test_an_enabled_user_authenticates_again(tmp_path):
    zaloz(tmp_path, "hana")
    admin = Admin.local(tmp_path)
    admin.disable_user("hana")
    admin.enable_user("hana")
    assert Access.local(tmp_path).authenticate(
        "hana", {"totp": kod()}, purpose="login"
    )


def test_disabling_keeps_the_membership(tmp_path):
    # Vypnuty clovek neni smazany clovek: clenstvi i auditni stopa zustavaji.
    zaloz(tmp_path, "hana")
    skupiny(tmp_path, {"ucetni": {"members": ["hana"]}})
    Admin.local(tmp_path).disable_user("hana")
    user = Access.local(tmp_path).user("hana")
    assert not user.enabled
    assert "group:ucetni" in user.principals


def test_disabling_twice_is_harmless(tmp_path):
    zaloz(tmp_path, "hana")
    admin = Admin.local(tmp_path)
    admin.disable_user("hana")
    admin.disable_user("hana")
    assert not Access.local(tmp_path).user("hana").enabled


def test_disabling_an_unknown_user_is_refused(tmp_path):
    with pytest.raises(ValueError):
        Admin.local(tmp_path).disable_user("nikdo")


def test_a_removed_member_loses_the_group(tmp_path):
    admin = Admin.local(tmp_path)
    admin.add_user("hana")
    admin.add_group("ucetni")
    admin.add_member("ucetni", "hana")
    admin.remove_member("ucetni", "hana")
    assert "group:ucetni" not in Access.local(tmp_path).user("hana").principals


def test_removing_an_absent_member_is_harmless(tmp_path):
    # DELETE je idempotentni: "uz tam neni" je splneny cil, ne chyba.
    admin = Admin.local(tmp_path)
    admin.add_group("ucetni")
    admin.remove_member("ucetni", "hana")


def test_removing_a_member_from_an_unknown_group_is_refused(tmp_path):
    with pytest.raises(ValueError):
        Admin.local(tmp_path).remove_member("neni", "hana")


def test_a_removed_user_is_gone_even_from_member_lists(tmp_path):
    # Smazani je ucinny zasah (navrh par. 3.2) - a po sobe nesmi nechat
    # jmeno v zadnem seznamu clenu.
    admin = Admin.local(tmp_path)
    admin.add_user("hana")
    admin.add_group("ucetni")
    admin.add_member("ucetni", "hana")
    admin.remove_user("hana")
    access = Access.local(tmp_path)
    assert access.user("hana") is None
    assert access.group("ucetni").members == ()
    verdikt = access.authenticate("hana", {"totp": "123456"}, purpose="login")
    assert verdikt.reason == "unknown_user"


def test_removing_an_unknown_user_is_refused(tmp_path):
    with pytest.raises(ValueError):
        Admin.local(tmp_path).remove_user("nikdo")


def test_lifecycle_writes_move_the_generation(tmp_path):
    admin = Admin.local(tmp_path)
    access = Access.local(tmp_path)
    admin.add_user("hana")
    pred = access.generation()
    admin.disable_user("hana")
    assert access.generation() > pred
```

- [ ] **Krok 2: Ověř pád** — `pytest tests/test_lifecycle.py -v`; očekávání: FAIL (`disable_user` neexistuje).

- [ ] **Krok 3: Implementuj ve `files.py`** — nahoru `import shutil`; do třídy nová sekce za zápis skupin:

```python
    # == zapis: zivotni cyklus =============================================

    def _existing_user_dir(self, name: str) -> Path:
        directory = self.home / f"user-{name}"
        if not directory.is_dir():
            raise ValueError(f"uzivatel {name!r} neexistuje")
        return directory

    def disable_user(self, name: str) -> None:
        """Docasne vypnuti. Clenstvi i auditni stopa zustavaji."""
        name = check_name(name)
        directory = self._existing_user_dir(name)
        if (directory / "disabled").exists():
            return
        with _locked(self.home):
            _write(directory / "disabled", "")
            self._bump_gen()

    def enable_user(self, name: str) -> None:
        name = check_name(name)
        directory = self._existing_user_dir(name)
        if not (directory / "disabled").exists():
            return
        with _locked(self.home):
            (directory / "disabled").unlink(missing_ok=True)
            self._bump_gen()

    def remove_member(self, group: str, name: str) -> None:
        group, name = check_name(group), check_name(name)
        with _locked(self.home):
            table = self._table()
            if group not in table:
                raise ValueError(f"skupina {group!r} neexistuje")
            members = set(table[group].get("members", ()))
            if name not in members:
                # DELETE je idempotentni: "uz tam neni" je splneny cil.
                return
            members.discard(name)
            table[group]["members"] = sorted(members)
            self._write_table(table)
            self._bump_gen()

    def remove_user(self, name: str) -> None:
        """Smaz cloveka VCETNE jmena v seznamech clenu.

        Principaly se pocitaji pri kazdem dotazu, takze zasah je ucinny uz
        smazanim adresare - ale jmeno visici v `groups.json` by matlo kazdy
        audit a jednou by se pod nim zalozil nekdo jiny.
        """
        name = check_name(name)
        directory = self._existing_user_dir(name)
        with _locked(self.home):
            table = self._table()
            for data in table.values():
                if name in data.get("members", ()):
                    data["members"] = sorted(set(data["members"]) - {name})
            self._write_table(table)
            shutil.rmtree(directory)
            self._bump_gen()
```

- [ ] **Krok 4: Vystav v `admin.py`** — do sekce lide:

```python
    def disable_user(self, name: str) -> None:
        """Docasne vypnuti - clenstvi i auditni stopa zustavaji."""
        self._store.disable_user(name)

    def enable_user(self, name: str) -> None:
        self._store.enable_user(name)

    def remove_user(self, name: str) -> None:
        """Smazani vcetne clenstvi. Na tri dny se clovek vypina, ne maze."""
        self._store.remove_user(name)
```

do sekce skupiny:

```python
    def remove_member(self, group: str, name: str) -> None:
        self._store.remove_member(group, name)
```

- [ ] **Krok 5: Rozšiř `tests/test_split.py`** — `ZAPISOVE = ["add_user", "add_group", "add_member", "include", "disable_user", "enable_user", "remove_member", "remove_user", "pair_missing"]` (tím se ověří, že `Access` nic z toho nemá a `Admin` všechno).

- [ ] **Krok 6: Ověř** — `pytest`; očekávání: vše zelené (~99 testů).
- [ ] **Krok 7: Commit** — `git add access_manager/ tests/ && git commit -m "zivotni cyklus: disable, enable, remove_member, remove_user"`

---

### Úkol 7: Ztracený telefon — revoke_credential a nové párování

Návrh §3.2c: „Bez rotace a odvolání nemá ztracený telefon řešení.“ `DELETE .../credentials/totp` v knihovně chybí; jediné párování je `pair_missing` přes všechny. Odvolání musí smazat i `used.json` — čísla spotřebovaných kroků patří ke starému tajemství a s novým by týž krok byl falešný replay.

**Files:**
- Modify: `access_manager/files.py` (+`revoke_credential`, `pair`), `access_manager/admin.py` (+2 metody), `tests/test_split.py` (`ZAPISOVE` + `revoke_credential`, `pair`)
- Test: `tests/test_lifecycle.py` (přidat sekci)

**Interfaces:**
- Consumes: `_locked`, `_bump_gen`, `_pair`, `_existing_user_dir` (úkoly 3, 4, 6).
- Produces: `FileStore.revoke_credential(name, mechanism="totp") -> None`, `FileStore.pair(name) -> Enrolment`; totéž na `Admin`. `pair` ODMÍTNE existující tajemství (`ValueError`) — jediná cesta k novému je revoke + pair.

- [ ] **Krok 1: Failing testy** — do `tests/test_lifecycle.py`:

```python
# ===========================================================================
# Ztraceny telefon: odvolat a znovu sparovat
# ===========================================================================


def test_a_revoked_credential_refuses_as_no_secret(tmp_path):
    zaloz(tmp_path, "hana")
    Admin.local(tmp_path).revoke_credential("hana")
    verdikt = Access.local(tmp_path).authenticate(
        "hana", {"totp": kod()}, purpose="login"
    )
    assert verdikt.reason == "no_secret"


def test_pairing_never_overwrites_an_existing_secret(tmp_path):
    # Stejne pravidlo jako u add_user: prepsat tajemstvi znamena zamknout
    # cloveka ven. Jedina cesta k novemu je revoke + pair.
    zaloz(tmp_path, "hana")
    with pytest.raises(ValueError):
        Admin.local(tmp_path).pair("hana")


def test_revoke_and_pair_issue_a_different_secret(tmp_path):
    admin = Admin.local(tmp_path)
    admin.add_user("hana")
    stare = (tmp_path / "user-hana" / "totp.secret").read_text()
    admin.revoke_credential("hana")
    admin.pair("hana")
    assert (tmp_path / "user-hana" / "totp.secret").read_text() != stare


def test_revocation_forgets_the_used_steps_of_the_old_secret(tmp_path):
    # Cisla spotrebovanych kroku patri ke STAREMU tajemstvi. Kdyby prezila,
    # prvni kod z noveho telefonu by v temz okne vypadal jako replay.
    zaloz(tmp_path, "hana")
    access = Access.local(tmp_path)
    assert access.authenticate("hana", {"totp": kod()}, purpose="login")
    admin = Admin.local(tmp_path)
    admin.revoke_credential("hana")
    admin.pair("hana")
    nove = (tmp_path / "user-hana" / "totp.secret").read_text().strip()
    assert access.authenticate("hana", {"totp": kod(nove)}, purpose="login")


def test_an_unknown_mechanism_cannot_be_revoked(tmp_path):
    zaloz(tmp_path, "hana")
    with pytest.raises(ValueError):
        Admin.local(tmp_path).revoke_credential("hana", mechanism="password")
```

- [ ] **Krok 2: Ověř pád** — `pytest tests/test_lifecycle.py -v -k "revok or pair"`; očekávání: FAIL (`revoke_credential` neexistuje).

- [ ] **Krok 3: Implementuj ve `files.py`** — do sekce zivotni cyklus:

```python
    def revoke_credential(self, name: str, mechanism: str = "totp") -> None:
        """Odvolani povereni - reseni ztraceneho telefonu.

        Maze i `used.json`: cisla spotrebovanych kroku patri ke staremu
        tajemstvi a s novym by tyz krok byl falesny replay.
        """
        if mechanism != "totp":
            raise ValueError(
                f"neznamy mechanismus {mechanism!r}; zatim existuje jen 'totp'"
            )
        name = check_name(name)
        directory = self._existing_user_dir(name)
        with _locked(self.home):
            for artefakt in ("totp.secret", "totp.uri", "totp.txt", "used.json"):
                (directory / artefakt).unlink(missing_ok=True)
            self._bump_gen()

    def pair(self, name: str) -> Enrolment:
        """Nove parovani JEDNOHO cloveka. Existujici tajemstvi neprepise."""
        name = check_name(name)
        directory = self._existing_user_dir(name)
        if (directory / "totp.secret").is_file():
            raise ValueError(
                f"uzivatel {name!r} uz tajemstvi ma; nejdriv revoke_credential - "
                f"prepsani by ho zamklo ven"
            )
        with _locked(self.home):
            (directory / "used.json").unlink(missing_ok=True)
            enrolment = self._pair(name, directory)
            self._bump_gen()
        return enrolment
```

- [ ] **Krok 4: Vystav v `admin.py`** — do sekce lide:

```python
    def revoke_credential(self, name: str, mechanism: str = "totp") -> None:
        """Ztraceny telefon: odvolat, pak `pair` pro novy."""
        self._store.revoke_credential(name, mechanism)

    def pair(self, name: str) -> Enrolment:
        """Nove parovani jednoho cloveka. Existujici tajemstvi neprepise."""
        return self._store.pair(name)
```

- [ ] **Krok 5: Rozšiř `tests/test_split.py`** — do `ZAPISOVE` přidej `"revoke_credential"`, `"pair"`.
- [ ] **Krok 6: Ověř** — `pytest`; očekávání: vše zelené (~106 testů).
- [ ] **Krok 7: Commit** — `git add access_manager/ tests/ && git commit -m "ztraceny telefon: revoke_credential a nove parovani"`

---

### Úkol 8: add_user bez torza a srozumitelná chyba bez pyotp

Dnes `add_user` nejdřív vyrobí adresář a teprve `_pair` importuje pyotp. Bez nainstalovaného `[totp]` spadne holým `ModuleNotFoundError` (bez nápovědy, kterou `_matching_step` má) a nechá po sobě torzo: adresář bez tajemství, na kterém druhý pokus řekne zavádějící „přepsat jeho tajemství by ho zamklo ven“.

**Files:**
- Modify: `access_manager/files.py` (`_require_totp`, `_require_pairing`, preflight v `add_user`/`pair`/`pair_missing`, zjednodušení `_matching_step`, nápověda v `_qr_text`)
- Test: `tests/test_admin.py`

**Interfaces:**
- Consumes: `add_user`/`pair`/`pair_missing` z úkolů 4, 7.
- Produces: `_require_totp() -> module` (jen pyotp — ověřovací cesta nesmí chtít qrcode), `_require_pairing() -> None` (pyotp i qrcode). Obě modulové, obě hlásí `pip install 'access-manager[totp]'`.

- [ ] **Krok 1: Failing test** — do `tests/test_admin.py` (nahoru přidej `import sys`):

```python
def test_missing_pyotp_says_how_to_install_and_leaves_nothing(tmp_path, monkeypatch):
    # Pad az UVNITR zavadeni nechava torzo: adresar bez tajemstvi, na kterem
    # druhy pokus lze rekne "uz existuje". Selhat se musi driv - a s navodem.
    monkeypatch.setitem(sys.modules, "pyotp", None)
    with pytest.raises(RuntimeError, match=r"access-manager\[totp\]"):
        Admin.local(tmp_path).add_user("hana")
    assert not (tmp_path / "user-hana").exists()
```

- [ ] **Krok 2: Ověř pád** — `pytest tests/test_admin.py -v -k missing_pyotp`; očekávání: FAIL (padne `ImportError`, ne `RuntimeError`, a torzo existuje).

- [ ] **Krok 3: Implementuj** — do sekce Pomocne ve `files.py`:

```python
def _require_totp():
    """Vrat pyotp, nebo rekni JAK ho doinstalovat - ne jen ze chybi."""
    try:
        import pyotp
    except ImportError as chybi:
        raise RuntimeError(
            "TOTP potrebuje pyotp: pip install 'access-manager[totp]'"
        ) from chybi
    return pyotp


def _require_pairing() -> None:
    """Parovani chce pyotp i qrcode. Selhat ma DRIV, nez po nem neco zbyde."""
    try:
        import pyotp  # noqa: F401
        import qrcode  # noqa: F401
    except ImportError as chybi:
        raise RuntimeError(
            "zavadeni potrebuje pyotp a qrcode: pip install 'access-manager[totp]'"
        ) from chybi
```

Použití:
  - `add_user`: hned za `name = check_name(name)` přidej `_require_pairing()` (před `with _locked(...)`).
  - `pair` (úkol 7): totéž, za `check_name`.
  - `pair_missing`: `_require_pairing()` jako první řádek těla.
  - `_pair`: smaž `import pyotp` a použij `pyotp = _require_totp()`.
  - `_matching_step`: smaž try/except kolem `import pyotp` a nahraď `pyotp = _require_totp()`.
  - `_qr_text`: `import qrcode` obal stejně — `except ImportError` → `RuntimeError("textovy QR potrebuje qrcode: pip install 'access-manager[totp]'")`.

- [ ] **Krok 4: Test práv domovského adresáře** — do `tests/test_admin.py` (pojistka chování z úkolu 3, kde `_locked` domov zakládá i chmoduje; dřív ho `mkdir(parents=True)` nechával s právy podle umask a kdokoli si mohl vypsat jména uživatelů):

```python
def test_the_home_is_private_from_the_first_write(tmp_path):
    # Vypis `user-*` adresaru je seznam uzivatelu - domov musi byt 0700
    # od prvniho zapisu, ne az od druheho.
    home = tmp_path / "am"
    Admin.local(home).add_user("hana")
    assert stat.S_IMODE(home.stat().st_mode) == 0o700
```

- [ ] **Krok 5: Ověř** — `pytest`; očekávání: vše zelené (~108 testů).
- [ ] **Krok 6: Commit** — `git add access_manager/files.py tests/test_admin.py && git commit -m "add_user: srozumitelna chyba bez pyotp a zadne torzo"`

---

### Úkol 9: Čtecí povrch — unknown_principals a ready

Návrh §6 jmenuje `access.unknown_principals(names)` (kontrola deklarace při `serve()`, §3.3) a `access.ready()` (zrcadlo `/readyz`, §3.4). Ani jedno neexistuje.

**Files:**
- Modify: `access_manager/files.py` (+`unknown_principals`, `_principal_exists`, `ready`), `access_manager/access.py` (+2 metody)
- Test: `tests/test_files_identity.py`

**Interfaces:**
- Consumes: `USERS`, `PUBLIC` z `principals.py`, `_table` z `files.py`.
- Produces: `FileStore.unknown_principals(names) -> list[str]` (setříděný, bez duplicit; zdeformované jméno = neznámý principál, ne výjimka — kontrola při startu má vyjmenovat všechno, ne spadnout na prvním překlepu), `FileStore.ready() -> str | None` (None = připraveno). Obojí na `Access` 1:1.

- [ ] **Krok 1: Failing testy** — do `tests/test_files_identity.py`:

```python
# ===========================================================================
# Existuji tyhle principaly? (navrh par. 3.3)
# ===========================================================================


def test_existing_principals_are_not_unknown(tmp_path):
    zaloz(tmp_path, "hana")
    skupiny(tmp_path, {"ucetni": {"members": []}})
    assert Access.local(tmp_path).unknown_principals(
        ["user:hana", "group:ucetni", USERS, PUBLIC]
    ) == []


def test_a_typo_in_a_group_is_reported(tmp_path):
    # `default_access` se skupinou, ktera neexistuje, je slib, ktery
    # instance nemuze splnit - dnes to konci prazdnou obrazovkou.
    skupiny(tmp_path, {"ucetni": {"members": []}})
    assert Access.local(tmp_path).unknown_principals(["group:ucetnii"]) == [
        "group:ucetnii"
    ]


def test_a_malformed_principal_is_unknown_not_an_error(tmp_path):
    # Kontrola pri startu ma vyjmenovat vsechno spatne, ne spadnout na
    # prvnim preklepu.
    assert Access.local(tmp_path).unknown_principals(["group:../x", "cokoli"]) == [
        "cokoli",
        "group:../x",
    ]


# ===========================================================================
# Pripravenost uloziste (zrcadlo /readyz, navrh par. 3.4)
# ===========================================================================


def test_an_existing_home_is_ready(tmp_path):
    assert Access.local(tmp_path).ready() is None


def test_a_missing_home_is_not_ready(tmp_path):
    # Neexistujici domov je spatne pripojeny svazek, ne cerstva instalace.
    assert Access.local(tmp_path / "nikde").ready() is not None


def test_a_corrupt_groups_file_is_not_ready(tmp_path):
    (tmp_path / "groups.json").write_text("{zlomeno", encoding="utf-8")
    assert "groups.json" in Access.local(tmp_path).ready()
```

- [ ] **Krok 2: Ověř pád** — `pytest tests/test_files_identity.py -v`; očekávání: FAIL (`unknown_principals` neexistuje).

- [ ] **Krok 3: Implementuj ve `files.py`** — do sekce cteni:

```python
    def unknown_principals(self, names) -> list[str]:
        """Ktere z principalu NEEXISTUJI - hromadne, kvuli startu instance.

        Zdeformovane jmeno je "neznamy", ne vyjimka: kontrola deklarace ma
        vyjmenovat vsechno spatne najednou, ne spadnout na prvnim preklepu.
        """
        return sorted({str(p) for p in names if not self._principal_exists(str(p))})

    def _principal_exists(self, principal: str) -> bool:
        if principal in (USERS, PUBLIC):
            return True
        kind, _, name = principal.partition(":")
        try:
            name = check_name(name)
        except ValueError:
            return False
        if kind == "group":
            return name in self._table()
        if kind == "user":
            return (self.home / f"user-{name}").is_dir()
        return False

    def ready(self) -> str | None:
        """`None` znamena pripraveno; jinak duvod. Zrcadli budouci /readyz.

        Neexistujici domov je duvod: sluzba se spatne pripojenym svazkem ma
        rict "nejsem", ne obsluhovat prazdno a vsem odpovidat `unknown_user`.
        """
        if not self.home.is_dir():
            return f"uloziste neexistuje: {self.home}"
        try:
            self._table()
        except (OSError, json.JSONDecodeError) as chyba:
            return f"{GROUPS} nejde precist: {chyba}"
        return None
```

- [ ] **Krok 4: Vystav v `access.py`**:

```python
    def unknown_principals(self, names) -> list[str]:
        """Ktere z principalu neexistuji - hromadne, kvuli startu instance."""
        return self._store.unknown_principals(names)

    def ready(self) -> str | None:
        """`None` znamena pripraveno; jinak duvod."""
        return self._store.ready()
```

- [ ] **Krok 5: Ověř** — `pytest`; očekávání: vše zelené (~114 testů).
- [ ] **Krok 6: Commit** — `git add access_manager/ tests/test_files_identity.py && git commit -m "cteci povrch: unknown_principals a ready"`

---

### Úkol 10: Nářadí — ruff a aktuální README

Repo nemá žádný lint; a README tvrdí „64 testů“, což po tomhle plánu přestane platit.

**Files:**
- Modify: `pyproject.toml`, `README.md`, případné drobné opravy z ruffu

- [ ] **Krok 1: Konfigurace** — do `pyproject.toml` přidej:

```toml
[tool.ruff]
line-length = 88
target-version = "py312"

[tool.ruff.lint]
select = ["E", "F", "W", "I", "B", "UP"]
```

a do `dev` extra přidej `"ruff>=0.6"`.

- [ ] **Krok 2: Spusť** — `.venv/bin/pip install -e '.[dev]' && .venv/bin/ruff check .` a oprav, co nahlásí (čekej hlavně přeskládané importy z `I`; chování se nesmí změnit). Pokud `ruff` navrhne autofix, použij `ruff check --fix .` a diff zkontroluj.

- [ ] **Krok 3: Aktualizuj README** — v sekci Stav spusť `pytest -q`, vezmi počet z posledního řádku výstupu a nahraď „(64 testu, bezi bez site i bez serveru)“ skutečným počtem. Ve stejné sekci rozšiř větu o hotové vrstvě: po „anti-replay a cela zapisova pulka“ doplň „vcetne zivotniho cyklu (disable, remove, revoke + nove parovani), generace a kontroly principalu“.

- [ ] **Krok 4: Ověř** — `pytest` a `ruff check .`; očekávání: obojí čisté.
- [ ] **Krok 5: Commit** — `git add pyproject.toml README.md access_manager/ tests/ && git commit -m "naradi: ruff a aktualni stav v README"`

---

## Self-review (proběhla při psaní plánu)

- **Pokrytí návrhu:** §3.1 čtyři tvary → úkol 2; `gen` u každé odpovědi → úkol 4; §3.2c životní cyklus → úkoly 6–7; §3.3 kontrola principálů → úkol 9; §3.4 generation/ready → úkoly 4, 9; §4 sdílený stav (v mezích souborového backendu) → úkol 3; vyhrazené skupiny (README) → úkol 5. Vědomě mimo: služba, remote klient, throttling, origin ACL, audit, fragmentovaná konfigurace — viz úvod.
- **Typová konzistence:** `Verdict.refused(reason, gen=None)` a `Verdict.need_factor(required, gen=None)` z úkolu 2 se používají v úkolech 4, 6, 7 se stejnými signaturami; `_locked(home)` z úkolu 3 v úkolech 4, 6, 7; `_existing_user_dir` z úkolu 6 v úkolu 7; `_require_pairing` z úkolu 8 se do `pair` (úkol 7) doplňuje až v úkolu 8 (v pořadí úkolů je to řečeno explicitně).
- **Placeholders:** žádné TBD; všechny testy i implementace jsou vypsané. Jediné hodnoty určované až při exekuci jsou počty testů („očekávání: ~N“) a číslo do README (krok s přesným postupem).
