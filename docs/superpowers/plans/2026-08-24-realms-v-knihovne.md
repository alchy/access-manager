# Realms v knihovně — implementační plán

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implementovat do knihovny vše z odsouhlaseného specu realms, co nevyžaduje HTTP: jmenné prostory (realm = subadresář), identity správců s dvoukódovým ověřením, platnost párovacího QR, klíče aplikací (otisky), per-realm audit a reconcile z deklarací.

**Architecture:** `FileStore` zůstává jediná úložná vrstva — dostane kořen `realm-<název>/` a poroste o admin identity, komponenty a audit. `Access`/`Admin` vážou realm při konstrukci. Nové moduly: `realms.py` (kořen realmu + reconcile) a `audit.py` (JSONL zapisovač/čtečka). Ověření správce je metoda `FileStore` — na fasády se nevystavuje (interní povrch budoucí konzole).

**Tech Stack:** Python ≥ 3.12, pytest, ruff; volitelné extras pyotp+qrcode (`[totp]`), `secrets`/`hashlib` ze stdlib. Žádné povinné závislosti.

**Spec:** `docs/superpowers/specs/2026-08-23-realms-design.md` (odsouhlasený). Normativní pozadí: `docs/design.md`.

## Global Constraints

- `dependencies = []`; pyotp/qrcode jen lazy-importem přes `_require_totp`/`_require_pairing`.
- Testy bez sítě a serveru: `./.venv/bin/python -m pytest`; po každém úkolu zelené; `./.venv/bin/ruff check .` čistý (config už v pyproject).
- **Žádný výchozí realm.** `Access.local(home, realm=...)` a `Admin.local(home, realm=...)` mají realm povinný (keyword-only). `FileStore` bere přímo kořen realmu.
- Všechna jména se **normalizují na malá písmena**; uživatelé a správci smí mít **právě jeden `@`** (e-mail), skupiny a realmy ne.
- Existující tajemství se nikdy nepřepíše; tajemství/kódy nikdy do repr, logů ani auditu (jen čísla kroků a `key_id`).
- `_locked` NENÍ reentrantní; `_bump_gen` a auditní zápis běží jen pod zámkem daného zápisu; žádné vnořené zamykání.
- Verdikt: 4 veřejné tvary; `expired` dostává výrobce (QR TTL). Vyhrazené skupiny `users`/`public` platí per realm (už hotové — kořenem).
- Párovací štítek má tvar `<realm>-<role>-<jméno>` (role `member`/`admin`), vydavatel = název realmu. Štítek se nikdy neparsuje.
- Kód a komentáře česky bez diakritiky; jména testů anglicky; commity česky, malými písmeny, s trailerem `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` po prázdném řádku.
- Rozhodnutí plánu (vědomá): auditní událost ověření nese pole `subject` (`user:hana` / `admin:jindrich`) místo `user` ze specového příkladu — jeden klíč pro obě role; formát auditu je vnitřní, ne drát. `totp.issued` nese epochu (celé sekundy). Adresář bez `totp.issued` (starší/ručně založený) neexpiruje.

## Struktura souborů po úkolech

| Soubor | Odpovědnost | Změna |
|---|---|---|
| `access_manager/principals.py` | jména (3 kontroly), záznamy, `Component` | úkoly 1, 6 |
| `access_manager/realms.py` | kořen realmu, `reconcile` | úkoly 2, 8 (nový) |
| `access_manager/files.py` | úložiště: + admin identity, QR platnost, dvoukód, komponenty, napojení auditu | úkoly 3–7 |
| `access_manager/audit.py` | JSONL append/čtení/retence | úkol 7 (nový) |
| `access_manager/access.py`, `admin.py`, `__init__.py` | realm ve fasádách, nové delegace, exporty | úkoly 2, 3, 6, 9 |
| `tests/helpers.py` | + `REALM`, `koren(home)`; zakládání pod realm | úkol 2 |
| `tests/test_realms.py`, `test_admins.py`, `test_qr_validity.py`, `test_components.py`, `test_audit.py`, `test_reconcile.py` | nové oblasti | úkoly 2–8 |

Mimo rozsah: HTTP služba, `Access.remote`, origin ACL vynucování, throttling, konzole. `component_for_key` je připravené rozhraní pro službu, vynucovat ho bude až ona.

---

### Úkol 1: Jména — tři kontroly, malá písmena, e-mail

**Files:**
- Modify: `access_manager/principals.py`, `access_manager/files.py` (call sites), `tests/test_files_identity.py`

**Interfaces:**
- Produces: `check_name(name) -> str` (skupiny: malá písmena, bez `@` — stávající jméno funkce zůstává), `check_identity(name) -> str` (lidé/správci: + právě jeden `@`), `check_realm(name) -> str` (pravidla jako skupiny; FQDN projde). Všechny stripují, **lowercase-ují** a při neshodě řeknou ValueError. Úkoly 2–8 je konzumují.

- [ ] **Krok 1: Failing testy** — do `tests/test_files_identity.py` (sekce Existence):

```python
def test_names_are_normalized_to_lowercase(tmp_path):
    zaloz(tmp_path, "hana")
    assert Access.local(tmp_path).user("Hana") is not None


def test_an_email_is_a_valid_user_name(tmp_path):
    zaloz(tmp_path, "jindrich.nemec@yahoo.com")
    user = Access.local(tmp_path).user("jindrich.nemec@yahoo.com")
    assert user is not None
    assert user.subject_id == "user:jindrich.nemec@yahoo.com"


def test_two_ats_are_refused(tmp_path):
    with pytest.raises(ValueError):
        Access.local(tmp_path).user("a@b@c")
```

(Pozn.: v tomto úkolu volání `Access.local(tmp_path)` ještě nemá realm — realm přijde v úkolu 2 a tyto testy se v jeho sweepu upraví spolu s ostatními.)

- [ ] **Krok 2: Ověř pád** — `pytest tests/test_files_identity.py -v`; očekávání: FAIL (velké písmeno projde beze změny → adresář nenajde; `@` je odmítnut).

- [ ] **Krok 3: Implementuj v `principals.py`** — nahraď blok `_NAME`/`check_name`:

```python
#: Jmeno se sklada do cesty i do principalu, takze je to VSTUP a chova se
#: jako vstup. Vsechna jmena se normalizuji na mala pismena: `Example.com`
#: a `example.com` nesmi byt dva realmy, `Jindrich` a `jindrich` dva lide.
_NAME = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)*$")

#: Lide a spravci smi mit PRAVE JEDEN zavinac - identifikatorem muze byt
#: e-mailova adresa. Skupiny a realmy zavinac nemaji.
_IDENTITY = re.compile(
    r"^[a-z0-9_-]+(\.[a-z0-9_-]+)*(@[a-z0-9_-]+(\.[a-z0-9_-]+)*)?$"
)


def _checked(name: str, vzor: re.Pattern, druh: str) -> str:
    text = str(name).strip().lower()
    if not vzor.match(text):
        raise ValueError(
            f"neplatne jmeno {name!r} ({druh}): povolena jsou mala pismena, "
            f"cislice, '-', '_' a tecka uvnitr"
        )
    return text


def check_name(name: str) -> str:
    """Jmeno skupiny. Over driv, nez se z nej stane cesta nebo principal."""
    return _checked(name, _NAME, "skupina")


def check_identity(name: str) -> str:
    """Jmeno cloveka nebo spravce - navic smi mit jeden zavinac."""
    return _checked(name, _IDENTITY, "identita")


def check_realm(name: str) -> str:
    """Nazev realmu - stejna pravidla jako skupina, FQDN projde."""
    return _checked(name, _NAME, "realm")
```

- [ ] **Krok 4: Přepni call sites ve `files.py`** — na `check_identity` přejdou všechna místa, kde jméno označuje člověka: `user()`, `authenticate()`, `add_user()`, `pair_missing()` (u výřezu jména z adresáře), `disable_user()`, `enable_user()`, `remove_user()`, `remove_member()` (jen parametr `name`), `add_member()` (jen parametr `name`), `pair()`, `revoke_credential()`, `_principal_exists()` (větev `user`). Skupinové parametry zůstávají na `check_name`. Import doplň.
- [ ] **Krok 5: Ověř** — `pytest` (celá sada) a `ruff check .`; očekávání: vše zelené (123).
- [ ] **Krok 6: Commit** — `git add -A && git commit` — "jmena: mala pismena vsude, e-mail jako identita".

---

### Úkol 2: Realm = subadresář; fasády s povinným realmem

**Files:**
- Create: `access_manager/realms.py`, `tests/test_realms.py`
- Modify: `access_manager/access.py`, `access_manager/admin.py`, `access_manager/files.py` (konstruktor), `tests/helpers.py`, všechny testovací soubory (mechanický sweep volání fasád)

**Interfaces:**
- Produces: `realms.REALM_PREFIX = "realm-"`; `realms.realm_root(home, realm) -> Path`; `FileStore.__init__(self, root, *, realm=None, qr_ttl_days=14, audit_retention_days=90, actor="operator")` (nové parametry zatím jen uložit jako atributy `self.realm`, `self.qr_ttl_days`, `self.audit_retention_days`, `self.actor` — konzumují je úkoly 3, 4, 7); `Access.local(home, *, realm)`, `Admin.local(home, *, realm, actor="operator")`; helpers `REALM = "example.com"`, `koren(home) -> Path`.

- [ ] **Krok 1: Failing testy** — `tests/test_realms.py`:

```python
"""Realm je striktni jmenny prostor: pres hranici nevede nic.

Stejne jmeno ve dvou realmech jsou dve ruzne identity. Zadny vychozi realm
neexistuje - fasady realm vyzaduji a uloziste dostava primo koren realmu.
"""
import pytest

from access_manager import Access, Admin


def test_the_same_name_in_two_realms_is_two_identities(tmp_path):
    Admin.local(tmp_path, realm="alfa").add_user("hana")
    assert Access.local(tmp_path, realm="alfa").user("hana") is not None
    assert Access.local(tmp_path, realm="beta").user("hana") is None


def test_realm_data_lives_under_a_realm_directory(tmp_path):
    Admin.local(tmp_path, realm="example.com").add_user("hana")
    assert (tmp_path / "realm-example.com" / "user-hana" / "totp.secret").is_file()


def test_realm_names_are_normalized_to_lowercase(tmp_path):
    Admin.local(tmp_path, realm="Example.COM").add_user("hana")
    assert Access.local(tmp_path, realm="example.com").user("hana") is not None


def test_a_realm_name_with_a_slash_is_refused(tmp_path):
    with pytest.raises(ValueError):
        Access.local(tmp_path, realm="../jinam")


def test_generations_are_independent_per_realm(tmp_path):
    Admin.local(tmp_path, realm="alfa").add_user("hana")
    assert Access.local(tmp_path, realm="alfa").generation() == 1
    assert Access.local(tmp_path, realm="beta").generation() == 0


def test_realm_is_required(tmp_path):
    with pytest.raises(TypeError):
        Access.local(tmp_path)
```

- [ ] **Krok 2: Ověř pád** — `pytest tests/test_realms.py -v`; očekávání: FAIL (`realm` neexistuje).

- [ ] **Krok 3: Implementuj `access_manager/realms.py`**:

```python
"""Realm = subadresar. Uvnitr ma presne dosavadni layout ulozisti.

Zadny vychozi realm neexistuje: kdo se pta, pta se vzdy v ramci jednoho
realmu, a pres hranici realmu nevede nic. Nazev prochazi stejnou kontrolou
jako jmena (FQDN projde) a normalizuje se na mala pismena.
"""
from __future__ import annotations

from pathlib import Path

from .principals import check_realm

#: Prefix adresare realmu. `realm-example.com/` je koren, na ktery se stavi
#: FileStore - ten o realmech nic nevi a vedet nema.
REALM_PREFIX = "realm-"


def realm_root(home, realm: str) -> Path:
    """Koren realmu pod domovskym adresarem instance."""
    return Path(home).expanduser() / f"{REALM_PREFIX}{check_realm(realm)}"
```

- [ ] **Krok 4: Fasády a konstruktor** — `access.py`:

```python
    @classmethod
    def local(cls, home, *, realm: str) -> Access:
        """V jednom procesu, primo ze souboru realmu.

        Realm je povinny - zadny vychozi neexistuje. Obchazi sit, a tim
        i vsechno, co se na siti kontroluje.
        """
        return cls(FileStore(realm_root(home, realm), realm=check_realm(realm)))
```

`admin.py` stejně, navíc s `actor`:

```python
    @classmethod
    def local(cls, home, *, realm: str, actor: str = "operator") -> Admin:
        return cls(FileStore(realm_root(home, realm), realm=check_realm(realm), actor=actor))
```

`files.py` konstruktor:

```python
    def __init__(
        self,
        root,
        *,
        realm: str | None = None,
        qr_ttl_days: int = 14,
        audit_retention_days: int = 90,
        actor: str = "operator",
    ) -> None:
        self.home = Path(root).expanduser()
        self.realm = realm
        self.qr_ttl_days = qr_ttl_days
        self.audit_retention_days = audit_retention_days
        self.actor = actor
```

- [ ] **Krok 5: Helpers a sweep testů** — `tests/helpers.py`: přidej `REALM = "example.com"` a `def koren(home): return home / f"realm-{REALM}"`; `zaloz`/`skupiny` zakládají pod `koren(home)` (mkdir parents); `principaly` volá `Access.local(home, realm=REALM)`. Pak mechanicky v celé `tests/`: `Access.local(tmp_path)` → `Access.local(tmp_path, realm=REALM)`, `Admin.local(tmp_path)` → `Admin.local(tmp_path, realm=REALM)` (+ import `REALM` z helpers) a všechny přímé cesty `tmp_path / "user-…"`, `tmp_path / "groups.json"`, `tmp_path / "audit"`, `tmp_path / "gen"` → přes `koren(tmp_path)`. Test `test_the_home_is_private_from_the_first_write` kontroluje nově `koren(home)` (0700) — domov instance samotný zakládá `realm_root` mkdirem fasády? Ne — home vzniká až zámkem uvnitř kořene realmu; test práv se týká kořene realmu. Testy z úkolu 1 dostanou `realm=REALM` také. `tests/test_realms.py` jako jediný pracuje s více realmy přímo.
- [ ] **Krok 6: Ověř** — `pytest` + `ruff check .`; očekávání: vše zelené (129).
- [ ] **Krok 7: Commit** — "realmy: subadresar, fasady s povinnym realmem".

---

### Úkol 3: Identity správců (admin-*) a jejich životní cyklus

**Files:**
- Modify: `access_manager/files.py`, `access_manager/admin.py`, `tests/test_split.py`
- Test: `tests/test_admins.py` (nový)

**Interfaces:**
- Consumes: `check_identity` (úkol 1), `self.realm` (úkol 2), `_locked`/`_bump_gen`/`_pair`/`CREDENTIAL_ARTEFACTS`.
- Produces: prefixy `USER_PREFIX = "user-"`, `ADMIN_PREFIX = "admin-"`; interní `self._dir(prefix, name) -> Path`; `FileStore.add_admin(name) -> Enrolment`, `admins() -> list[str]`, `remove_admin(name)`, `revoke_admin_credential(name)`, `pair_admin(name) -> Enrolment`; `_pair(name, directory, role)` s **novým povinným parametrem `role`** (`"member"`/`"admin"`) — štítek `f"{self.realm}-{role}-{name}"`, vydavatel `self.realm` (fallback na dosavadní tvar, když `self.realm is None`). Guard: posledního správce nejde odebrat ani mu odvolat token.

- [ ] **Krok 1: Failing testy** — `tests/test_admins.py`:

```python
"""Spravce realmu je oddelena identita: neni uzivatel, nema skupiny.

Tentyz clovek jako spravce i clen ma dve tajemstvi a dve polozky
v autentikatoru; odvolani jedne se druhe nedotkne. Posledniho spravce
nejde odebrat ani mu odvolat token - realm nesmi zustat bez spravy.
"""
import pytest

from access_manager import Access, Admin

from helpers import REALM, koren


def admin(tmp_path):
    return Admin.local(tmp_path, realm=REALM)


def test_an_admin_is_not_a_user(tmp_path):
    admin(tmp_path).add_admin("jindrich")
    access = Access.local(tmp_path, realm=REALM)
    assert access.user("jindrich") is None
    assert "jindrich" not in access.users()


def test_an_admin_and_a_user_share_a_name_but_nothing_else(tmp_path):
    a = admin(tmp_path)
    a.add_admin("jindrich")
    a.add_user("jindrich")
    tajemstvi_admin = (koren(tmp_path) / "admin-jindrich" / "totp.secret").read_text()
    tajemstvi_user = (koren(tmp_path) / "user-jindrich" / "totp.secret").read_text()
    assert tajemstvi_admin != tajemstvi_user


def test_the_pairing_label_carries_realm_and_role(tmp_path):
    a = admin(tmp_path)
    zavedeni = a.add_admin("jindrich")
    assert zavedeni.label == f"{REALM}-admin-jindrich"
    zavedeni = a.add_user("hana")
    assert zavedeni.label == f"{REALM}-member-hana"


def test_admins_are_listed_separately(tmp_path):
    a = admin(tmp_path)
    a.add_admin("jindrich")
    a.add_admin("marie")
    assert a.admins() == ["jindrich", "marie"]


def test_the_last_admin_cannot_be_removed(tmp_path):
    a = admin(tmp_path)
    a.add_admin("jindrich")
    with pytest.raises(ValueError):
        a.remove_admin("jindrich")


def test_the_last_admins_token_cannot_be_revoked(tmp_path):
    a = admin(tmp_path)
    a.add_admin("jindrich")
    with pytest.raises(ValueError):
        a.revoke_admin_credential("jindrich")


def test_a_second_admin_can_be_removed(tmp_path):
    a = admin(tmp_path)
    a.add_admin("jindrich")
    a.add_admin("marie")
    a.remove_admin("marie")
    assert a.admins() == ["jindrich"]


def test_admin_lifecycle_moves_the_generation(tmp_path):
    a = admin(tmp_path)
    access = Access.local(tmp_path, realm=REALM)
    a.add_admin("jindrich")
    pred = access.generation()
    a.add_admin("marie")
    assert access.generation() > pred
```

- [ ] **Krok 2: Ověř pád** — `pytest tests/test_admins.py -v`; FAIL (`add_admin` neexistuje).
- [ ] **Krok 3: Implementuj ve `files.py`** — konstanty `USER_PREFIX = "user-"`, `ADMIN_PREFIX = "admin-"`; interní `def _dir(self, prefix, name): return self.home / f"{prefix}{name}"`; existující kód postupně na `_dir` tam, kde se dotkneš (bez plošného refaktoru). `_pair` dostane `role: str` a štítek:

```python
    def _pair(self, name: str, directory: Path, role: str) -> Enrolment:
        pyotp = _require_totp()
        secret = pyotp.random_base32()
        if self.realm:
            # Stitek <realm>-<role>-<jmeno>: v telefonu je videt realm i role.
            # Je to napis pro lidske oci - NIKDY se neparsuje zpet.
            label = f"{self.realm}-{role}-{name}"
            issuer = self.realm
        else:
            label = f"{ISSUER}:user:{name}"
            issuer = ISSUER
        uri = pyotp.TOTP(secret).provisioning_uri(name=label, issuer_name=issuer)
        ...
```

(zbytek beze změny; call sites `_pair(...)` v `add_user`/`pair`/`pair_missing` doplní `role="member"`). Admin operace zrcadlí uživatelské s prefixem `ADMIN_PREFIX` a kontrolami pod zámkem (vzor `add_user`/`remove_user`/`revoke_credential`/`pair`), navíc guard:

```python
    def _require_not_last_admin(self, name: str) -> None:
        # Realm nesmi zustat bez spravy; zasah ma jen provozovatel na serveru.
        if self.admins() == [name]:
            raise ValueError(
                f"{name!r} je posledni spravce realmu; odebrat ho ani mu "
                f"odvolat token nejde"
            )
```

volaný v `remove_admin` a `revoke_admin_credential` UVNITŘ zámku (čtení seznamu je levné; `admins()` nezamyká). `admins()` = sorted glob `admin-*`. Každá mutace bumpuje generaci; `remove_admin` maže adresář (`shutil.rmtree`), do skupin správci nepatří, takže žádný scrub.
- [ ] **Krok 4: `admin.py` delegace** — `add_admin`, `admins`, `remove_admin`, `revoke_admin_credential`, `pair_admin` (1:1, s krátkými docstringy proč). `tests/test_split.py`: rozšiř `ZAPISOVE` o `add_admin`, `remove_admin`, `revoke_admin_credential`, `pair_admin`; přidej test, že `Admin` má `admins` a `Access` nemá nic z admin sady.
- [ ] **Krok 5: Ověř** — `pytest` + `ruff`; očekávání: vše zelené (~139).
- [ ] **Krok 6: Commit** — "spravci: oddelene identity admin-*, stitek realm-role-jmeno".

---

### Úkol 4: Platnost párovacího QR (issued/paired + TTL, výrobce `expired`)

**Files:**
- Modify: `access_manager/files.py`
- Test: `tests/test_qr_validity.py` (nový)

**Interfaces:**
- Consumes: `self.qr_ttl_days` (úkol 2), `_pair` (úkol 3), `_locked`, `CREDENTIAL_ARTEFACTS`.
- Produces: `_pair` navíc zapisuje `totp.issued` (epocha, celé sekundy); `CREDENTIAL_ARTEFACTS = ("totp.secret", "totp.uri", "totp.txt", "totp.issued", "totp.paired", "used.json")` a **`pair`/`pair_missing` úklid přes tuto konstantu** (vše kromě `totp.secret` — oprava zaparkovaného nálezu: komentář konstanty konečně platí); interní `_enrolment_expired(directory) -> bool`; `_complete_pairing(directory)` (po prvním úspěšném ověření: marker `totp.paired`, smaže `totp.uri` + `totp.txt`); `authenticate` vrací `denied`/`expired` pro nespárované zavedení po TTL. Úkoly 5 a 8 obojí konzumují.

- [ ] **Krok 1: Failing testy** — `tests/test_qr_validity.py`:

```python
"""QR je zobrazene tajemstvi, ne registracni tiket - proto ma platnost.

Dva nezavisle mechanismy: do sparovani (po prvnim uspesnem prihlaseni se
uri/txt smazou) a nejdele N dni (nesparovane zavedeni expiruje - duvod
`expired` tim prestava byt jmenem pro stav, ktery nemuze nastat).
"""
import time

import pytest

from access_manager import Access, Admin

from helpers import REALM, koren, kod


def test_enrolment_records_when_it_was_issued(tmp_path):
    Admin.local(tmp_path, realm=REALM).add_user("hana")
    assert (koren(tmp_path) / "user-hana" / "totp.issued").is_file()


def test_first_successful_login_consumes_the_qr(tmp_path):
    Admin.local(tmp_path, realm=REALM).add_user("hana")
    secret = (koren(tmp_path) / "user-hana" / "totp.secret").read_text().strip()
    assert Access.local(tmp_path, realm=REALM).authenticate(
        "hana", {"totp": kod(secret)}, purpose="login"
    )
    directory = koren(tmp_path) / "user-hana"
    assert (directory / "totp.paired").is_file()
    assert not (directory / "totp.txt").exists()
    assert not (directory / "totp.uri").exists()
    assert (directory / "totp.secret").is_file()   # tajemstvi overuje dal


def test_an_unpaired_enrolment_expires_after_ttl(tmp_path):
    Admin.local(tmp_path, realm=REALM).add_user("hana")
    directory = koren(tmp_path) / "user-hana"
    stare = int(time.time()) - 15 * 86400
    (directory / "totp.issued").write_text(f"{stare}\n", encoding="utf-8")
    secret = (directory / "totp.secret").read_text().strip()
    verdikt = Access.local(tmp_path, realm=REALM).authenticate(
        "hana", {"totp": kod(secret)}, purpose="login"
    )
    assert verdikt.reason == "expired"


def test_a_paired_identity_never_expires(tmp_path):
    Admin.local(tmp_path, realm=REALM).add_user("hana")
    directory = koren(tmp_path) / "user-hana"
    secret = (directory / "totp.secret").read_text().strip()
    access = Access.local(tmp_path, realm=REALM)
    assert access.authenticate("hana", {"totp": kod(secret)}, purpose="login")
    stare = int(time.time()) - 400 * 86400
    (directory / "totp.issued").write_text(f"{stare}\n", encoding="utf-8")
    assert access.authenticate("hana", {"totp": kod(secret)}, purpose="unlock:x")


def test_a_dir_without_issued_never_expires(tmp_path):
    # Rucne zalozeny adresar (napr. testovaci zaloz()) nema issued - nesmi
    # zacit expirovat; TTL plati jen pro zavedeni, ktera vydala knihovna.
    from helpers import zaloz
    zaloz(tmp_path, "hana")
    assert Access.local(tmp_path, realm=REALM).authenticate(
        "hana", {"totp": kod()}, purpose="login"
    )


def test_revoke_and_pair_reset_the_validity(tmp_path):
    admin = Admin.local(tmp_path, realm=REALM)
    admin.add_user("hana")
    directory = koren(tmp_path) / "user-hana"
    stare = int(time.time()) - 15 * 86400
    (directory / "totp.issued").write_text(f"{stare}\n", encoding="utf-8")
    admin.revoke_credential("hana")
    admin.pair("hana")
    hodnota = int((directory / "totp.issued").read_text().strip())
    assert hodnota > stare + 14 * 86400
```

- [ ] **Krok 2: Ověř pád** — `pytest tests/test_qr_validity.py -v`; FAIL (`totp.issued` nevzniká).
- [ ] **Krok 3: Implementuj** — v `_pair` po zápisu `totp.txt`: `_write(directory / "totp.issued", str(int(time.time())))`. Konstanta rozšířena + úklidové cesty `pair`/`pair_missing` přes ni (`for artefakt in CREDENTIAL_ARTEFACTS: if artefakt != "totp.secret": unlink(missing_ok=True)`) — oprav i komentář konstanty, ať říká pravdu. Nové pomocníky:

```python
    def _enrolment_expired(self, directory: Path) -> bool:
        """Nesparovane zavedeni po TTL. Bez `totp.issued` nikdy neexpiruje."""
        if (directory / "totp.paired").is_file():
            return False
        issued = directory / "totp.issued"
        if not issued.is_file():
            return False
        vydano = int(issued.read_text(encoding="utf-8").strip())
        return time.time() - vydano > self.qr_ttl_days * 86400

    def _complete_pairing(self, directory: Path) -> None:
        """Prvni uspesne prihlaseni: QR uz neni co ukazovat.

        Tajemstvi zustava a overuje dal; mizi jen jeho zobrazitelna podoba.
        """
        if (directory / "totp.paired").is_file():
            return
        with _locked(self.home):
            if (directory / "totp.paired").is_file():
                return
            _write(directory / "totp.paired", str(int(time.time())))
            (directory / "totp.uri").unlink(missing_ok=True)
            (directory / "totp.txt").unlink(missing_ok=True)
```

`authenticate`: za kontrolu `no_secret` vlož `if self._enrolment_expired(directory): return Verdict.refused("expired", gen=gen)`; do úspěšné větve (po `_consume`, před `Verdict.ok`) `self._complete_pairing(directory)`. Pozor na zámky: `_complete_pairing` zamyká až PO návratu z `_consume` (žádné vnoření).
- [ ] **Krok 4: Ověř** — `pytest` + `ruff`; vše zelené (~145).
- [ ] **Krok 5: Commit** — "qr plati do sparovani, nejdele N dni; expired ma vyrobce".

---

### Úkol 5: Dvoukódové ověření správce

**Files:**
- Modify: `access_manager/files.py`, `tests/test_split.py`
- Test: `tests/test_admin_login.py` (nový)

**Interfaces:**
- Consumes: admin prefix (úkol 3), `_enrolment_expired`/`_complete_pairing` (úkol 4), `_matching_step`, `_consume`.
- Produces: `_consume(self, name, purpose, *steps, prefix=USER_PREFIX) -> bool` (rozšíření: víc kroků najednou, atomicky pod jedním zámkem; kterýkoli už použitý → False a nic se nezapíše); `FileStore.authenticate_admin(name, first, second) -> Verdict` — **jen na FileStore**, fasády ho nevystavují (interní povrch konzole). Účel anti-replay: `"admin"`.

- [ ] **Krok 1: Failing testy** — `tests/test_admin_login.py`:

```python
"""Vstup do konzole: dva kody z po sobe jdoucich oken, v jednom pozadavku.

Jedno odkoukane cislo nestaci - dokazuje se souvisle drzeni autentikatoru.
Druhy kod musi sedet PRESNE na krok s+1; oba kroky se spotrebuji.
"""
import pyotp

from access_manager.files import FileStore

from helpers import REALM, koren


def store(tmp_path):
    from access_manager import Admin
    Admin.local(tmp_path, realm=REALM).add_admin("jindrich")
    return FileStore(koren(tmp_path), realm=REALM)


def dva_kody(tmp_path, offset=0):
    secret = (koren(tmp_path) / "admin-jindrich" / "totp.secret").read_text().strip()
    totp = pyotp.TOTP(secret)
    ted = __import__("time").time() + offset * totp.interval
    return totp.at(ted), totp.at(ted + totp.interval)


def test_two_adjacent_codes_pass(tmp_path):
    s = store(tmp_path)
    prvni, druhy = dva_kody(tmp_path)
    verdikt = s.authenticate_admin("jindrich", prvni, druhy)
    assert verdikt
    assert verdikt.subject_id == "admin:jindrich"
    assert verdikt.principals == frozenset()


def test_the_same_code_twice_is_not_adjacent(tmp_path):
    s = store(tmp_path)
    prvni, _ = dva_kody(tmp_path)
    assert s.authenticate_admin("jindrich", prvni, prvni).reason == "bad_code"


def test_swapped_codes_are_refused(tmp_path):
    s = store(tmp_path)
    prvni, druhy = dva_kody(tmp_path)
    assert s.authenticate_admin("jindrich", druhy, prvni).reason == "bad_code"


def test_replaying_the_pair_is_a_replay(tmp_path):
    s = store(tmp_path)
    prvni, druhy = dva_kody(tmp_path)
    assert s.authenticate_admin("jindrich", prvni, druhy)
    assert s.authenticate_admin("jindrich", prvni, druhy).reason == "replay"


def test_an_unknown_admin_is_refused_by_name(tmp_path):
    s = store(tmp_path)
    assert s.authenticate_admin("nikdo", "000000", "111111").reason == "unknown_user"


def test_a_user_cannot_log_in_as_admin(tmp_path):
    from access_manager import Admin
    Admin.local(tmp_path, realm=REALM).add_user("hana")
    s = FileStore(koren(tmp_path), realm=REALM)
    secret = (koren(tmp_path) / "user-hana" / "totp.secret").read_text().strip()
    totp = pyotp.TOTP(secret)
    ted = __import__("time").time()
    verdikt = s.authenticate_admin("hana", totp.at(ted), totp.at(ted + totp.interval))
    assert verdikt.reason == "unknown_user"


def test_admin_login_completes_the_pairing(tmp_path):
    s = store(tmp_path)
    prvni, druhy = dva_kody(tmp_path)
    assert s.authenticate_admin("jindrich", prvni, druhy)
    assert (koren(tmp_path) / "admin-jindrich" / "totp.paired").is_file()
    assert not (koren(tmp_path) / "admin-jindrich" / "totp.txt").exists()
```

- [ ] **Krok 2: Ověř pád** — FAIL (`authenticate_admin` neexistuje).
- [ ] **Krok 3: Implementuj** — `_consume` rozšiř na `*steps` (prořezávání podle `max(steps)`, kontrola všech, zápis všech, jeden zámek; parametr `prefix` určuje adresář). Pak:

```python
    def authenticate_admin(self, name: str, first, second) -> Verdict:
        """Vstup do konzole: dva kody z po sobe jdoucich oken.

        NENI to verejny endpoint ani povrch fasad - vola to konzole uvnitr
        procesu sluzby. Druhy kod musi sedet PRESNE na krok s+1: tolerance
        hodin plati pro nalezeni s, ne pro sousednost.
        """
        name = check_identity(name)
        directory = self._dir(ADMIN_PREFIX, name)
        gen = self.generation()

        if not directory.is_dir():
            return Verdict.refused("unknown_user", gen=gen)
        if (directory / "disabled").exists():
            return Verdict.refused("disabled", gen=gen)
        secret = directory / "totp.secret"
        if not secret.is_file():
            return Verdict.refused("no_secret", gen=gen)
        if self._enrolment_expired(directory):
            return Verdict.refused("expired", gen=gen)

        tajemstvi = secret.read_text(encoding="utf-8").strip()
        step = _matching_step(tajemstvi, first)
        if step is None or not _code_at_step(tajemstvi, step + 1, second):
            return Verdict.refused("bad_code", gen=gen)
        if not self._consume(name, "admin", step, step + 1, prefix=ADMIN_PREFIX):
            return Verdict.refused("replay", gen=gen)

        self._complete_pairing(directory)
        return Verdict.ok(f"admin:{name}", frozenset(), gen=gen)
```

a modulový pomocník vedle `_matching_step`:

```python
def _code_at_step(secret: str, step: int, code) -> bool:
    """Sedi kod PRESNE na dany krok? Zadna tolerance - sousednost je tvrda."""
    pyotp = _require_totp()
    totp = pyotp.TOTP(secret)
    return hmac.compare_digest(totp.at(step * totp.interval), str(code))
```

- [ ] **Krok 4: test_split** — přidej test, že `Access` ani `Admin` nemají `authenticate_admin`.
- [ ] **Krok 5: Ověř** — `pytest` + `ruff`; vše zelené (~153).
- [ ] **Krok 6: Commit** — "vstup do konzole: dva sousedni kody, oba se spotrebuji".

---

### Úkol 6: Aplikace a klíče (components.json)

**Files:**
- Modify: `access_manager/principals.py` (+`Component`), `access_manager/files.py`, `access_manager/admin.py`, `tests/test_split.py`
- Test: `tests/test_components.py` (nový)

**Interfaces:**
- Consumes: `_locked`, `_bump_gen`, `_table`-styl čtení/zápisu (nový soubor `components.json` přes `_replace`).
- Produces: `principals.Component(name, key_id, key_hash, origins: tuple, detail: bool)` (frozen dataclass; hash není tajemství); `FileStore.register_component(name, origins=(), detail=False) -> str` (vrací celý klíč `am_<key_id>_<64 hex>` — JEDINÝ okamžik, kdy klíč existuje mimo aplikaci), `components() -> list[Component]`, `revoke_component(name)`, `component_for_key(key) -> Component | None` (ověření otiskem, konstantní čas přes `hmac.compare_digest`); `Admin` deleguje registraci/výpis/odvolání (component_for_key je pro službu — jen FileStore). Jméno komponenty je neprůhledné: požaduje se neprázdný řetězec bez bílých a řídicích znaků, unikátní v realmu; NIC víc (není to cesta).

- [ ] **Krok 1: Failing testy** — `tests/test_components.py`:

```python
"""Klice aplikaci: vydat jednou, ulozit jen otisk.

Registrace aplikace v realmu = udeleni pristupu k verejnemu API toho
realmu. Klic na serveru nikdy nelezi - ztraceny klic se nevzpomina,
vyda se novy.
"""
import pytest

from access_manager import Access, Admin
from access_manager.files import FileStore

from helpers import REALM, koren


def admin(tmp_path):
    return Admin.local(tmp_path, realm=REALM)


def test_registration_returns_the_key_exactly_once(tmp_path):
    klic = admin(tmp_path).register_component("app:report")
    assert klic.startswith("am_")
    zaznamy = admin(tmp_path).components()
    assert [k.name for k in zaznamy] == ["app:report"]
    assert klic not in repr(zaznamy)          # otisk, nikdy klic


def test_the_key_verifies_against_its_fingerprint(tmp_path):
    klic = admin(tmp_path).register_component("core", origins=("10.0.0.0/8",), detail=True)
    store = FileStore(koren(tmp_path), realm=REALM)
    komponenta = store.component_for_key(klic)
    assert komponenta is not None
    assert komponenta.name == "core"
    assert komponenta.detail is True
    assert komponenta.origins == ("10.0.0.0/8",)


def test_a_wrong_key_verifies_as_nothing(tmp_path):
    admin(tmp_path).register_component("core")
    store = FileStore(koren(tmp_path), realm=REALM)
    assert store.component_for_key("am_k1_" + "0" * 64) is None


def test_a_revoked_key_stops_working(tmp_path):
    a = admin(tmp_path)
    klic = a.register_component("core")
    a.revoke_component("core")
    assert FileStore(koren(tmp_path), realm=REALM).component_for_key(klic) is None


def test_a_duplicate_component_name_is_refused(tmp_path):
    a = admin(tmp_path)
    a.register_component("core")
    with pytest.raises(ValueError):
        a.register_component("core")


def test_key_ids_grow_and_survive_revocation(tmp_path):
    a = admin(tmp_path)
    k1 = a.register_component("prvni")
    a.revoke_component("prvni")
    k2 = a.register_component("druha")
    id1 = k1.split("_")[1]
    id2 = k2.split("_")[1]
    assert id1 != id2                          # key_id se nikdy nerecykluje


def test_registration_moves_the_generation(tmp_path):
    a = admin(tmp_path)
    access = Access.local(tmp_path, realm=REALM)
    pred = access.generation()
    a.register_component("core")
    assert access.generation() > pred
```

- [ ] **Krok 2: Ověř pád** — FAIL (`register_component` neexistuje).
- [ ] **Krok 3: Implementuj** — `Component` do `principals.py` (frozen, slots, docstring: hash není tajemství, ale klíč sem nikdy nepatří). Ve `files.py` konstanta `COMPONENTS = "components.json"`; formát souboru:

```json
{ "next_key_id": 3,
  "components": { "core": { "key_id": "k1", "key_hash": "…64hex…",
                             "origins": ["10.0.0.0/8"], "detail": true } } }
```

Implementace (jádro):

```python
    def register_component(self, name, origins=(), detail=False) -> str:
        """Registrace aplikace = udeleni pristupu k verejnemu API realmu.

        Klic se VRACI JEDNOU a nikde se neuklada - jen jeho sha256 otisk.
        """
        name = _check_component_name(name)
        with _locked(self.home):
            data = self._components_table()
            if name in data["components"]:
                raise ValueError(f"komponenta {name!r} uz existuje; klic se nevzpomina, odvolej a registruj znovu")
            key_id = f"k{data['next_key_id']}"
            data["next_key_id"] += 1
            klic = f"am_{key_id}_{secrets.token_hex(32)}"
            data["components"][name] = {
                "key_id": key_id,
                "key_hash": hashlib.sha256(klic.encode()).hexdigest(),
                "origins": sorted(origins),
                "detail": bool(detail),
            }
            _replace(self.home / COMPONENTS, json.dumps(data, indent=2, sort_keys=True))
            self._bump_gen()
        return klic
```

`_check_component_name`: `text = str(name).strip()`; prázdné / bílé znaky uvnitř / řídicí znaky → ValueError; jinak vrať text (neprůhledné jméno, žádná další pravidla). `component_for_key`: spočti otisk, projdi záznamy, `hmac.compare_digest` na hex otiscích; vrať `Component` nebo None. `components()`: setříděné podle jména. `revoke_component`: chybějící → ValueError; smaž záznam, bump. Importy `secrets`, `hashlib` nahoru.
- [ ] **Krok 4: Delegace + split** — `Admin.register_component/components/revoke_component`; `ZAPISOVE` + `register_component`, `revoke_component`; test že `Access` nemá `component_for_key` ani registraci.
- [ ] **Krok 5: Ověř** — `pytest` + `ruff`; vše zelené (~161).
- [ ] **Krok 6: Commit** — "aplikace: klic jednou, na serveru jen otisk".

---

### Úkol 7: Auditní log per realm

**Files:**
- Create: `access_manager/audit.py`
- Modify: `access_manager/files.py` (napojení), `access_manager/access.py` (`authenticate(..., component=None)` průchod)
- Test: `tests/test_audit.py` (nový)

**Interfaces:**
- Consumes: `self.actor`, `self.audit_retention_days` (úkol 2).
- Produces: `audit.append_event(root, event: dict, retention_days: int)` (JSONL řádek do `audit/RRRR-MM-DD.jsonl`, O_APPEND jediný write; při přechodu dne smaže soubory starší retence), `audit.read_events(root, day_from=None, day_to=None, *, subject=None, outcome=None, kind=None) -> list[dict]` (dny jako "RRRR-MM-DD"); `FileStore._audit(**pole)` (doplní `t` ISO UTC); `authenticate(username, credentials, *, purpose, component=None)` — komponenta jen do auditu; každá mutace loguje `kind="write"` s `actor` a `op`. Nikdy kódy ani tajemství.

- [ ] **Krok 1: Failing testy** — `tests/test_audit.py`:

```python
"""Kazdy realm loguje do sveho prostoru; podrobne duvody patri SEM.

Jeden radek = jedna udalost; denni soubory delaji z retence proste mazani.
Tajemstvi ani kody se neloguji nikdy - jen jmena, vysledky, cisla kroku.
"""
import json

from access_manager import Access, Admin
from access_manager.audit import read_events

from helpers import REALM, koren, kod, zaloz


def test_authentication_lands_in_the_audit_with_its_reason(tmp_path):
    zaloz(tmp_path, "hana")
    Access.local(tmp_path, realm=REALM).authenticate(
        "hana", {"totp": "000000"}, purpose="login", component="app:test"
    )
    udalosti = read_events(koren(tmp_path))
    assert len(udalosti) == 1
    u = udalosti[0]
    assert u["kind"] == "authenticate"
    assert u["subject"] == "user:hana"
    assert u["component"] == "app:test"
    assert u["outcome"] == "denied"
    assert u["reason"] == "bad_code"


def test_the_code_itself_is_never_logged(tmp_path):
    zaloz(tmp_path, "hana")
    spravny = kod()
    Access.local(tmp_path, realm=REALM).authenticate(
        "hana", {"totp": spravny}, purpose="login"
    )
    for soubor in (koren(tmp_path) / "audit").glob("*.jsonl"):
        assert spravny not in soubor.read_text(encoding="utf-8")


def test_writes_carry_their_actor(tmp_path):
    Admin.local(tmp_path, realm=REALM, actor="admin:jindrich").add_user("hana")
    zapisy = read_events(koren(tmp_path), kind="write")
    assert zapisy
    assert zapisy[-1]["actor"] == "admin:jindrich"
    assert zapisy[-1]["op"] == "add_user"


def test_the_default_actor_is_the_operator(tmp_path):
    Admin.local(tmp_path, realm=REALM).add_group("ucetni")
    zapisy = read_events(koren(tmp_path), kind="write")
    assert zapisy[-1]["actor"] == "operator"


def test_events_can_be_filtered_by_subject(tmp_path):
    zaloz(tmp_path, "hana")
    zaloz(tmp_path, "petr")
    access = Access.local(tmp_path, realm=REALM)
    access.authenticate("hana", {"totp": "000000"}, purpose="login")
    access.authenticate("petr", {"totp": "000000"}, purpose="login")
    jen_hana = read_events(koren(tmp_path), subject="user:hana")
    assert {u["subject"] for u in jen_hana} == {"user:hana"}


def test_old_daily_files_are_pruned(tmp_path):
    zaloz(tmp_path, "hana")
    adresar = koren(tmp_path) / "audit"
    adresar.mkdir(parents=True, exist_ok=True)
    (adresar / "2020-01-01.jsonl").write_text("{}\n", encoding="utf-8")
    Access.local(tmp_path, realm=REALM).authenticate(
        "hana", {"totp": "000000"}, purpose="login"
    )
    assert not (adresar / "2020-01-01.jsonl").exists()


def test_every_line_is_valid_json(tmp_path):
    zaloz(tmp_path, "hana")
    Admin.local(tmp_path, realm=REALM).add_group("ucetni")
    Access.local(tmp_path, realm=REALM).authenticate(
        "hana", {"totp": "000000"}, purpose="login"
    )
    for soubor in (koren(tmp_path) / "audit").glob("*.jsonl"):
        for radek in soubor.read_text(encoding="utf-8").splitlines():
            json.loads(radek)
```

- [ ] **Krok 2: Ověř pád** — FAIL (`access_manager.audit` neexistuje).
- [ ] **Krok 3: Implementuj `audit.py`**:

```python
"""Auditni stopa realmu: JSONL, jeden radek = jedna udalost.

Denni soubory (audit/RRRR-MM-DD.jsonl) delaji z retence proste mazani
souboru a ze cteni rozsahu levnou operaci. Podrobne duvody odmitnuti
patri SEM - na drat jde jen ctverice tvaru. Tajemstvi ani kody se
neloguji nikdy; append je jediny os.write s O_APPEND, takze radky se
neproplitaji ani bez zamku.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

ADRESAR = "audit"
MODE = 0o600


def append_event(root, event: dict, retention_days: int) -> None:
    adresar = Path(root) / ADRESAR
    adresar.mkdir(mode=0o700, exist_ok=True)
    dnes = datetime.now(timezone.utc)
    cil = adresar / f"{dnes:%Y-%m-%d}.jsonl"
    if not cil.exists():
        _prune(adresar, retention_days)
    radek = json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n"
    handle = os.open(cil, os.O_WRONLY | os.O_CREAT | os.O_APPEND, MODE)
    try:
        os.write(handle, radek.encode("utf-8"))
    finally:
        os.close(handle)


def _prune(adresar: Path, retention_days: int) -> None:
    """Smaz denni soubory starsi nez retence. Bezi jen pri zalozeni dne."""
    hranice = time.time() - retention_days * 86400
    for soubor in adresar.glob("*.jsonl"):
        try:
            stari = datetime.strptime(soubor.stem, "%Y-%m-%d")
        except ValueError:
            continue                     # cizi soubor neni nas ukol
        if stari.replace(tzinfo=timezone.utc).timestamp() < hranice:
            soubor.unlink(missing_ok=True)


def read_events(root, day_from=None, day_to=None, *, subject=None,
                outcome=None, kind=None) -> list[dict]:
    """Precti udalosti s filtrem. Dny jako 'RRRR-MM-DD', vcetne."""
    adresar = Path(root) / ADRESAR
    if not adresar.is_dir():
        return []
    vysledek = []
    for soubor in sorted(adresar.glob("*.jsonl")):
        den = soubor.stem
        if day_from and den < day_from:
            continue
        if day_to and den > day_to:
            continue
        for radek in soubor.read_text(encoding="utf-8").splitlines():
            udalost = json.loads(radek)
            if subject and udalost.get("subject") != subject:
                continue
            if outcome and udalost.get("outcome") != outcome:
                continue
            if kind and udalost.get("kind") != kind:
                continue
            vysledek.append(udalost)
    return vysledek
```

- [ ] **Krok 4: Napojení ve `files.py`** — pomocník:

```python
    def _audit(self, **pole) -> None:
        udalost = {"t": datetime.now(timezone.utc).isoformat(timespec="seconds"), **pole}
        append_event(self.home, udalost, self.audit_retention_days)
```

`authenticate` dostane `component: str | None = None` (jen audit; `Access.authenticate` parametr propustí) a před KAŽDÝM return zaloguje jednou (nejčistěji: vnitřní `_verdikt(...)` lokální funkce, nebo jediný výstupní bod — implementuj jako `verdikt = ...` + `self._audit(kind="authenticate", subject=f"user:{name}", purpose=purpose, component=component, outcome=verdikt.outcome, **({"reason": verdikt.reason} if verdikt.reason else {}), gen=verdikt.gen)` na konci; výjimky ValueError z check_* se nelogují — nejsou to události uživatele). `authenticate_admin` loguje stejně se `subject=f"admin:{name}"`. Každá mutace (add_user, pair, pair_missing per doplněný, add_group, add_member, include, disable_user, enable_user, remove_member, remove_user, revoke_credential, add_admin, remove_admin, revoke_admin_credential, pair_admin, register_component — bez klíče!, revoke_component) na konci úspěšné cesty `self._audit(kind="write", actor=self.actor, op="add_user", name=name)` (pole podle operace: skupina, člen…; NIKDY klíč, tajemství, kód). Auditní zápis smí běžet uvnitř zámku (append nezamyká).
- [ ] **Krok 5: Ověř** — `pytest` + `ruff`; vše zelené (~168).
- [ ] **Krok 6: Commit** — "audit: jsonl per realm, retence, podrobne duvody patri sem".

---

### Úkol 8: Reconcile z deklarací

**Files:**
- Modify: `access_manager/realms.py`, `access_manager/__init__.py`
- Test: `tests/test_reconcile.py` (nový)

**Interfaces:**
- Consumes: `realm_root`, `FileStore` (admin ops, `_enrolment_expired` přes veřejné chování), `Enrolment`.
- Produces: `reconcile(home, declarations) -> list[Enrolment]` — `declarations` je seznam dictů `{"name": str, "admins": [str, ...]}` (volitelně `"qr_ttl_days"`, `"audit_retention_days"`); doplní JEN co chybí: chybějící realm založí, deklarovanému správci bez adresáře udělá `add_admin`, správci bez tajemství `pair_admin`, správci s **expirovaným nespárovaným** zavedením `revoke_admin_credential` + `pair_admin` (výměna tajemství, které nikdo nepoužil, nikoho nezamyká — a guard posledního správce se na tuto cestu nesmí vztahovat: revoke tu obchází fasádu, viz krok 3). Nikdy se nedotkne spárovaných ani existujících dat; duplicitní název realmu v deklaraci → ValueError. Vrací nová zavedení (QR k předání). Export `reconcile` z balíčku.

- [ ] **Krok 1: Failing testy** — `tests/test_reconcile.py`:

```python
"""Reconcile: deklarace rika CO ma byt, sluzba doplni JEN co chybi.

Restart ve 3 rano nikomu nic nevymeni. Zmizeni z deklarace neni mazani -
sjednocenim nejde nic odebrat.
"""
import time

import pytest

from access_manager import Access, reconcile

from helpers import REALM


DEKLARACE = [{"name": REALM, "admins": ["jindrich"]}]


def test_reconcile_creates_the_realm_and_its_first_admin(tmp_path):
    nova = reconcile(tmp_path, DEKLARACE)
    assert [z.name for z in nova] == ["jindrich"]
    assert (tmp_path / f"realm-{REALM}" / "admin-jindrich" / "totp.txt").is_file()


def test_reconcile_is_idempotent(tmp_path):
    reconcile(tmp_path, DEKLARACE)
    tajemstvi = (tmp_path / f"realm-{REALM}" / "admin-jindrich" / "totp.secret").read_text()
    assert reconcile(tmp_path, DEKLARACE) == []
    assert (tmp_path / f"realm-{REALM}" / "admin-jindrich" / "totp.secret").read_text() == tajemstvi


def test_reconcile_adds_a_newly_declared_admin(tmp_path):
    reconcile(tmp_path, DEKLARACE)
    nova = reconcile(tmp_path, [{"name": REALM, "admins": ["jindrich", "marie"]}])
    assert [z.name for z in nova] == ["marie"]


def test_an_expired_unpaired_admin_gets_a_fresh_qr(tmp_path):
    reconcile(tmp_path, DEKLARACE)
    adresar = tmp_path / f"realm-{REALM}" / "admin-jindrich"
    stare_tajemstvi = (adresar / "totp.secret").read_text()
    (adresar / "totp.issued").write_text(
        f"{int(time.time()) - 15 * 86400}\n", encoding="utf-8"
    )
    nova = reconcile(tmp_path, DEKLARACE)
    assert [z.name for z in nova] == ["jindrich"]
    assert (adresar / "totp.secret").read_text() != stare_tajemstvi


def test_a_missing_realm_in_the_declaration_is_not_deleted(tmp_path):
    reconcile(tmp_path, DEKLARACE)
    reconcile(tmp_path, [{"name": "jiny", "admins": ["petr"]}])
    assert (tmp_path / f"realm-{REALM}").is_dir()


def test_duplicate_realm_names_close_the_start(tmp_path):
    with pytest.raises(ValueError):
        reconcile(tmp_path, [{"name": "a", "admins": []}, {"name": "A", "admins": []}])


def test_reconcile_audits_as_the_operator(tmp_path):
    from access_manager.audit import read_events
    reconcile(tmp_path, DEKLARACE)
    zapisy = read_events(tmp_path / f"realm-{REALM}", kind="write")
    assert zapisy
    assert all(z["actor"] == "operator" for z in zapisy)
```

- [ ] **Krok 2: Ověř pád** — FAIL (`reconcile` není v balíčku).
- [ ] **Krok 3: Implementuj v `realms.py`**:

```python
def reconcile(home, declarations) -> list[Enrolment]:
    """Dorovnej stav podle deklaraci. Doplnuje se JEN co chybi.

    Existujiciho se nedotyka: restart ve 3 rano nikomu nic nevymeni.
    Expirovane nesparovane zavedeni spravce dostane novy QR - vymena
    tajemstvi, ktere nikdo nikdy nepouzil, nikoho nezamyka. Zmizeni
    realmu z deklarace NENI mazani; sjednocenim nejde nic odebrat.
    """
    videne: set[str] = set()
    nova: list[Enrolment] = []
    for deklarace in declarations:
        nazev = check_realm(deklarace["name"])
        if nazev in videne:
            raise ValueError(f"realm {nazev!r} je deklarovany dvakrat; konflikt zavira start")
        videne.add(nazev)
        store = FileStore(
            realm_root(home, nazev),
            realm=nazev,
            qr_ttl_days=int(deklarace.get("qr_ttl_days", 14)),
            audit_retention_days=int(deklarace.get("audit_retention_days", 90)),
        )
        for jmeno in deklarace.get("admins", ()):
            jmeno = check_identity(jmeno)
            adresar = store.home / f"admin-{jmeno}"
            if not adresar.is_dir():
                nova.append(store.add_admin(jmeno))
            elif not (adresar / "totp.secret").is_file():
                nova.append(store.pair_admin(jmeno))
            elif store._enrolment_expired(adresar):
                # Guard posledniho spravce tu neplati: tajemstvi nikdo
                # nikdy nepouzil a bez vymeny by se realm zasekl.
                store._replace_expired_admin_enrolment(jmeno)
                nova.append(store.pair_admin(jmeno))
    return nova
```

K tomu ve `files.py` malý interní pomocník `_replace_expired_admin_enrolment(name)` = odvolání admin pověření **bez** guardu posledního správce (stejný úklid artefaktů pod zámkem + bump + audit `op="reconcile_reissue"`); veřejné `revoke_admin_credential` guard drží dál. Import `FileStore`, `check_identity`, `Enrolment` do `realms.py`; export `reconcile` v `__init__.py` (`__all__` + docstring o třetích dvířkách provozovatele).
- [ ] **Krok 4: Ověř** — `pytest` + `ruff`; vše zelené (~175).
- [ ] **Krok 5: Commit** — "reconcile: deklarace doplni jen co chybi".

---

### Úkol 9: Exporty, README a úklid

**Files:**
- Modify: `access_manager/__init__.py`, `README.md`

- [ ] **Krok 1: `__init__.py`** — exporty: `Access`, `Admin`, `Enrolment`, `Group`, `User`, `Verdict`, `reconcile` (+ `Component` ano — aplikační vývojář ho dostane z `components()`); doplň docstring o třetích dvířkách (`reconcile` je provozovatelský vstup, žádné API).
- [ ] **Krok 2: README** — sekci Použití přepiš na realm podobu (`Access.local("~/.access-manager", realm="example.com")`), přidej krátkou sekci Realmy (subadresář, reconcile z deklarací, správci s dvoukódovým vstupem — 6–10 řádek, bez diakritiky, střízlivě ve stylu README) a v sekci Stav aktualizuj počet testů podle `pytest -q` a větu o hotovém rozsahu („… plus realmy: spravci, platnost QR, klice aplikaci, audit a reconcile; sluzba a Access.remote stale ne").
- [ ] **Krok 3: Ověř** — `pytest` + `ruff check .`; vše zelené.
- [ ] **Krok 4: Commit** — "exporty a readme: realmy v knihovne".

---

## Self-review (proběhla při psaní plánu)

- **Pokrytí specu:** §2 jména+lowercase+@ → úkol 1; §2 stromy/realm subadresář → úkol 2; §4 správci, štítek, guard, dvoukód → úkoly 3+5; §5 platnost QR + expired → úkol 4 (reconcile re-issue v 8); §6 komponenty/otisky → úkol 6; §9 audit → úkol 7; §3 reconcile/deklarace → úkol 8; §10 povrch knihovny → průběžně + úkol 9. Vědomě mimo (subprojekt 3+4): drátové API, origin vynucování, konzole, `conf.d` loader (reconcile bere už rozparsovaný seznam), relace správce.
- **Typová konzistence:** `_pair(name, directory, role)` z úkolu 3 konzumují úkoly 4 a 8 beze změny; `_consume(name, purpose, *steps, prefix=...)` z úkolu 5 zpětně kompatibilní s voláním z `authenticate` (jeden krok, výchozí prefix); `FileStore.__init__` parametry z úkolu 2 konzumují 4 (qr_ttl_days), 7 (actor, retention), 8 (oba); `koren(home)`/`REALM` z úkolu 2 používají všechny nové testy.
- **Placeholders:** žádné TBD; počty testů „~N“ jsou očekávání ověřovaná při exekuci; README počet se bere z běhu.
- **Známá rizika pro exekuci:** sweep v úkolu 2 je největší mechanická plocha (všechny testy) — dispatch má výslovně projít soubor po souboru; TOTP časové testy pracují s pevně zapsanými epochami (žádný sleep) kromě dvoukódu, který si kroky počítá explicitně přes `totp.at`.
