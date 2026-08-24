"""Souborove uloziste.

NENI to atrapa pro testy: je to skutecne uloziste, ktere si vevnitr drzi sama
sluzba. Tytez testy tak bezi proti obema zapojenim.

Ven se `FileStore` nevystavuje. Kdyby si ho aplikace mohla vzit primo,
obejde tim origin ACL, omezovani pokusu i auditni stopu - a udela to, protoze
je to jednodussi. Aplikace dostane `Access`, spravcovsky nastroj `Admin`.

Format navazuje na to, co uz zaklada `python -m viewbase.admin adduser`:

    HOME/
      user-jindrich/totp.secret     tajemstvi (0600)
      user-jindrich/totp.uri        URI pro autentikator
      user-jindrich/totp.txt        QR jako text - `cat` na hlave bez obrazovky
      user-jindrich/used.json       spotrebovane kroky, per ucel
      user-jindrich/disabled        kdyz je clovek docasne vypnuty
      groups.json                   {"ucetni": {"members": [...], "includes": [...]}}
"""
from __future__ import annotations

import fcntl
import hmac
import json
import os
import shutil
import time
from contextlib import contextmanager
from pathlib import Path

from .principals import (
    ISSUER,
    PUBLIC,
    RESERVED_GROUPS,
    USERS,
    Enrolment,
    Group,
    User,
    check_identity,
    check_name,
)
from .purpose import check_purpose
from .verdicts import Verdict

#: Kde skupiny bydli. Jeden soubor, protoze zatim staci jeden.
GROUPS = "groups.json"

#: Kolik kroku dozadu a dopredu se kod jeste uzna. Hodiny telefonu se rozchazi.
WINDOW = 1

#: Prava. Tajemstvi je citelne jen vlastnikem a adresar se ani neda projit.
FILE_MODE = 0o600
DIR_MODE = 0o700

#: Zamek vedle dat. Jeden na cely adresar: sporu je malo a spravnost je
#: videt na prvni pohled. fcntl je POSIXovy - Windows tu nikdy nebyl cil.
LOCK = ".lock"

#: Cislo generace. Zvedne ho kazdy administrativni zapis; cteni ho jen cte.
GEN = "gen"

#: Soubory jednoho povereni: pouziva revoke_credential i revoke_admin_credential,
#: i uklid pred novym parovanim, kdyz po preruseni zbyde osireny QR bez tajemstvi.
CREDENTIAL_ARTEFACTS = (
    "totp.secret",
    "totp.uri",
    "totp.txt",
    "totp.issued",
    "totp.paired",
    "used.json",
)

#: Prefixy adresaru podle role.
USER_PREFIX = "user-"
ADMIN_PREFIX = "admin-"


class FileStore:
    """Identita a politika ze souboru pod jednim adresarem."""

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

    def _dir(self, prefix: str, name: str) -> Path:
        """Cesta k adresari identifikujici se podle prefixu a jmena."""
        return self.home / f"{prefix}{name}"

    # == cteni =============================================================

    def user(self, name: str) -> User | None:
        name = check_identity(name)
        directory = self._dir(USER_PREFIX, name)
        if not directory.is_dir():
            return None
        groups = {f"group:{g}" for g in self._groups_of(name)}
        return User(
            name=name,
            subject_id=f"user:{name}",
            enabled=not (directory / "disabled").exists(),
            principals=frozenset({f"user:{name}", USERS, PUBLIC, *groups}),
        )

    def users(self) -> list[str]:
        return sorted(
            d.name[len(USER_PREFIX):]
            for d in self.home.glob(f"{USER_PREFIX}*")
            if d.is_dir()
        )

    def groups(self) -> list[str]:
        return sorted(self._table())

    def group(self, name: str) -> Group | None:
        name = check_name(name)
        data = self._table().get(name)
        if data is None:
            return None
        return Group(
            name=name,
            members=tuple(sorted(data.get("members", ()))),
            includes=tuple(sorted(data.get("includes", ()))),
        )

    def generation(self) -> int:
        """Cislo generace: zvedne ho kazdy administrativni zapis. Cache plati,
        dokud se nehne."""
        path = self.home / GEN
        return int(path.read_text(encoding="utf-8")) if path.is_file() else 0

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
            if kind == "user":
                name = check_identity(name)
            else:
                name = check_name(name)
        except ValueError:
            return False
        if kind == "group":
            return name in self._table()
        if kind == "user":
            return self._dir(USER_PREFIX, name).is_dir()
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

    # == platnost ==========================================================

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

    # == overeni ===========================================================

    def authenticate(self, username: str, credentials, *, purpose: str) -> Verdict:
        """Odpoved na "jsi to ty?" - nikdy na "smis to?"."""
        purpose = check_purpose(purpose)
        name = check_identity(username)
        directory = self._dir(USER_PREFIX, name)
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

        if self._enrolment_expired(directory):
            return Verdict.refused("expired", gen=gen)

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
        if user is None:
            # Soubeh: mezi _consume a timhle dotazem stihl remove_user smazat
            # adresar. Spravny kod bez existujiciho uzivatele neni verdikt.
            return Verdict.refused("unknown_user", gen=gen)

        self._complete_pairing(directory)
        return Verdict.ok(user.subject_id, user.principals, gen=gen)

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

    # == zapis: lide =======================================================

    def _bump_gen(self) -> None:
        # Volat JEN pod _locked - jinak se dva zapisy sejdou na temz cisle.
        _replace(self.home / GEN, str(self.generation() + 1))

    def add_user(self, name: str) -> Enrolment:
        name = check_identity(name)
        _require_pairing()
        with _locked(self.home):
            directory = self._dir(USER_PREFIX, name)
            if directory.exists():
                raise ValueError(
                    f"uzivatel {name!r} uz existuje ({directory}); prepsat jeho "
                    f"tajemstvi by ho zamklo ven"
                )
            directory.mkdir(mode=DIR_MODE)
            os.chmod(directory, DIR_MODE)  # mkdir podleha umask, chmod ne
            enrolment = self._pair(name, directory, role="member")
            self._bump_gen()
        return enrolment

    def pair_missing(self) -> list[Enrolment]:
        """Doplň parovaci kod tem, kdo zadny nemaji. Ostatnich se nedotykej.

        Sluzba restartovana ve 3 rano nesmi vymenit tajemstvi lidem, kteri uz
        je maji - autentikator by dal vydaval kody, ktere uz nikam nepatri.
        """
        _require_pairing()
        with _locked(self.home):
            doplneno = []
            for directory in sorted(self.home.glob(f"{USER_PREFIX}*")):
                if not directory.is_dir() or (directory / "totp.secret").is_file():
                    continue
                # Osireny QR z preruseneho revoke (nebo cizi zasah) by jinak
                # srazil _pair na O_EXCL - viz pair().
                for artefakt in CREDENTIAL_ARTEFACTS:
                    if artefakt != "totp.secret":
                        (directory / artefakt).unlink(missing_ok=True)
                name = check_identity(directory.name[len(USER_PREFIX):])
                doplneno.append(
                    self._pair(name, directory, role="member")
                )
            if doplneno:
                self._bump_gen()
        return doplneno

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
        _write(directory / "totp.secret", secret)
        _write(directory / "totp.uri", uri)
        _write(directory / "totp.txt", _qr_text(uri))
        _write(directory / "totp.issued", str(int(time.time())))
        return Enrolment(name=name, directory=directory, label=label)

    # == zapis: skupiny ====================================================

    def add_group(self, name: str) -> None:
        name = check_name(name)
        if name in RESERVED_GROUPS:
            raise ValueError(
                f"skupina {name!r} je vyhrazena: clenstvi v ni je automaticke "
                f"a nejde spravovat"
            )
        with _locked(self.home):
            table = self._table()
            if name in table:
                raise ValueError(f"skupina {name!r} uz existuje")
            table[name] = {"members": [], "includes": []}
            self._write_table(table)
            self._bump_gen()

    def add_member(self, group: str, name: str) -> None:
        group, name = check_name(group), check_identity(name)
        with _locked(self.home):
            table = self._table()
            if group not in table:
                # Preklep by jinak zalozil skupinu, kterou nikdo nikdy nenapsal
                # do zadneho ACL - clenstvi bez ucinku, ktere vypada hotove.
                raise ValueError(f"skupina {group!r} neexistuje")
            if not self._dir(USER_PREFIX, name).is_dir():
                raise ValueError(f"uzivatel {name!r} neexistuje")
            members = set(table[group].get("members", ()))
            members.add(name)
            table[group]["members"] = sorted(members)
            self._write_table(table)
            self._bump_gen()

    def include(self, parent: str, child: str) -> None:
        """`parent` OBSAHUJE `child`: kdo je v child, je i v parent."""
        parent, child = check_name(parent), check_name(child)
        with _locked(self.home):
            table = self._table()
            for group in (parent, child):
                if group not in table:
                    raise ValueError(f"skupina {group!r} neexistuje")
            if parent == child:
                raise ValueError(f"skupina {parent!r} nemuze obsahovat sama sebe")
            if parent in _descendants(table, child):
                # Cyklus cteni prezije, ale VYROBIT ho je vzdycky omyl - a v tuhle
                # chvili jeste vime, kdo ho dela a proc.
                raise ValueError(
                    f"{parent!r} uz je obsazena v {child!r}; opacne zretezeni by "
                    f"udelalo cyklus"
                )
            includes = set(table[parent].get("includes", ()))
            includes.add(child)
            table[parent]["includes"] = sorted(includes)
            self._write_table(table)
            self._bump_gen()

    # == zapis: zivotni cyklus =============================================

    def disable_user(self, name: str) -> None:
        """Docasne vypnuti. Clenstvi i auditni stopa zustavaji."""
        name = check_identity(name)
        with _locked(self.home):
            directory = self._dir(USER_PREFIX, name)
            if not directory.is_dir():
                raise ValueError(f"uzivatel {name!r} neexistuje")
            if (directory / "disabled").exists():
                return
            _write(directory / "disabled", "")
            self._bump_gen()

    def enable_user(self, name: str) -> None:
        name = check_identity(name)
        with _locked(self.home):
            directory = self._dir(USER_PREFIX, name)
            if not directory.is_dir():
                raise ValueError(f"uzivatel {name!r} neexistuje")
            if not (directory / "disabled").exists():
                return
            (directory / "disabled").unlink(missing_ok=True)
            self._bump_gen()

    def remove_member(self, group: str, name: str) -> None:
        group, name = check_name(group), check_identity(name)
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
        name = check_identity(name)
        with _locked(self.home):
            directory = self._dir(USER_PREFIX, name)
            if not directory.is_dir():
                raise ValueError(f"uzivatel {name!r} neexistuje")
            table = self._table()
            for data in table.values():
                if name in data.get("members", ()):
                    data["members"] = sorted(set(data["members"]) - {name})
            self._write_table(table)
            shutil.rmtree(directory)
            self._bump_gen()

    def revoke_credential(self, name: str, mechanism: str = "totp") -> None:
        """Odvolani povereni - reseni ztraceneho telefonu.

        Maze i `used.json`: cisla spotrebovanych kroku patri ke staremu
        tajemstvi a s novym by tyz krok byl falesny replay.
        """
        if mechanism != "totp":
            raise ValueError(
                f"neznamy mechanismus {mechanism!r}; zatim existuje jen 'totp'"
            )
        name = check_identity(name)
        with _locked(self.home):
            directory = self._dir(USER_PREFIX, name)
            if not directory.is_dir():
                raise ValueError(f"uzivatel {name!r} neexistuje")
            if not any((directory / a).exists() for a in CREDENTIAL_ARTEFACTS):
                # Idempotentni: zadne tajemstvi neni zadny problem
                return
            for artefakt in CREDENTIAL_ARTEFACTS:
                (directory / artefakt).unlink(missing_ok=True)
            self._bump_gen()

    def pair(self, name: str) -> Enrolment:
        """Nove parovani JEDNOHO cloveka. Existujici tajemstvi neprepise."""
        name = check_identity(name)
        _require_pairing()
        with _locked(self.home):
            directory = self._dir(USER_PREFIX, name)
            if not directory.is_dir():
                raise ValueError(f"uzivatel {name!r} neexistuje")
            if (directory / "totp.secret").is_file():
                raise ValueError(
                    f"uzivatel {name!r} uz tajemstvi ma; nejdriv revoke_credential - "
                    f"prepsani by ho zamklo ven"
                )
            # Osireny stav z preruseneho revoke (nebo cizi zasah): tajemstvi
            # chybi, ale used.json/uri/txt patrici STAREMU tajemstvi tu jeste
            # mohou lezet. Bez uklidu by _pair spadl na O_EXCL a nechal by
            # pulku stareho QR vedle pulky noveho.
            for artefakt in CREDENTIAL_ARTEFACTS:
                if artefakt != "totp.secret":
                    (directory / artefakt).unlink(missing_ok=True)
            enrolment = self._pair(name, directory, role="member")
            self._bump_gen()
        return enrolment

    # == zapis: spravci ====================================================

    def add_admin(self, name: str) -> Enrolment:
        name = check_identity(name)
        _require_pairing()
        with _locked(self.home):
            directory = self._dir(ADMIN_PREFIX, name)
            if directory.exists():
                raise ValueError(
                    f"spravce {name!r} uz existuje ({directory}); prepsat jeho "
                    f"tajemstvi by ho zamklo ven"
                )
            directory.mkdir(mode=DIR_MODE)
            os.chmod(directory, DIR_MODE)  # mkdir podleha umask, chmod ne
            enrolment = self._pair(name, directory, role="admin")
            self._bump_gen()
        return enrolment

    def admins(self) -> list[str]:
        return sorted(
            d.name[len(ADMIN_PREFIX):]
            for d in self.home.glob(f"{ADMIN_PREFIX}*")
            if d.is_dir()
        )

    def _require_not_last_admin(self, name: str) -> None:
        # Realm nesmi zustat bez spravy; zasah ma jen provozovatel na serveru.
        if self.admins() == [name]:
            raise ValueError(
                f"{name!r} je posledni spravce realmu; odebrat ho ani mu "
                f"odvolat token nejde"
            )

    def remove_admin(self, name: str) -> None:
        """Smaz spravce. Spravci nejsou v skupinach, takze zadny scrub."""
        name = check_identity(name)
        with _locked(self.home):
            self._require_not_last_admin(name)
            directory = self._dir(ADMIN_PREFIX, name)
            if not directory.is_dir():
                raise ValueError(f"spravce {name!r} neexistuje")
            shutil.rmtree(directory)
            self._bump_gen()

    def revoke_admin_credential(self, name: str, mechanism: str = "totp") -> None:
        """Odvolani povereni spravce - reseni ztraceneho telefonu."""
        if mechanism != "totp":
            raise ValueError(
                f"neznamy mechanismus {mechanism!r}; zatim existuje jen 'totp'"
            )
        name = check_identity(name)
        with _locked(self.home):
            self._require_not_last_admin(name)
            directory = self._dir(ADMIN_PREFIX, name)
            if not directory.is_dir():
                raise ValueError(f"spravce {name!r} neexistuje")
            if not any((directory / a).exists() for a in CREDENTIAL_ARTEFACTS):
                # Idempotentni: zadne tajemstvi neni zadny problem
                return
            for artefakt in CREDENTIAL_ARTEFACTS:
                (directory / artefakt).unlink(missing_ok=True)
            self._bump_gen()

    def pair_admin(self, name: str) -> Enrolment:
        """Nove parovani spravce. Existujici tajemstvi neprepise."""
        name = check_identity(name)
        _require_pairing()
        with _locked(self.home):
            directory = self._dir(ADMIN_PREFIX, name)
            if not directory.is_dir():
                raise ValueError(f"spravce {name!r} neexistuje")
            if (directory / "totp.secret").is_file():
                raise ValueError(
                    f"spravce {name!r} uz tajemstvi ma; nejdriv "
                    f"revoke_admin_credential - prepsani by ho zamklo ven"
                )
            # Osireny stav z preruseneho revoke (nebo cizi zasah): tajemstvi
            # chybi, ale used.json/uri/txt patrici STAREMU tajemstvi tu jeste
            # mohou lezet. Bez uklidu by _pair spadl na O_EXCL a nechal by
            # pulku stareho QR vedle pulky noveho.
            for artefakt in CREDENTIAL_ARTEFACTS:
                if artefakt != "totp.secret":
                    (directory / artefakt).unlink(missing_ok=True)
            enrolment = self._pair(name, directory, role="admin")
            self._bump_gen()
        return enrolment

    # == anti-replay =======================================================

    def _consume(
        self, name: str, purpose: str, *steps: int, prefix: str = USER_PREFIX
    ) -> bool:
        """Zapis pouzite kroky pod jeden ucel, atomicky pod jednim zamkem.

        Na disku lezi CISLA KROKU, ne kody: zadne poverení se tim nikam
        neuklada a prorezavani je pouhe porovnani. Sestimistna hodnota se
        casem vrati, takze bez prorezavani by seznam nejen rostl, ale po case
        zacal odmitat legitimni kody.

        Kdyz je kroku vic (dvoukodove overeni spravce), plati vsechno-nebo-nic:
        prorezava se podle nejvyssiho z nich a pokud uz je zapsany KTERYKOLI
        z nich, nezapise se zadny - jinak by pulka dvojice presla jako pouzita
        a druhy pokus se stejnym prvnim kodem uz by neprosel.
        """
        path = self._dir(prefix, name) / "used.json"
        with _locked(self.home):
            if path.is_file():
                used = json.loads(path.read_text(encoding="utf-8"))
            else:
                used = {}

            nejstarsi = max(steps) - (2 * WINDOW + 1)
            used = {
                klic: [s for s in staved if s > nejstarsi]
                for klic, staved in used.items()
            }

            jiz_pouzite = used.get(purpose, ())
            if any(step in jiz_pouzite for step in steps):
                return False

            used.setdefault(purpose, []).extend(steps)
            used = {klic: staved for klic, staved in used.items() if staved}
            _replace(path, json.dumps(used))
            return True

    # == zretezeni =========================================================

    def _table(self) -> dict:
        path = self.home / GROUPS
        if not path.is_file():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))

    def _write_table(self, table: dict) -> None:
        self.home.mkdir(parents=True, mode=DIR_MODE, exist_ok=True)
        _replace(self.home / GROUPS, json.dumps(table, indent=2, sort_keys=True))

    def _groups_of(self, name: str) -> set[str]:
        """Tranzitivni uzaver smerem NAHORU: kdo je v mzdach, je i v ucetni.

        Fronta s mnozinou uz nalezenych, takze cyklus ve zretezeni skonci -
        dva spravci, kazdy prida jedno zretezeni, a nikdo nevidi cely graf.
        Vyrobit cyklus sice `include` odmita, ale soubor muze prijit i odjinud.
        """
        table = self._table()

        parents: dict[str, set[str]] = {}
        for group, data in table.items():
            for child in data.get("includes", ()):
                parents.setdefault(child, set()).add(group)

        found = {g for g, data in table.items() if name in data.get("members", ())}
        queue = list(found)
        while queue:
            group = queue.pop()
            for parent in parents.get(group, ()):
                if parent not in found:
                    found.add(parent)
                    queue.append(parent)
        return found


# ===========================================================================
# Pomocne
# ===========================================================================


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


def _descendants(table: dict, start: str) -> set[str]:
    """Vsechno, co `start` obsahuje - primo i pres dalsi zretezeni."""
    seen: set[str] = set()
    queue = list(table.get(start, {}).get("includes", ()))
    while queue:
        group = queue.pop()
        if group in seen:
            continue
        seen.add(group)
        queue.extend(table.get(group, {}).get("includes", ()))
    return seen


def _write(path: Path, text: str) -> None:
    """Zapis s pravy 0600 uz pri VZNIKU souboru.

    Kdyby se prava nastavovala az po zapisu, existuje okamzik, kdy je
    tajemstvi citelne komukoli - kratky, ale skutecny.
    """
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
    with os.fdopen(handle, "w", encoding="utf-8") as out:
        out.write(text if text.endswith("\n") else text + "\n")
    os.chmod(path, FILE_MODE)


def _replace(path: Path, text: str) -> None:
    """Prepis souboru atomicky.

    Pres docasny soubor a prejmenovani: prerusenym zapisem do `groups.json` by
    se ztratilo clenstvi vsech, a poznalo by se to az tim, ze nikdo nikam
    nesmi.
    """
    tmp = path.with_name(path.name + ".tmp")
    handle = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    with os.fdopen(handle, "w", encoding="utf-8") as out:
        out.write(text if text.endswith("\n") else text + "\n")
    os.chmod(tmp, FILE_MODE)
    os.replace(tmp, path)


def _qr_text(uri: str) -> str:
    """QR jako text.

    Na server se clovek dostane pres ssh; `cat totp.txt` vypise kod do
    terminalu a telefon ho sejme z obrazovky. Obrazek je na hlave bez
    obrazovky k nicemu.
    """
    import io

    try:
        import qrcode
    except ImportError as chybi:
        raise RuntimeError(
            "textovy QR potrebuje qrcode: pip install 'access-manager[totp]'"
        ) from chybi

    code = qrcode.QRCode(border=2)
    code.add_data(uri)
    code.make(fit=True)
    buffer = io.StringIO()
    code.print_ascii(out=buffer)
    return buffer.getvalue()


def _matching_step(secret: str, code: str, now: float | None = None) -> int | None:
    """Ktery casovy krok ten kod odpovida - nebo `None`.

    `pyotp.verify` odpovi jen ano/ne, jenze pro anti-replay potrebujeme VEDET
    KTERY krok se spotreboval; bez toho by "pouzity kod" nesel zapamatovat.
    """
    pyotp = _require_totp()

    totp = pyotp.TOTP(secret)
    now = time.time() if now is None else now
    for offset in range(-WINDOW, WINDOW + 1):
        moment = now + offset * totp.interval
        if hmac.compare_digest(totp.at(moment), str(code)):
            return int(moment // totp.interval)
    return None


def _code_at_step(secret: str, step: int, code) -> bool:
    """Sedi kod PRESNE na dany krok? Zadna tolerance - sousednost je tvrda."""
    pyotp = _require_totp()
    totp = pyotp.TOTP(secret)
    return hmac.compare_digest(totp.at(step * totp.interval), str(code))
