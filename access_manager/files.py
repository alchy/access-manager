"""Souborovy backend."""
from __future__ import annotations

import hmac
import json
import time
from pathlib import Path

from .principals import PUBLIC, USERS, User, check_name
from .purpose import check_purpose
from .verdicts import Verdict

#: Kde skupiny bydli. Jeden soubor, protoze zatim staci jeden.
GROUPS = "groups.json"

#: Kolik kroku dozadu a dopredu se kod jeste uzna. Hodiny telefonu se rozchazi.
WINDOW = 1


class Files:
    """Identita a politika ze souboru pod jednim adresarem."""

    def __init__(self, home) -> None:
        self.home = Path(home).expanduser()

    # -- identita ----------------------------------------------------------

    def user(self, name: str) -> User | None:
        name = check_name(name)
        if not (self.home / f"user-{name}").is_dir():
            return None
        groups = {f"group:{g}" for g in self._groups_of(name)}
        return User(
            name=name,
            subject_id=f"user:{name}",
            principals=frozenset({f"user:{name}", USERS, PUBLIC, *groups}),
        )

    # -- overeni -----------------------------------------------------------

    def authenticate(self, username: str, credentials, *, purpose: str) -> Verdict:
        """Odpoved na "jsi to ty?" - nikdy na "smis to?"."""
        purpose = check_purpose(purpose)
        name = check_name(username)
        directory = self.home / f"user-{name}"

        if not directory.is_dir():
            return Verdict.refused("unknown_user")
        if (directory / "disabled").exists():
            return Verdict.refused("disabled")

        secret = directory / "totp.secret"
        if not secret.is_file():
            # Zalozeny adresar bez tajemstvi neni "spatny kod": je to
            # nedokoncene zavedeni a spravce to ma poznat z auditu.
            return Verdict.refused("no_secret")

        # Co je potreba, rozhoduje KOMPONENTA. Nezname jmeno mechanismu se
        # chova, jako by neprislo - jinak si klient vybere ten slabsi.
        code = dict(credentials or {}).get("totp")
        if not code:
            return Verdict.refused("need_second_factor", required=("totp",))

        step = _matching_step(secret.read_text(encoding="utf-8").strip(), code)
        if step is None:
            return Verdict.refused("bad_code")
        if not self._consume(name, purpose, step):
            return Verdict.refused("replay")

        user = self.user(name)
        return Verdict.ok(user.subject_id, user.principals)

    # -- anti-replay -------------------------------------------------------

    def _consume(self, name: str, purpose: str, step: int) -> bool:
        """Zapis pouzity kod pod jeho ucel. `False`, kdyz uz tam byl.

        Na disku lezi CISLO KROKU, ne kod: zadne poverení se tim nikam
        neuklada a prorezavani je pouhe porovnani. Sestimistna hodnota se
        casem vrati, takze bez prorezavani by seznam nejen rostl, ale po case
        zacal odmitat legitimni kody.
        """
        path = self.home / f"user-{name}" / "used.json"
        used = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}

        nejstarsi = step - (2 * WINDOW + 1)
        used = {
            klic: [s for s in steps if s > nejstarsi]
            for klic, steps in used.items()
        }

        if step in used.get(purpose, ()):
            return False

        used.setdefault(purpose, []).append(step)
        used = {klic: steps for klic, steps in used.items() if steps}
        path.write_text(json.dumps(used), encoding="utf-8")
        return True

    # -- zretezeni ---------------------------------------------------------

    def _table(self) -> dict:
        path = self.home / GROUPS
        if not path.is_file():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))

    def _groups_of(self, name: str) -> set[str]:
        """Tranzitivni uzaver smerem NAHORU: kdo je v mzdach, je i v ucetni.

        Fronta s mnozinou uz nalezenych, takze cyklus ve zretezeni skonci -
        dva spravci, kazdy prida jedno zretezeni, a nikdo nevidi cely graf.
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


def _matching_step(secret: str, code: str, now: float | None = None) -> int | None:
    """Ktery casovy krok ten kod odpovida - nebo `None`.

    `pyotp.verify` odpovi jen ano/ne, jenze pro anti-replay potrebujeme VEDET
    KTERY krok se spotreboval; bez toho by "pouzity kod" nesel zapamatovat.
    """
    try:
        import pyotp
    except ModuleNotFoundError as chybi:  # pragma: no cover - instalacni chyba
        raise RuntimeError(
            "TOTP potrebuje pyotp: pip install 'access-manager[totp]'"
        ) from chybi

    totp = pyotp.TOTP(secret)
    now = time.time() if now is None else now
    for offset in range(-WINDOW, WINDOW + 1):
        moment = now + offset * totp.interval
        if hmac.compare_digest(totp.at(moment), str(code)):
            return int(moment // totp.interval)
    return None
