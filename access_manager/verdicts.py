"""Verdikt: co access-manager odpovedel a proc."""
from __future__ import annotations

from dataclasses import dataclass, field

#: Kazdy duvod ma vlastni jmeno. Ve viewBase2 se tri ruzne priciny hlasily
#: stejnou hlaskou a stalo to hodinu hledani (chyba 3.6).
OUTCOMES = frozenset({
    "ok",
    "bad_code",
    "bad_password",
    "need_second_factor",
    "replay",
    "throttled",
    "no_secret",
    "unknown_user",
    "disabled",
    "expired",
})


@dataclass(frozen=True, slots=True)
class Verdict:
    """Odpoved na "jsi to ty?".

    Pravdivy je JEN `ok`. Kdo napise `if access.authenticate(...)`, dostane
    spravne chovani; kdo chce vedet proc, sahne na `outcome`.
    """

    outcome: str
    subject_id: str | None = None
    principals: frozenset[str] = field(default_factory=frozenset)
    required: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.outcome not in OUTCOMES:
            raise ValueError(
                f"nezname jmeno verdiktu {self.outcome!r}; zname: "
                f"{', '.join(sorted(OUTCOMES))}"
            )
        if self.outcome == "ok" and not self.subject_id:
            raise ValueError("verdikt `ok` bez subject_id: nevim, kdo prosel")

    def __bool__(self) -> bool:
        return self.outcome == "ok"

    @classmethod
    def ok(cls, subject_id: str | None, principals) -> "Verdict":
        return cls(outcome="ok", subject_id=subject_id, principals=frozenset(principals))

    @classmethod
    def refused(cls, outcome: str, required=()) -> "Verdict":
        if outcome == "ok":
            raise ValueError("odmitnuti se nesmi jmenovat `ok`")
        return cls(outcome=outcome, required=tuple(required))
