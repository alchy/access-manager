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
#: musi byt tam. `expired` vyrabi TTL nesparovaneho zavedeni (QR platnost).
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
    """Vysledek overeni totoznosti.

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
    retry_after: int | None = None

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
        if self.retry_after is not None and self.outcome != "throttled":
            raise ValueError("retry_after patri jen k `throttled`")

    def __bool__(self) -> bool:
        return self.outcome == "ok"

    @classmethod
    def ok(cls, subject_id: str | None, principals, gen: int | None = None) -> Verdict:
        return cls(
            outcome="ok",
            subject_id=subject_id,
            principals=frozenset(principals),
            gen=gen,
        )

    @classmethod
    def refused(cls, reason: str, gen: int | None = None) -> Verdict:
        """Odmitnuti s duvodem. Ven jde `denied`; duvod je pro audit."""
        return cls(outcome="denied", reason=reason, gen=gen)

    @classmethod
    def need_factor(cls, required, gen: int | None = None) -> Verdict:
        return cls(outcome="need_factor", required=tuple(required), gen=gen)

    @classmethod
    def throttled(cls, retry_after: int | None, gen: int | None = None) -> Verdict:
        """Prilis mnoho pokusu. `retry_after` rika, za kolik sekund to zkusit."""
        return cls(outcome="throttled", retry_after=retry_after, gen=gen)
