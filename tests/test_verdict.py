"""Odpoved na "jsi to ty?" je VERDIKT, ne bool.

Ve viewBase2 se tri ruzne priciny hlasily stejnou hlaskou a stalo to hodinu
hledani (chyba 3.6). Verdikt ale nesmi byt jen hezci navrat: az ho nekdo
napise do `if`, musi se chovat spravne. Verdikt, ktery je vzdy pravdivy, je
HORSI nez bool - protoze vypada bezpecne.
"""
import pytest

from access_manager import Verdict


def test_an_ok_verdict_is_truthy():
    assert Verdict.ok(subject_id="user:hana", principals=["user:hana"])


def test_a_refused_verdict_is_falsy():
    # `if access.authenticate(...)` musi propustit jen `ok`.
    assert not Verdict.refused("bad_code")


def test_a_refusal_cannot_accidentally_say_ok():
    # Preklep, ktery by z odmitnuti udelal propustku.
    with pytest.raises(ValueError):
        Verdict.refused("ok")


def test_an_unknown_outcome_is_refused_at_the_source():
    # `bad_cde` by bylo falsy, takze by `if` prosel spravne - a v auditu by
    # zustal nesmysl, ktery nikdo nikdy nedohleda.
    with pytest.raises(ValueError):
        Verdict.refused("bad_cde")


def test_an_ok_verdict_without_an_identity_is_refused():
    # "Prosel, ale nevim kdo" neni odpoved, se kterou jde neco delat.
    with pytest.raises(ValueError):
        Verdict.ok(subject_id=None, principals=["group:users"])
