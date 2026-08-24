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


def test_retry_after_rides_only_on_throttled():
    assert Verdict.throttled(27).retry_after == 27
    with pytest.raises(ValueError):
        Verdict(outcome="denied", reason="bad_code", retry_after=5)
