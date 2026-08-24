"""Dratove tvary: presne ctyri podoby odpovedi a nic navic.

`reason` jde ven JEN komponentam s detail=true - jinak je odpoved
postranni kanal na vycet uzivatelu (design.md par. 3.1).
"""
from access_manager import Verdict
from access_manager.principals import Group, User
from access_manager.wire import group_to_wire, user_to_wire, verdict_to_wire


def test_an_ok_verdict_carries_sorted_principals():
    v = Verdict.ok("user:hana", {"group:b", "group:a"}, gen=41)
    assert verdict_to_wire(v, detail=False) == {
        "outcome": "ok", "subject_id": "user:hana",
        "principals": ["group:a", "group:b"], "gen": 41,
    }


def test_a_denied_verdict_hides_the_reason_by_default():
    v = Verdict.refused("unknown_user", gen=41)
    assert verdict_to_wire(v, detail=False) == {"outcome": "denied", "gen": 41}


def test_a_trusted_component_sees_the_reason():
    v = Verdict.refused("bad_code", gen=41)
    assert verdict_to_wire(v, detail=True) == {
        "outcome": "denied", "reason": "bad_code", "gen": 41,
    }


def test_need_factor_and_throttled_shapes():
    assert verdict_to_wire(Verdict.need_factor(("totp",), gen=1), detail=False) == {
        "outcome": "need_factor", "required": ["totp"], "gen": 1,
    }
    assert verdict_to_wire(Verdict.throttled(27, gen=1), detail=False) == {
        "outcome": "throttled", "retry_after": 27, "gen": 1,
    }


def test_an_unknown_user_is_just_exists_false():
    assert user_to_wire(None) == {"exists": False}


def test_a_user_shape_matches_the_design():
    u = User(name="hana", subject_id="user:hana", enabled=True,
             principals=frozenset({"user:hana", "group:a"}))
    assert user_to_wire(u) == {
        "exists": True, "subject_id": "user:hana", "enabled": True,
        "principals": ["group:a", "user:hana"],
    }


def test_a_group_shape_matches_the_design():
    g = Group(name="ucetni", members=("hana",), includes=("mzdy",))
    assert group_to_wire("ucetni", g) == {
        "exists": True, "members": ["hana"], "includes": ["group:mzdy"],
    }
    assert group_to_wire("neni", None) == {"exists": False}


def test_detail_never_leaks_a_reason_onto_ok_or_bare_denied():
    # Pojistka poradi vetvi: detail=True nesmi pridat "reason" tam, kam nepatri.
    ok = Verdict.ok("user:hana", {"user:hana"}, gen=1)
    assert "reason" not in verdict_to_wire(ok, detail=True)
    holy = Verdict(outcome="denied", gen=1)
    assert verdict_to_wire(holy, detail=True) == {"outcome": "denied", "gen": 1}
