"""Fragmentovana konfigurace: scita se, skalarni konflikt zavira start."""
import json

import pytest

from access_manager.config import load_config


def zapis(conf, jmeno, obsah):
    conf.mkdir(parents=True, exist_ok=True)
    (conf / jmeno).write_text(json.dumps(obsah), encoding="utf-8")


def test_a_minimal_config_gets_defaults(tmp_path):
    zapis(tmp_path / "conf.d", "service.json", {"data": str(tmp_path / "data")})
    cfg = load_config(tmp_path / "conf.d")
    assert cfg.listeners["api"] == "127.0.0.1:22000"
    assert cfg.hops == 1
    assert cfg.throttle["attempts"] == 5
    assert cfg.realms == ()


def test_fragments_are_summed(tmp_path):
    zapis(tmp_path / "conf.d", "10-base.json", {"data": str(tmp_path / "d")})
    zapis(tmp_path / "conf.d", "20-net.json", {"trusted_proxies": ["10.0.0.0/8"]})
    cfg = load_config(tmp_path / "conf.d")
    assert cfg.trusted_proxies == ("10.0.0.0/8",)


def test_a_scalar_conflict_closes_the_start(tmp_path):
    zapis(tmp_path / "conf.d", "a.json", {"data": "/a"})
    zapis(tmp_path / "conf.d", "b.json", {"data": "/b"})
    with pytest.raises(ValueError):
        load_config(tmp_path / "conf.d")


def test_missing_data_closes_the_start(tmp_path):
    zapis(tmp_path / "conf.d", "service.json", {"hops": 2})
    with pytest.raises(ValueError):
        load_config(tmp_path / "conf.d")


def test_realm_declarations_are_loaded(tmp_path):
    zapis(tmp_path / "conf.d", "service.json", {"data": str(tmp_path / "d")})
    zapis(tmp_path / "conf.d" / "realms", "example.com.json",
          {"name": "example.com", "admins": ["jindrich"]})
    cfg = load_config(tmp_path / "conf.d")
    assert cfg.realms == ({"name": "example.com", "admins": ["jindrich"]},)


def test_a_corrupt_fragment_closes_the_start(tmp_path):
    (tmp_path / "conf.d").mkdir()
    (tmp_path / "conf.d" / "service.json").write_text("{zlomeno", encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(tmp_path / "conf.d")
