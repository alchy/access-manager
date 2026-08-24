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


def test_a_fresh_instance_home_is_private(tmp_path):
    domov = tmp_path / "instance"
    Admin.local(domov, realm="example.com").add_user("hana")
    import stat as _stat
    assert _stat.S_IMODE(domov.stat().st_mode) == 0o700
