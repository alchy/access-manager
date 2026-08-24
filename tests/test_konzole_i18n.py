"""Preklady konzole: JSON katalogy, fallback, paritni klice."""
from access_manager.konzole import preklady


def test_catalogs_have_identical_key_sets():
    cs = preklady.nacti("cs")
    en = preklady.nacti("en")
    assert set(cs) == set(en)
    assert cs                      # neprazdne


def test_an_unknown_language_falls_back_to_czech():
    assert preklady.nacti("de") == preklady.nacti("cs")


def test_a_missing_key_returns_the_key_itself():
    cs = preklady.nacti("cs")
    assert preklady.prelozit(cs, "neexistujici.klic") == "neexistujici.klic"


def test_known_keys_translate():
    cs = preklady.nacti("cs")
    en = preklady.nacti("en")
    assert cs["nav.people"] == "Lidé"
    assert en["nav.people"] == "People"
