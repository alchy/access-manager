"""Server entrypoint: reconcile, konzole i API zalozeni a spusteni."""
import json
from unittest.mock import Mock, patch

import pytest

from access_manager.server import main


def test_main_missing_config_closes_start(tmp_path):
    """Chybejici -c volba -> SystemExit."""
    with pytest.raises(SystemExit):
        main([])


def test_main_reconciles_and_serves(tmp_path):
    """main spusti reconcile, konzoli v demonskem vlakne a API primo
    v hlavnim vlakne."""
    # Pripravi konfiguraci
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()
    data_dir = tmp_path / "data"

    # Zakladni konfigurace
    (conf_dir / "service.json").write_text(
        json.dumps({
            "data": str(data_dir),
            "listeners": {"api": "127.0.0.1:22000", "console": "127.0.0.1:22001"}
        }),
        encoding="utf-8"
    )

    # Realm deklarace
    realms_dir = conf_dir / "realms"
    realms_dir.mkdir()
    (realms_dir / "example.com.json").write_text(
        json.dumps({"name": "example.com", "admins": ["jindrich"]}),
        encoding="utf-8"
    )

    # Monkeypatch - zachytavame volani waitress.serve a Thread vytvoren
    serve_calls = []
    thread_creations = []

    def mock_serve(app_or_callable, host=None, port=None, **kwargs):
        # Capture app/callable, host, and port
        serve_calls.append({
            "app": app_or_callable,
            "host": host,
            "port": port
        })

    # Custom Mock Thread class aby zachytavala vytvoreni
    class MockThread:
        def __init__(self, target=None, **kwargs):
            self.target = target
            thread_creations.append(
                {"target": target, "daemon": kwargs.get("daemon", False)}
            )
            # Bezne inicializace
            self.daemon = kwargs.get("daemon", False)

        def start(self):
            # Zavolej target ihned, aby se serve voleal bez ohledu na vlakno
            if self.target:
                self.target()

        def join(self):
            pass

    # Sentinel misto skutecne konzolove Flask aplikace - overuje se, ze
    # PRAVE tenhle navrat z create_console_app skonci na konzolovem serve.
    mock_console_app = Mock(name="console_app")

    with patch("access_manager.server._require_server") as mock_require, \
            patch(
                "access_manager.server.create_console_app",
                return_value=mock_console_app,
            ) as mock_create_console_app:
        # Vrat mock flask a waitress
        mock_flask = Mock()
        mock_app = Mock()
        mock_flask.Flask.return_value = mock_app  # app
        mock_waitress = Mock()
        mock_waitress.serve = mock_serve
        mock_require.return_value = (mock_flask, mock_waitress)

        # Monkeypatch threading.Thread
        with patch("access_manager.server.threading.Thread", MockThread):
            main(["-c", str(conf_dir)])

            # Jen konzole bezi ve vlakne (jako demon) - API posloucha primo
            # v hlavnim vlakne, bez vlastniho vlakna.
            assert len(thread_creations) == 1
            assert thread_creations[0]["daemon"] is True

    # create_console_app dostal konfiguraci sluzby (cfg) - overeni na
    # cfg.data, ktere zna i test (Path stejny jako data_dir).
    mock_create_console_app.assert_called_once()
    (predana_cfg,), _ = mock_create_console_app.call_args
    assert predana_cfg.data == data_dir

    # Overeni, ze reconcile probehl - admin adresar ma vzniknout
    assert (data_dir / "realm-example.com" / "admin-jindrich").is_dir()

    # Overeni, ze serve byl volan dvakrat (API primo, konzole ve vlakne)
    assert len(serve_calls) == 2

    # Overeni spojeni listeneru s aplikacemi
    api_call = next((c for c in serve_calls if c["port"] == 22000), None)
    console_call = next((c for c in serve_calls if c["port"] == 22001), None)

    assert api_call is not None, "API listener (22000) not found"
    assert console_call is not None, "Console listener (22001) not found"

    # API listener musi mit Flask app
    assert api_call["app"] is mock_app, "API listener has wrong app"
    assert hasattr(api_call["app"], "test_client"), (
        "API listener app lacks Flask attributes"
    )

    # Console listener musi mit prave to, co vratil create_console_app(cfg)
    assert console_call["app"] is mock_console_app, "Console listener has wrong app"


def test_main_merges_instance_defaults_into_declarations(tmp_path):
    """Instancni defaults dopadnou do kazde deklarace, ktera si vlastni
    hodnotu nerekla sama; deklarace s vlastni hodnotou si ji ponecha."""
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()
    data_dir = tmp_path / "data"

    (conf_dir / "service.json").write_text(
        json.dumps({
            "data": str(data_dir),
            "defaults": {"qr_ttl_days": 30},
        }),
        encoding="utf-8"
    )

    realms_dir = conf_dir / "realms"
    realms_dir.mkdir()
    (realms_dir / "bez-vlastni.json").write_text(
        json.dumps({"name": "bez-vlastni.example", "admins": []}),
        encoding="utf-8"
    )
    (realms_dir / "vlastni.json").write_text(
        json.dumps(
            {"name": "vlastni.example", "admins": [], "qr_ttl_days": 7}
        ),
        encoding="utf-8"
    )

    zachyceno = {}

    def mock_reconcile(home, declarations):
        zachyceno["declarations"] = list(declarations)
        return []

    class MockThread:
        def __init__(self, target=None, **kwargs):
            self.target = target
            self.daemon = kwargs.get("daemon", False)

        def start(self):
            pass

        def join(self):
            pass

    def mock_serve(app_or_callable, host=None, port=None, **kwargs):
        pass

    with patch("access_manager.server.reconcile", mock_reconcile), \
            patch("access_manager.server._require_server") as mock_require, \
            patch("access_manager.server.threading.Thread", MockThread):
        mock_flask = Mock()
        mock_flask.Flask.return_value = Mock()
        mock_waitress = Mock()
        mock_waitress.serve = mock_serve
        mock_require.return_value = (mock_flask, mock_waitress)

        main(["-c", str(conf_dir)])

    podle_jmena = {d["name"]: d for d in zachyceno["declarations"]}
    assert podle_jmena["bez-vlastni.example"]["qr_ttl_days"] == 30
    assert podle_jmena["vlastni.example"]["qr_ttl_days"] == 7


def test_main_prints_new_enrolments(tmp_path, capsys):
    """main vypise cesty ke QR noveho zavedeni na stdout."""
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()
    data_dir = tmp_path / "data"

    (conf_dir / "service.json").write_text(
        json.dumps({"data": str(data_dir)}),
        encoding="utf-8"
    )

    realms_dir = conf_dir / "realms"
    realms_dir.mkdir()
    (realms_dir / "example.com.json").write_text(
        json.dumps({"name": "example.com", "admins": ["jindrich"]}),
        encoding="utf-8"
    )

    # Mock Thread class
    class MockThread:
        def __init__(self, target=None, **kwargs):
            self.target = target
            self.daemon = kwargs.get("daemon", False)

        def start(self):
            pass

        def join(self):
            pass

    # Monkeypatch
    def mock_serve(app_or_callable, host=None, port=None, **kwargs):
        pass

    with patch("access_manager.server._require_server") as mock_require:
        mock_flask = Mock()
        mock_flask.Flask.return_value = Mock()
        mock_waitress = Mock()
        mock_waitress.serve = mock_serve
        mock_require.return_value = (mock_flask, mock_waitress)

        with patch("access_manager.server.threading.Thread", MockThread):
            main(["-c", str(conf_dir)])

    captured = capsys.readouterr()
    assert "nove zavedeni:" in captured.out
    assert "totp.txt" in captured.out


def test_serve_keeps_forwarded_headers(tmp_path):
    """Oba servery dostanou clear_untrusted_proxy_headers=False.

    waitress ve vychozim stavu hlavicky X-Forwarded-* zahazuje driv, nez se
    dostanou do WSGI environ. Bez tohoto prepinace by _resolve_origin nikdy
    hlavicku nevidel, spadl zpatky na peer, a origin ACL i audit by za proxy
    merily adresu proxy misto klienta - tise, bez jedine chyby.
    """
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()
    data_dir = tmp_path / "data"
    (conf_dir / "service.json").write_text(
        json.dumps({
            "data": str(data_dir),
            "listeners": {"api": "127.0.0.1:22000", "console": "127.0.0.1:22001"},
            "trusted_proxies": ["127.0.0.1"],
        }),
        encoding="utf-8",
    )

    serve_calls = []

    def mock_serve(app_or_callable, host=None, port=None, **kwargs):
        serve_calls.append({"port": port, "kwargs": kwargs})

    class MockThread:
        def __init__(self, target=None, **kwargs):
            self.target = target
            self.daemon = kwargs.get("daemon", False)

        def start(self):
            if self.target:
                self.target()

        def join(self):
            pass

    with patch("access_manager.server._require_server") as mock_require:
        mock_waitress = Mock()
        mock_waitress.serve = mock_serve
        mock_require.return_value = (Mock(), mock_waitress)
        with patch("access_manager.server.threading.Thread", MockThread):
            main(["-c", str(conf_dir)])

    assert len(serve_calls) == 2, "ceka se API i konzole"
    for volani in serve_calls:
        assert volani["kwargs"].get("clear_untrusted_proxy_headers") is False, (
            f"listener na portu {volani['port']} zahazuje X-Forwarded-*"
        )

    # trusted_proxy se ZAMERNE nenastavuje - waitress by prepsal REMOTE_ADDR
    # a _resolve_origin by prisel o skutecneho peera, podle ktereho rozhoduje.
    for volani in serve_calls:
        assert "trusted_proxy" not in volani["kwargs"]
