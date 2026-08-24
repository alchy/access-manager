"""Server entrypoint a konzole 501."""
import json
from unittest.mock import Mock, patch

import pytest

from access_manager.server import console_app, main


def test_console_app_returns_501_with_json(tmp_path):
    """WSGI konzole vzdy vraci 501 a JSON s chybou."""
    # Primy WSGI vyzyvac - bez Flasku
    environ = {
        "REQUEST_METHOD": "GET",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "22001",
        "wsgi.url_scheme": "http",
    }
    response_data = []
    status = None
    headers = None

    def start_response(stat, hdrs):
        nonlocal status, headers
        status = stat
        headers = hdrs

    # Zavola aplikaci
    result = console_app(environ, start_response)
    if isinstance(result, (list, tuple)):
        response_data = b"".join(result)
    else:
        response_data = b"".join(result)

    # Overeni odpovedi
    assert status == "501 Not Implemented"
    body = json.loads(response_data)
    assert body == {"error": "console_not_implemented"}


def test_console_app_no_flask_dependency():
    """console_app se importuje bez flask."""
    # Testovani, ze modul lze naimportovat
    from access_manager import server
    assert hasattr(server, "console_app")
    assert callable(server.console_app)


def test_main_missing_config_closes_start(tmp_path):
    """Chybejici -c volba → SystemExit."""
    with pytest.raises(SystemExit):
        main([])


def test_main_reconciles_and_serves(tmp_path):
    """main spusti reconcile a zacne slouchat na obou listenerech."""
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
        serve_calls.append({"host": host, "port": port})

    # Custom Mock Thread class aby zachytavala vytvoreni
    class MockThread:
        def __init__(self, target=None, **kwargs):
            self.target = target
            thread_creations.append({"target": target})
            # Bezne inicializace
            self.daemon = kwargs.get("daemon", False)

        def start(self):
            # Zavolej target ihned, aby se serve voleal bez ohledu na vlakno
            if self.target:
                self.target()

        def join(self):
            pass

    with patch("access_manager.server._require_server") as mock_require:
        # Vrat mock flask a waitress
        mock_flask = Mock()
        mock_flask.Flask.return_value = Mock()  # app
        mock_waitress = Mock()
        mock_waitress.serve = mock_serve
        mock_require.return_value = (mock_flask, mock_waitress)

        # Monkeypatch threading.Thread
        with patch("access_manager.server.threading.Thread", MockThread):
            main(["-c", str(conf_dir)])

            # Overeni, ze se vytvořilo právě 2 vlákna
            assert len(thread_creations) == 2

    # Overeni, ze reconcile probehl - admin adresar ma vzniknout
    assert (data_dir / "realm-example.com" / "admin-jindrich").is_dir()

    # Overeni, ze serve byl volan dvakrat (API a konzole)
    assert len(serve_calls) == 2
    # Prvni je API, druha je konzole
    hosts_ports = [(c["host"], c["port"]) for c in serve_calls]
    assert ("127.0.0.1", 22000) in hosts_ports
    assert ("127.0.0.1", 22001) in hosts_ports


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
