"""Konfiguracni loader: fragmenty se scitaji, skalarni konflikt zavira start."""
import json
from dataclasses import dataclass
from pathlib import Path


def _sluc(cil: dict, novy: dict, zdroj: str) -> None:
    """Sluc novy slovnik do ciloveho, detekuj skalarni konflikty."""
    for klic, hodnota in novy.items():
        if klic not in cil:
            cil[klic] = hodnota
        elif isinstance(cil[klic], dict) and isinstance(hodnota, dict):
            _sluc(cil[klic], hodnota, zdroj)
        elif cil[klic] != hodnota:
            raise ValueError(
                f"konflikt konfigurace u {klic!r} ({zdroj}): "
                f"{cil[klic]!r} vs {hodnota!r} - skalarni konflikt zavira start"
            )


@dataclass(frozen=True)
class ServiceConfig:
    """Konfigurace sluzby - immutabilni."""
    data: Path
    listeners: dict
    trusted_proxies: tuple[str, ...]
    forwarded_header: str
    hops: int
    defaults: dict
    throttle: dict
    realms: tuple[dict, ...]
    console_secure_cookie: bool
    log: dict


def load_config(conf_dir: Path) -> ServiceConfig:
    """Nacti konfiguraci ze vsech *.json v conf_dir a realms/*.json."""
    conf_dir = Path(conf_dir)

    # Nacteni vsech *.json z korene (serazeno podle jmena)
    config = {}
    fragment_files = sorted([f for f in conf_dir.glob("*.json")])

    for frag_file in fragment_files:
        try:
            with open(frag_file, encoding="utf-8") as f:
                novy = json.load(f)
            _sluc(config, novy, frag_file.name)
        except json.JSONDecodeError as e:
            raise ValueError(f"neplatny JSON v {frag_file.name}: {e}") from e

    # Overeni mandatory data
    if "data" not in config:
        raise ValueError("data je povinne")

    # Aplikuj vychozi hodnoty
    defaults_config = config.get("defaults", {})
    if "qr_ttl_days" not in defaults_config:
        defaults_config["qr_ttl_days"] = 14
    if "audit_retention_days" not in defaults_config:
        defaults_config["audit_retention_days"] = 90

    listeners_config = config.get("listeners", {})
    if "api" not in listeners_config:
        listeners_config["api"] = "127.0.0.1:22000"
    if "console" not in listeners_config:
        listeners_config["console"] = "127.0.0.1:22001"

    forwarded_header = config.get("forwarded_header", "X-Forwarded-For")
    try:
        hops = int(config.get("hops", 1))
    except (TypeError, ValueError) as chyba:
        raise ValueError(f"hops musi byt cislo: {config.get('hops')!r}") from chyba

    throttle_config = config.get("throttle", {})
    if "attempts" not in throttle_config:
        throttle_config["attempts"] = 5
    if "window_s" not in throttle_config:
        throttle_config["window_s"] = 60

    # Vychozi False - Secure cookie bez TLS by prohlizec zahodil rovnou a
    # konzole by nikdy neprihlasila nikoho; kdo bezi za TLS proxy, zapne to
    # sam (viz instalace.md).
    console_secure_cookie = bool(config.get("console_secure_cookie", False))

    # Provozni log (viz provoz.py). `json` je vychozi: radky cte stroj -
    # log driver kontejneru, journald, sberac - a `text` je ustupek cloveku,
    # ktery se diva bez `jq`. Nezname jmeno formatu NEzavira start; log neni
    # duvod nenastartovat sluzbu, spadne se na `json`.
    log_config = config.get("log", {})
    if "level" not in log_config:
        log_config["level"] = "info"
    if "format" not in log_config:
        log_config["format"] = "json"

    trusted_proxies_list = config.get("trusted_proxies", [])
    if not isinstance(trusted_proxies_list, list):
        trusted_proxies_list = [trusted_proxies_list]
    trusted_proxies = tuple(trusted_proxies_list)

    # Nacteni realm deklaraci
    realms_dir = conf_dir / "realms"
    realms_list = []
    if realms_dir.exists():
        realm_files = sorted([f for f in realms_dir.glob("*.json")])
        for realm_file in realm_files:
            try:
                with open(realm_file, encoding="utf-8") as f:
                    realm_config = json.load(f)
                realms_list.append(realm_config)
            except json.JSONDecodeError as e:
                raise ValueError(f"neplatny JSON v {realm_file.name}: {e}") from e

    realms = tuple(realms_list)

    # Vrat ServiceConfig - frozen je dataclass, ne obsah (slovniky zustanu mutabilni)
    return ServiceConfig(
        data=Path(config["data"]),
        listeners=listeners_config,
        trusted_proxies=trusted_proxies,
        forwarded_header=forwarded_header,
        hops=hops,
        defaults=defaults_config,
        throttle=throttle_config,
        realms=realms,
        console_secure_cookie=console_secure_cookie,
        log=log_config,
    )
