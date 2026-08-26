#!/bin/sh
# Pripravi stroj na provoz access-manageru v kontejneru. Spousti se JAKO ROOT,
# ale vysledkem je sluzba, ktera rootem nebezi.
#
#     sudo deploy/install-container.sh [--user JMENO] [--home CESTA]
#
# Co udela:
#   1. zalozi systemoveho uzivatele (nologin) a adresare conf.d/data/logs
#   2. deleguje mu subuid/subgid  - bez nich rootless podman nenastartuje
#   3. zapne linger              - bez nej neni kontejner po bootu co spustit
#   4. nainstaluje container-run.sh a systemd unit
#
# Idempotentni: co uz existuje, necha byt.
set -eu

UZIVATEL=access-manager
DOMOV=""
KOREN=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

while [ "$#" -gt 0 ]; do
    case "$1" in
        --user) UZIVATEL="$2"; shift 2 ;;
        --home) DOMOV="$2"; shift 2 ;;
        --help|-h) sed -n '2,17p' "$0"; exit 0 ;;
        *) echo "neznamy prepinac: $1" >&2; exit 2 ;;
    esac
done
[ -n "$DOMOV" ] || DOMOV="/www/$UZIVATEL"

[ "$(id -u)" -eq 0 ] || { echo "spustte jako root" >&2; exit 1; }
command -v podman >/dev/null || { echo "podman neni nainstalovan (dnf install podman)" >&2; exit 1; }

# --- 1. uzivatel a adresare ----------------------------------------------
if ! id "$UZIVATEL" >/dev/null 2>&1; then
    useradd --system --home-dir "$DOMOV" --create-home --shell /usr/sbin/nologin \
            --comment "access-manager service" "$UZIVATEL"
    echo "zalozen uzivatel $UZIVATEL"
fi
UID_UZ=$(id -u "$UZIVATEL")

# 0700: v data lezi parovaci tajemstvi. Uloziste si prava hlida samo, ale
# koren `data` si prechmoduje jen kdyz ho zaklada samo - viz docs/instalace.md.
for D in "$DOMOV/conf.d" "$DOMOV/conf.d/realms" "$DOMOV/.access-manager" "$DOMOV/logs"; do
    install -d -o "$UZIVATEL" -g "$UZIVATEL" -m 0700 "$D"
done
echo "adresare v $DOMOV pripraveny"

# --- 2. subuid/subgid -----------------------------------------------------
# Rootless kontejner potrebuje cely blok UID, ktere smi mapovat dovnitr.
# Bez nich podman odmitne start hlaskou o chybejicim namespace.
if ! grep -q "^$UZIVATEL:" /etc/subuid 2>/dev/null; then
    usermod --add-subuids 200000-265535 --add-subgids 200000-265535 "$UZIVATEL"
    echo "delegovany subuid/subgid pro $UZIVATEL"
fi

# --- 3. linger ------------------------------------------------------------
# "Bez terminalu": bez lingeru systemd uzivatelsky manager po bootu nespusti
# a /run/user/<uid> vubec nevznikne - podman pak nema kam polozit runtime.
loginctl enable-linger "$UZIVATEL"
echo "linger zapnut ($(loginctl show-user "$UZIVATEL" --property=Linger))"

# --- 4. skript a unit -----------------------------------------------------
install -m 0755 "$KOREN/deploy/container-run.sh" /usr/local/bin/access-manager-container

# UID se do unitu dosazuje az tady - napevno zapsana 980 by na jinem stroji
# ukazovala do prazdna.
sed -e "s#XDG_RUNTIME_DIR=/run/user/980#XDG_RUNTIME_DIR=/run/user/$UID_UZ#" \
    -e "s#DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/980/bus#DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$UID_UZ/bus#" \
    -e "s#user@980.service#user@$UID_UZ.service#g" \
    -e "s#^User=access-manager\$#User=$UZIVATEL#" \
    -e "s#^Group=access-manager\$#Group=$UZIVATEL#" \
    -e "s#^Environment=HOME=/www/access-manager\$#Environment=HOME=$DOMOV#" \
    "$KOREN/deploy/access-manager-container.service" \
    > /etc/systemd/system/access-manager-container.service
chmod 0644 /etc/systemd/system/access-manager-container.service

if [ ! -f /etc/sysconfig/access-manager-container ]; then
    cat > /etc/sysconfig/access-manager-container <<SYSCONFIG
# Prebiti parametru pro access-manager-container.service.
# Vychozi hodnoty jsou v /usr/local/bin/access-manager-container (--help).
#AM_IMAGE=localhost/access-manager:latest
#AM_CONF=$DOMOV/conf.d
#AM_DATA=$DOMOV/.access-manager
#AM_LOG=$DOMOV/logs
#AM_API_PORT=22000
#AM_CONSOLE_PORT=22001
#AM_BIND=127.0.0.1
#AM_IP=10.89.0.2
# Bez TZ bezi kontejner v UTC (viz docs/install-container.md, oddil o auditu).
#AM_TZ=Europe/Prague
SYSCONFIG
fi

systemctl daemon-reload
echo
echo "hotovo. Dal:"
echo "  1) konfigurace do $DOMOV/conf.d (service.json, realms/*.json)"
echo "  2) obraz:  sudo -u $UZIVATEL -H XDG_RUNTIME_DIR=/run/user/$UID_UZ $KOREN/deploy/container-build.sh"
echo "  3) start:  systemctl enable --now access-manager-container"
echo "  4) pred sluzbu postavte reverzni proxy s TLS - porty jsou jen na 127.0.0.1"
