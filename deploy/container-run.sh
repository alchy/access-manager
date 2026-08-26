#!/bin/sh
# Spusti sluzbu v kontejneru (rootless podman).
#
# Vsechny parametry maji vychozi hodnotu a jdou prebit promennou prostredi
# nebo prepinacem; systemd unit `access-manager-container.service` vola tenhle
# skript s `--foreground`, takze provoz a rucni spusteni nemuzou rozejit.
#
#     deploy/container-run.sh --help
set -eu

IMAGE="${AM_IMAGE:-localhost/access-manager:latest}"
NAME="${AM_NAME:-access-manager}"
# Vsechny tri cesty jsou parametry - vychozi se odvozuji od domovskeho
# adresare uzivatele, pod kterym kontejner bezi. Datovy adresar drzi konvenci
# projektu: ~/.access-manager (viz .gitignore a README).
DOMOV="${HOME:-/www/access-manager}"
CONF="${AM_CONF:-$DOMOV/conf.d}"
DATA="${AM_DATA:-$DOMOV/.access-manager}"
LOGDIR="${AM_LOG:-$DOMOV/logs}"
NETWORK="${AM_NETWORK:-am-net}"
IP="${AM_IP:-10.89.0.2}"
# Spousti-li kontejner systemovy systemd unit, bezi proces v system slice a
# uzivatelsky systemd mu scope vyrobit nemuze - start skonci na `creating
# systemd unit ... got failed`. cgroupfs tenhle krok obchazi a cgroupy zaklada
# primo v delegovane skupine (Delegate=yes v unitu).
CGROUP_MANAGER="${AM_CGROUP_MANAGER:-cgroupfs}"
API_PORT="${AM_API_PORT:-22000}"
CONSOLE_PORT="${AM_CONSOLE_PORT:-22001}"
BIND="${AM_BIND:-127.0.0.1}"
# Kontejner bez teto promenne bezi v UTC. Auditni stopu to NEOVLIVNI - ta je
# v UTC vzdycky, audit.py si razitka pocita z datetime.now(UTC) napevno. Zona
# je tu pro hodiny uvnitr kontejneru a pro cokoli, co by cetlo mistni cas.
TZ_ZONA="${AM_TZ:-}"
FOREGROUND=0

napoveda() {
    cat <<'NAPOVEDA'
Pouziti: container-run.sh [prepinace]

  --image TAG          obraz (AM_IMAGE)          [localhost/access-manager:latest]
  --name JMENO         jmeno kontejneru (AM_NAME)          [access-manager]
  --conf CESTA         conf.d na hostiteli (AM_CONF)       [$HOME/conf.d]
  --data CESTA         datovy adresar (AM_DATA)            [$HOME/.access-manager]
  --log CESTA          adresar logu (AM_LOG)               [$HOME/logs]
  --network JMENO      podman sit (AM_NETWORK)             [am-net]
  --ip ADRESA          pevna adresa kontejneru (AM_IP)     [10.89.0.2]
  --api-port PORT      port API na hostiteli (AM_API_PORT) [22000]
  --console-port PORT  port konzole (AM_CONSOLE_PORT)      [22001]
  --bind ADRESA        na co publikovat (AM_BIND)          [127.0.0.1]
  --tz ZONA            casova zona kontejneru (AM_TZ)      [UTC]
  --foreground         nedemonizovat (pro systemd)
  --help

Porty se publikuji na 127.0.0.1, tedy JEN pro tenhle stroj. Ven z nej nevede
nic - pred sluzbu patri reverzni proxy s TLS, viz docs/install-container.md.
NAPOVEDA
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --image) IMAGE="$2"; shift 2 ;;
        --name) NAME="$2"; shift 2 ;;
        --conf) CONF="$2"; shift 2 ;;
        --data) DATA="$2"; shift 2 ;;
        --log) LOGDIR="$2"; shift 2 ;;
        --network) NETWORK="$2"; shift 2 ;;
        --ip) IP="$2"; shift 2 ;;
        --api-port) API_PORT="$2"; shift 2 ;;
        --console-port) CONSOLE_PORT="$2"; shift 2 ;;
        --bind) BIND="$2"; shift 2 ;;
        --tz) TZ_ZONA="$2"; shift 2 ;;
        --foreground) FOREGROUND=1; shift ;;
        --help|-h) napoveda; exit 0 ;;
        *) echo "neznamy prepinac: $1" >&2; napoveda >&2; exit 2 ;;
    esac
done

[ -d "$DATA" ] || { echo "datovy adresar neexistuje: $DATA" >&2; exit 1; }
mkdir -p "$LOGDIR"

# Sit se zaklada idempotentne. Pevna adresa neni rozmar: sluzba uvnitr vidi
# jako zdrojovou adresu prave ji, a na tom stoji `trusted_proxies` - viz
# docs/install-container.md, oddil o puvodu pozadavku.
podman --cgroup-manager "$CGROUP_MANAGER" network exists "$NETWORK" || podman network create "$NETWORK" >/dev/null

# Zbytek po predchozim behu. `--rm` uklizi po sobe, ale ne po padu stroje.
podman rm -f "$NAME" >/dev/null 2>&1 || true

set -- \
    --rm \
    --init \
    --name "$NAME" \
    --network "$NETWORK" \
    --ip "$IP" \
    --publish "$BIND:$API_PORT:22000" \
    --publish "$BIND:$CONSOLE_PORT:22001" \
    --userns "keep-id:uid=1000,gid=1000" \
    --volume "$CONF:/etc/access-manager/conf.d:ro,z" \
    --volume "$DATA:/var/lib/access-manager:Z" \
    --log-driver k8s-file \
    --log-opt "path=$LOGDIR/service.log" \
    --log-opt max-size=10m \
    --stop-timeout 15

[ -z "$TZ_ZONA" ] || set -- "$@" --env "TZ=$TZ_ZONA"

[ "$FOREGROUND" -eq 1 ] || set -- "$@" --detach

exec podman --cgroup-manager "$CGROUP_MANAGER" run "$@" "$IMAGE"
