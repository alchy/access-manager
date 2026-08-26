#!/bin/sh
# Vstupni bod kontejneru.
#
# Jedina vec, ktera v kontejneru neni, je konfigurace - ta se montuje zvenci.
# Kdyz se nenamontuje nic, kontejner NESPADNE: vyrobi si dummy konfiguraci,
# nahlas rekne, ze je dummy, a nastartuje. Smysl je, aby `podman run` bez
# jedineho prepinace neco delal a slo si na to sahnout.
set -eu

CONF="${ACCESS_MANAGER_CONF:-/etc/access-manager/conf.d}"

# Cokoli za prikazem se spusti misto sluzby - pro ladeni (`podman run ... sh`).
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

if ls "$CONF"/*.json >/dev/null 2>&1; then
    exec python -m access_manager.server -c "$CONF"
fi

# --- dummy defaults -------------------------------------------------------
# Do /tmp, ne do CONF: ten je typicky namontovany jen pro cteni a stejne do
# nej nemame co psat - konfigurace patri provozovateli, ne obrazu.
CONF=/tmp/access-manager-conf.d
mkdir -p "$CONF/realms"

# 0.0.0.0 je tu ZAMER: bez nej by publikovane porty (-p) nevedly nikam.
# Proto ta hlasitost nize - v host siti to znamena porty do sveta.
cat > "$CONF/service.json" <<'JSON'
{ "data": "/var/lib/access-manager",
  "listeners": { "api": "0.0.0.0:22000", "console": "0.0.0.0:22001" },
  "trusted_proxies": [],
  "hops": 1,
  "console_secure_cookie": false,
  "defaults": { "qr_ttl_days": 14, "audit_retention_days": 90 },
  "throttle": { "attempts": 5, "window_s": 60 } }
JSON

cat > "$CONF/realms/example.local.json" <<'JSON'
{ "name": "example.local", "admins": ["admin"] }
JSON

cat >&2 <<'VAROVANI'
================================================================================
POZOR: v /etc/access-manager/conf.d nebyla zadna konfigurace, bezim na DUMMY.

  realm            example.local, spravce "admin"
  naslouchani      0.0.0.0:22000 (API), 0.0.0.0:22001 (konzole)
  trusted_proxies  prazdne  -> origin ACL pusti jen smycku
  Secure cookie    vypnuta  -> relace konzole snese i holé HTTP

Na hrani to staci, do provozu ne. Namontujte vlastni conf.d:

  -v /cesta/ke/conf.d:/etc/access-manager/conf.d:ro

Bezite-li s --network=host, tohle naslouchani vystavuje oba porty do site.
================================================================================
VAROVANI

exec python -m access_manager.server -c "$CONF"
