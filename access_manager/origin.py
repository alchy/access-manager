"""Puvod pozadavku: kdo se to vlastne pta.

Sdili API i konzole - obe stoji za stejnou reverzni proxy a obe musi merit
STEJNOU adresu, jinak by origin ACL, audit a throttling kazde videly neco
jineho. Proto to nesmi byt zduplikovane u kazde aplikace zvlast.

Jen stdlib - modul musi jit importovat bez extras.
"""
from __future__ import annotations

from ipaddress import ip_address, ip_network


def is_trusted_proxy(peer: str, trusted_proxies) -> bool:
    """Je `peer` mezi duveryhodnymi proxy? Prijima adresu i CIDR."""
    try:
        adresa = ip_address(peer)
    except ValueError:
        return False
    for polozka in trusted_proxies:
        try:
            sit = ip_network(polozka, strict=False)
        except ValueError:
            continue
        if adresa in sit:
            return True
    return False


def resolve_origin(environ: dict, cfg) -> str:
    """Puvod pozadavku: peer socketu, nebo hlavicka od duveryhodne proxy.

    Cizi peer se nikdy neveri - hlavicka se cte JEN, kdyz je peer sam
    v `trusted_proxies`. Bere se `hops`-ty prvek ZPRAVA; chybejici nebo
    zdeformovana hlavicka spadne zpatky na peer.
    """
    peer = environ.get("REMOTE_ADDR", "")
    if not is_trusted_proxy(peer, cfg.trusted_proxies):
        return peer
    header_klic = "HTTP_" + cfg.forwarded_header.upper().replace("-", "_")
    surovy = environ.get(header_klic)
    if not surovy:
        return peer
    prvky = [p.strip() for p in surovy.split(",") if p.strip()]
    if not (1 <= cfg.hops <= len(prvky)):
        return peer
    return prvky[-cfg.hops]
