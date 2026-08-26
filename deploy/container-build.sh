#!/bin/sh
# Postavi obraz sluzby z korene repozitare.
#
#     deploy/container-build.sh [tag]
#
# Spousti se JAKO UZIVATEL, pod kterym pak kontejner pobezi (rootless podman
# ma uloziste obrazu v jeho domovskem adresari - obraz postaveny rootem by
# byl uplne jinde a `podman run` by ho nenasel).
set -eu

TAG="${1:-localhost/access-manager:latest}"
KOREN=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

# --format docker NENI kosmetika: v nativnim OCI formatu podman instrukci
# HEALTHCHECK zahodi a kontejner nema jak rict, ze je nezdravy.
exec podman build --format docker -t "$TAG" -f "$KOREN/Dockerfile" "$KOREN"
