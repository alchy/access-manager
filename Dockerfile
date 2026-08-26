# Obraz sluzby. Staví se z korene repozitare:
#
#     deploy/container-build.sh          (nebo: podman build -t access-manager .)
#
# V obrazu NENI konfigurace - ta se montuje zvenci do /etc/access-manager/conf.d.
# Bez ni kontejner nastartuje na dummy defaults, viz deploy/entrypoint.sh.
FROM python:3.12-slim

# UID natvrdo: rootless podman mapuje hostitelskeho uzivatele na tohle cislo
# pres --userns=keep-id:uid=1000,gid=1000. Kdyby se UID posunulo, prava na
# namontovanem datovem adresari prestanou sedet.
RUN useradd --create-home --uid 1000 spravce

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY access_manager ./access_manager
RUN pip install --no-cache-dir '.[server,totp]'

COPY deploy/entrypoint.sh /usr/local/bin/entrypoint.sh

# Adresare zalozit UZ TEDA a rovnou uzivateli sluzby: anonymni svazek podle
# VOLUME dedi vlastnictvi z obrazu, a kdyby patril rootovi, `spravce` by do
# nej nezapsal. Prava 0700 drzi uloziste stejne samo, tohle je vychozi stav.
RUN install -d -o spravce -g spravce -m 0700 /var/lib/access-manager \
 && install -d -o spravce -g spravce -m 0755 /etc/access-manager/conf.d \
 && chmod +x /usr/local/bin/entrypoint.sh

USER spravce
VOLUME /var/lib/access-manager
EXPOSE 22000 22001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:22000/healthz')"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD []
