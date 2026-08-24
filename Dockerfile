FROM python:3.12-slim
RUN useradd --create-home spravce
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY access_manager ./access_manager
RUN pip install --no-cache-dir '.[server,totp]'
USER spravce
VOLUME /var/lib/access-manager
EXPOSE 22000
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:22000/healthz')"
CMD ["python", "-m", "access_manager.server", "-c", "/etc/access-manager/conf.d"]
