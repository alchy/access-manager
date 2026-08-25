# access-manager

**An authenticator and a group directory.** It answers one question and
attaches, in the same breath, where that person belongs:

    "is this you?"  ->  ok, user:jindrich, [group:mzdy, group:ucetni, ...]

Today there is a single mechanism: a phone authenticator (TOTP).

It **deliberately does not answer** *"may they?"* — and holds no ACLs for
that question either. Permissions belong to whoever knows their own objects;
access-manager does not know them and is not supposed to. The reasoning
lives in [docs/design.md](docs/design.md) (Czech), §5.

Group chaining is expanded **server-side** and returned as a flat transitive
closure — the classic LDAP pain of clients re-computing nested membership
(half of them incorrectly) does not exist here.

Two things worth knowing up front:

1. **You get a verdict, not a session.** Access-manager keeps nobody logged
   in — otherwise its 3 a.m. restart would log everyone out. Keeping people
   signed in is the caller's job.
2. **`group:users` and `group:public` are reserved** — "anyone
   authenticated" and "anyone"; every person carries them and they cannot
   be taken away.

## Realms

A single instance serves many **realms** — strict namespaces, typically
named by FQDN. Users, groups, admins, application keys and the audit trail
all live inside a realm; nothing crosses the boundary, and the same name in
two realms is two different identities. Realms are declared in the
configuration; on startup a *reconcile* pass creates only what is missing.
Realm admins are separate identities (pairing label
`<realm>-<role>-<name>`) with a two-consecutive-codes login. Application
keys are shown exactly once at registration; the server stores only their
sha256 fingerprint. The audit log is per realm.

## Installation

```bash
pip install git+https://github.com/alchy/access-manager
```

The client has **no mandatory dependencies**. Extras by role:
`[remote]` (httpx) to talk to a service, `[totp]` (pyotp, qrcode) to enrol
identities, `[server]` (flask, waitress) to run the service.

## Quick start

```python
from access_manager import Access

# same machine, no service (development, single-host):
access = Access.local("~/.access-manager", realm="example.com")

# against a running service:
access = Access.remote("https://auth.example.com",
                       key=os.environ["ACCESS_MANAGER_KEY"],
                       realm="example.com")

verdict = access.authenticate("jindrich", {"totp": code}, purpose="login")

if verdict.outcome == "need_factor":
    ...                        # verdict.required says what is missing
if not verdict:                # only outcome "ok" is truthy
    ...                        # one message to the user; reasons go to audit

verdict.subject_id             # "user:jindrich"
verdict.principals             # frozenset — the flat closure for allowed()
```

Both wirings return the same types; switching from local to remote changes
one line. `Access.remote` requires `https://` (loopback excepted for
development), verifies the certificate with no off-switch, checks the API
version and the key's realm loudly at startup, and retries transient
failures with backoff.

## Running the service

```bash
pip install 'access-manager[server,totp]'
python -m access_manager.server -c conf.d/
```

The REST API listens on port 22000, the management console on 22001. TLS
is terminated by a reverse proxy in front of the service — the proxy must
be listed in `trusted_proxies` so the origin ACL measures real client
addresses. A `Dockerfile` sits at the repository root; in a container,
bind `listeners.api` to `0.0.0.0:22000` (EXPOSE alone is not enough) and
adjust the healthcheck if you rebind.

The service reloads on **SIGHUP** - it re-reads `conf.d/`, reconciles the
declared realms and swaps both applications in place. Sockets stay bound, so
no connection drops and console sessions survive; a broken config is refused
and the old one keeps running. A restart still wipes sessions, by design.

Administration (users, groups, application keys, admins, audit) is done
through the web console (port 22001) as the primary path; the `Admin`
library object on the server remains available for operators over ssh.
Pairing QR codes are stored as text so `cat totp.txt` over ssh works on
headless machines.

## Documentation (Czech)

| document | contents |
|---|---|
| [docs/instalace.md](docs/instalace.md) | installation, service, nginx/trusted-proxy sample, Docker |
| [docs/admin.md](docs/admin.md) | realms, admins, application keys, QR validity, audit |
| [docs/aplikace.md](docs/aplikace.md) | connecting an application, usage examples |
| [docs/api.md](docs/api.md) | REST API and the trust model |
| [docs/design.md](docs/design.md) | the normative design and its reasoning |

## Status

Complete: the file storage layer (verification, group expansion,
anti-replay per purpose, full write half with identity lifecycle), realms
(admins, QR validity, application keys, per-realm audit, reconcile), the
REST service (flask/waitress behind a proxy, throttling), `Access.remote`
and the web console (all five pages — people, groups, applications, admins,
audit — CZ/EN switch, CSRF on every mutation, sessions die on service
restart by design) — 359 tests, all running without network or a live
server (the console is driven through `create_console_app(cfg).test_client()`).

## License

Apache 2.0, see [LICENSE](LICENSE).
