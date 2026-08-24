# Webová konzole — návrh

*Stav: pracovní spec subprojektu 4 (2026-08-24). Vychází z odsouhlaseného
design canvasu (https://claude.ai/code/artifact/4ab3f3ec-75aa-4731-8258-b4831a9e0eb9)
a specu realms; po dokončení subprojektu se tento soubor uklidí (podstatné jde
do docs/). Rozhodnutí označená „(nové)“ nebyla dosud výslovně schválena.*

## 1. Rozsah

Konzole je **modul služby** na vlastním listeneru (22001, default smyčka) —
nahrazuje dnešní 501 stub. Je **jedinou cestou správce**: pokrývá všechny
jeho úkony (lidé, skupiny, aplikace, správci, audit). Žádné veřejné
správcovské API nevzniká; konzole zapisuje knihovnou uvnitř procesu.
Mimo rozsah: registrace realmu (konfigurace), fyzické mazání realmu
(provozovatel), samoobsluha uživatelů, mobilní optimalizace.

## 2. Technologie (nové)

- **Flask + Jinja2 šablony, server-rendered HTML, žádný JS build** —
  jednoduché formuláře, minimální inline JS (copy klíče). Flask už je
  v extra `[server]`; Jinja2 přichází s ním.
- Balíček `access_manager/konzole/` (subpackage): `app.py` (factory
  `create_console_app(cfg)`), `templates/`, `preklady/cs.json` + `en.json`.
  Hatchling balí celé adresáře balíčku, žádná další konfigurace.
- Vizuální jazyk z design canvasu: tmavě smrkový sidebar (#14352A), papír
  (#F6F7F5), akcent #166B52, monospace na identifikátory. Jeden sdílený
  layout template; inline CSS (bez externích assetů).

## 3. Přihlášení a relace

- Login stránka: **realm + jméno správce + dva po sobě jdoucí kódy**
  (ověření = hotové `FileStore.authenticate_admin`). Instance obsluhuje
  víc realmů; relace je připnutá k jednomu realmu.
- Relace = podepsaná cookie (flaskový session mechanismus). **Secret key
  se generuje při startu procesu** — restart služby odhlásí správce
  (přijaté rozhodnutí ze specu realms; správce zadá dva kódy znovu).
  Cookie HttpOnly + SameSite=Lax; `Secure` flag řídí konfigurace
  (`console_secure_cookie`, default false — TLS terminuje proxy) (nové).
- Neúspěšné přihlášení = jedna hláška („Přihlášení se nezdařilo.“) bez
  rozlišení důvodu; podrobnost jde do auditu (subject admin:…). Throttling
  platí (už ve FileStore).
- Odhlášení tlačítkem; guard: každá jiná cesta bez platné relace →
  redirect na login.

## 4. CSRF a mutace (nové)

Každá mutace je POST s CSRF tokenem drženým v relaci a vkládaným do
formulářů; nesouhlas → 400 a žádný zápis. GET nikdy nemutuje.

## 5. Stránky (dle canvasu)

| stránka | obsah a akce |
|---|---|
| Lidé | tabulka (subjekt, stav vč. „čeká na spárování · QR platí N dní“, plochý uzávěr, akce); založit (zobrazí QR jako text + štítek), vypnout/zapnout, smazat, odvolat token, nově spárovat (QR) |
| Skupiny | seznam + detail: přímí členové (přidat/odebrat), zřetězení (přidat include; cyklus → chybová hláška z knihovny), „patří sem přes zřetězení“; založit/zrušit skupinu; vyhrazené skupiny odmítá knihovna |
| Aplikace | tabulka (jméno, key_id + otisk zkráceně, origins, detail); registrovat → **klíč zobrazen právě jednou** na výsledkové stránce s tlačítkem kopírovat; odvolat |
| Správci | tabulka (štítek, stav spárování); přidat (QR), odebrat / odvolat token (guard posledního správce → hláška z knihovny), nově spárovat |
| Audit | filtry (od/do dne, subjekt, druh, výsledek) nad `read_events`; **tolerantní čtení** (pole přes `.get`, neznámé druhy se vypíší surově) — normalizace schématu se tím stává zbytečnou, formát zůstává interní |

QR se v konzoli zobrazuje jako `<pre>` s ASCII obrazcem z `totp.txt`
(žádné obrázky, žádné závislosti navíc; ssh cesta `cat totp.txt` zůstává).

## 6. i18n CZ/EN (odsouhlaseno u designu)

Texty UI jsou placeholdery doplňované z JSON katalogů
`preklady/cs.json` / `en.json` (klíč → řetězec; ploché klíče typu
`nav.people`, `login.title`). Přepínač CZ/EN v patě sidebaru; volba se
drží v relaci (default `cs`). Chybějící klíč = fallback na `cs` a klíč
samotný (nikdy KeyError). Katalogy jsou data balíčku; kontrola úplnosti
(oba katalogy mají tytéž klíče) je součást testů.

## 7. Zápisy, audit a aktér

Konzole drží per-realm `FileStore` s `actor=f"admin:{jmeno}"` konstruovaný
per-request (levné — FileStore je tenký objekt nad cestou). Deferred
nález ze služby se tím uzavírá: `FileStore` dostane **veřejnou metodu
`audit_event(**pole)`** (obal nad dosavadním `_audit`); server.py
(origin_denied) i konzole ji používají místo sahání na privátní metodu.

## 8. Zapojení do služby

`main()` v server.py nahradí 501 stub: `create_console_app(cfg)` běží na
konzolovém listeneru (dál jako daemon vlákno; API v hlavním vlákně).
Chybějící extra `[server]` hlásí stávající `_require_server`. Testy:
flask test_client konzolové aplikace, bez soketů; přihlášení v testech
přes pyotp (dva sousední kroky `totp.at(t)`, `totp.at(t+30)`).

## 9. Otevřené / odložené

1. `Secure` cookie default zapnout, až bude konzole běžně za TLS proxy.
2. Vzhledová parita s canvasem je vodítko, ne pixel-perfect cíl v1.
3. Mobil, klávesové zkratky, stránkování dlouhých tabulek — až po v1.
