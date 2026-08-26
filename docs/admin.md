# Správa: realmy, uživatelé, správci, klíče aplikací

*Co všechno spravuje správce realmu a provozovatel instance — a čím se liší.*

## Realmy

**Realm** je striktní jmenný prostor: identifikátor nadřazeného celku, typicky
FQDN (`example.com`), ale klidně libovolný název. Uvnitř žijí uživatelé,
skupiny, správci, klíče aplikací i auditní stopa; **přes hranici realmu nevede
nic** — stejné jméno ve dvou realmech jsou dvě různé identity. Na disku je
realm subadresář `realm-<název>/` pod datovým adresářem instance.

Realm **vzniká deklarací v konfiguraci** (viz [instalace.md](instalace.md)),
ne přes API ani konzoli. Při startu služby proběhne *reconcile*: doplní se
jen to, co chybí — chybějící adresáře, chybějící správci, párovací token
těm, kdo žádný nemají. Restart ve 3 ráno nikomu nic nevymění.

Všechna jména se normalizují na **malá písmena**; uživatelé a správci smí mít
jeden `@`, takže identifikátorem může být e-mailová adresa.

## Webová konzole

**Primární cesta ke správě** je webová konzole na portu **22001**
(`listeners.console` v konfiguraci, viz [instalace.md](instalace.md)).
Přihlášení vyžaduje realm, jméno správce a **dva kódy z po sobě jdoucích
oken** autentikátoru — stejně jako u knihovny níže. Konzole pokrývá všechny
běžné úkony: uživatele (založení, zákaz, smazání, odvolání a nové párování),
skupiny (členy i zřetězení), aplikace (registrace včetně jednorázového
zobrazení klíče a odvolání), správce (založení, odebrání, odvolání a
párování) a auditní stopu. Rozhraní přepíná mezi češtinou a angličtinou
(CS/EN v patě stránky).

Relace správce žije jen v paměti procesu — **restart služby odhlásí všechny
správce** (záměr, ne nedopatření: žádné tajemství session se nikam
neukládá).

Knihovna popsaná níže zůstává k dispozici provozovateli přímo na serveru
(např. přes ssh) — pro skriptování, automatizaci nebo když konzole zrovna
není po ruce.

## Správci realmu

Správce je **oddělená identita** (`admin-<jméno>/`): není uživatel, nemá
skupiny a běžným přihlášením neprojde. Tentýž člověk jako správce i člen má
dvě tajemství a dvě položky v autentikátoru se štítky
`example.com-admin-jindrich` a `example.com-member-jindrich` — odvolání
jedné se druhé nedotkne.

Vstup správce (do konzole i přes knihovnu) vyžaduje **dva kódy z po sobě
jdoucích oken** autentikátoru: opíšete aktuální kód, počkáte na přetočení
a opíšete i následující. Jedno odkoukané číslo nestačí.

**Pojistka:** posledního správce realmu nejde smazat ani mu zneplatnit
pověření — realm nesmí zůstat bez správy. Zásah má jen provozovatel
na serveru.

Tatáž správa přímo na serveru, knihovnou (viz výše — provozovatel přes ssh):

```python
from access_manager import Admin

admin = Admin.local("/var/lib/access-manager", realm="example.com",
                    actor="admin:jindrich")   # kdo bude v auditu

admin.add_user("hana")            # -> Enrolment; QR: cat .../user-hana/totp.txt
admin.add_group("ucetni")
admin.add_member("ucetni", "hana")
admin.include("ucetni", "mzdy")   # ucetni OBSAHUJE mzdy; cyklus se odmitne
admin.remove_group("ucetni")      # smaže i odkazy v cizím zřetězení

admin.disable_user("hana")        # docasne; clenstvi i audit zustavaji
admin.enable_user("hana")
admin.remove_user("hana")         # vcetne vycisteni ze skupin

admin.add_admin("marie")          # dalsi spravce (s QR)
admin.admins()                    # ["jindrich", "marie"]
```

## Ztracený telefon a platnost QR

```python
admin.revoke_credential("hana")   # odvola tajemstvi i spotrebovane kroky
admin.pair("hana")                # nove parovani (existujici NIKDY neprepise)
```

Párovací QR je zobrazené tajemství, ne registrační tiket, a proto má
omezenou platnost dvěma nezávislými mechanismy:

1. **Do spárování** — konec obstará **první úspěšné přihlášení**, ne první
   pokus: `_complete_pairing` běží až na úspěšné větvi ověření, takže
   špatný kód ani zaškrcení párování neshodí. Zapíše `totp.paired`
   a smaže `totp.txt` i `totp.uri`; `totp.secret` zůstává a ověřuje dál —
   mizí jen zobrazitelná podoba tajemství.
2. **Nejdéle N dní** (`qr_ttl_days`, výchozí 14) — nespárovaný párovací
   token expiruje a přihlášení vrací důvod `expired`; správce zneplatní
   pověření a vydá nový token. Deklarovaný správce s expirovaným
   nespárovaným tokenem dostane nový automaticky při dalším reconcile.

Konzole obojí respektuje: po spárování ukáže „Spárováno", po expiraci
vyzve k vydání nového tokenu. Soubory expirovaného tokenu na disku
zůstávají — skrývá se jen jejich zobrazení, dokud je někdo nevymění.

### Zavedení bez čtečky

Stránka **Zobrazit QR** nese pod QR kódem sekci **Zadat ručně** s toutéž
hodnotou k opsání: base32 tajemství a celé `otpauth://` URI, obojí
s tlačítkem Kopírovat. Je to pro případ, kdy není čím skenovat — konzole
přes ssh, terminál bez telefonu po ruce.

Není to druhé pověření, je to **tentýž obsah v jiném tvaru**, a má proto
i tutéž životnost: čte se z `totp.uri`, které se párováním i expirací
ztrácí přesně jako `totp.txt`. Kdyby se bralo z `totp.secret`, přežilo by
spárování a mazání artefaktů by ztratilo smysl.

Totéž jde i mimo web — soubory leží vedle sebe v adresáři identity:

```bash
cat .../user-hana/totp.txt    # QR jako text
cat .../user-hana/totp.uri    # otpauth:// URI
```

## Klíče aplikací

Aplikace získává přístup k realmu **registrací** — vznikne klíč, který se
zobrazí **právě jednou**; na serveru zůstává jen jeho sha256 otisk
(`components.json`), takže únik úložiště klíče nevyzradí:

```python
klic = admin.register_component("app:report",
                                detail=False)               # smi videt duvody?
print(klic)                       # am_k1_... — TED, pak uz nikdy

admin.add_origin("app:report", "10.42.0.0/16")      # odkud klic plati
admin.add_origin("app:report", "2a01:4f8:1c1b::/48")
admin.remove_origin("app:report", "10.42.0.0/16")

admin.components()                # zaznamy s key_id a otiskem
admin.revoke_component("app:report")
```

Rozsahy i `detail` se mění **bez zásahu do klíče**. Dřív se obojí dalo
zadat jen při registraci, takže přestěhování serveru — nebo změna názoru
na to, kolik smí aplikace vidět — znamenalo aplikaci zneplatnit a rozdat
nový klíč do všech instalací. Změna platí okamžitě, bez restartu: bumpne se
generace, na které stojí cache klíčů ve službě.

```python
admin.add_origin("app:report", "10.42.0.0/16")
admin.remove_origin("app:report", "10.42.0.0/16")
admin.set_detail("app:report", True)     # smi videt duvod zamitnuti
```

Konzole to má na stránce Aplikace **v řádku každé aplikace**: pole na
přidání rozsahu pod už přidanými, křížek u rozsahu ho odebere, přepínač
u sloupce s důvody ho zapne nebo vypne. Registrace zůstává dole, protože
zakládá něco nového.

Přijímá se IPv4 i IPv6, samostatná adresa i CIDR. Překlep se odmítne hned —
neuloží se, protože nerozpoznanou položku origin ACL přeskakuje a aplikace
by tiše přestala procházet. `10.0.0.5` a `10.0.0.5/32` je tatáž síť: nepřidá
se dvakrát a odebrat ji lze kterýmkoli z obou zápisů.

Registrace = udělení přístupu k **veřejnému API** realmu (ověřování a čtení)
— nic správcovského, žádný zápis, jen jeden realm. `origins` je druhý faktor
vedle klíče: uniklý klíč mimo uvedené sítě je bezcenný; **prázdné `origins`
znamená jen smyčku**, ne „kdokoli“. Ztracený klíč se nevzpomíná — odvolá se
a vydá nový; změna platí okamžitě, bez restartu.

## Omezování pokusů

Po `attempts` (výchozí 5) špatných kódech téže identity v okně `window_s`
(výchozí 60 s) vrací ověření `throttled` s `retry_after`. Počítají se jen
neúspěchy existujících identit — cizí ani náhodná jména počítadlo nezvedají,
takže nikdo nemůže zamknout cizí účet střelbou od vedle.

## Audit

Každý realm loguje do vlastního prostoru `audit/RRRR-MM-DD.jsonl` — jeden
řádek, jedna událost: každé ověření (s podrobným důvodem — `bad_code`,
`replay`, `unknown_user`…, které na drát nesmí) a každý zápis (s aktérem
a operací, včetně vydání a odvolání klíčů). Tajemství, kódy ani klíče se
nelogují nikdy. Denní soubory se po `audit_retention_days` (výchozí 90)
mažou. Čtení:

```python
from access_manager.audit import read_events

read_events("/var/lib/access-manager/realm-example.com",
            kind="authenticate", subject="user:hana")
```

### Kdo se ptal, ne jen koho

Záznam ověření nese kromě `subject` (koho se ptalo) i to, **kdo se ptal**:

```json
{ "kind": "authenticate", "subject": "user:demo", "purpose": "login",
  "component": "workbench", "key_id": "k3", "origin": "2001:db8::1",
  "outcome": "ok", "gen": 29, "t": "…" }
```

| pole | co říká |
|---|---|
| `subject` | koho se ptalo — `user:demo`, `admin:jindrich` |
| `component` | která aplikace o ověření požádala |
| `key_id` | kterým klíčem; po výměně klíče je z něj poznat který |
| `origin` | z jaké adresy — měřeno `resolve_origin`, stejně jako origin ACL |

Nepředané pole se **nepíše**. Lokální volání přes `Access.local` žádnou
adresu ani klíč nemá; prázdná hodnota by předstírala, že se měřily a nic
nevyšly. Přihlášení správce do konzole nemá `component` (je to konzole, ne
aplikace), ale `origin` ano.

Zbylé druhy událostí: `write` (zápis s aktérem a operací), `origin_denied`
(požadavek odmítnutý origin ACL, s `component`, `key_id` a `origin`)
a `session` (odhlášení, zamítnutý CSRF token, relace zabitá po odebrání
správce).

Co se do auditu **nedostane**, protože v jeho okamžiku ještě není znám realm
— neplatný klíč, neexistující realm při přihlášení — najdete v provozním logu
služby, viz [instalace.md](instalace.md).
