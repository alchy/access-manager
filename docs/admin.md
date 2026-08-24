# Správa: realmy, lidé, správci, klíče aplikací

*Co všechno spravuje správce realmu a provozovatel instance — a čím se liší.*

## Realmy

**Realm** je striktní jmenný prostor: identifikátor nadřazeného celku, typicky
FQDN (`example.com`), ale klidně libovolný název. Uvnitř žijí uživatelé,
skupiny, správci, klíče aplikací i auditní stopa; **přes hranici realmu nevede
nic** — stejné jméno ve dvou realmech jsou dvě různé identity. Na disku je
realm subadresář `realm-<název>/` pod datovým adresářem instance.

Realm **vzniká deklarací v konfiguraci** (viz [instalace.md](instalace.md)),
ne přes API ani konzoli. Při startu služby proběhne *reconcile*: doplní se
jen to, co chybí — chybějící adresáře, chybějící správci, párovací QR těm,
kdo žádné nemají. Restart ve 3 ráno nikomu nic nevymění.

Všechna jména se normalizují na **malá písmena**; uživatelé a správci smí mít
jeden `@`, takže identifikátorem může být e-mailová adresa.

## Webová konzole

**Primární cesta ke správě** je webová konzole na portu **22001**
(`listeners.console` v konfiguraci, viz [instalace.md](instalace.md)).
Přihlášení vyžaduje realm, jméno správce a **dva kódy z po sobě jdoucích
oken** autentikátoru — stejně jako u knihovny níže. Konzole pokrývá všechny
běžné úkony: lidi (založení, zákaz, smazání, odvolání a nové párování),
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

**Pojistka:** posledního správce realmu nejde odebrat ani mu odvolat token —
realm nesmí zůstat bez správy. Zásah má jen provozovatel na serveru.

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

1. **Do spárování** — po prvním úspěšném přihlášení se `totp.txt`/`totp.uri`
   smažou; tajemství dál ověřuje, ale už není co sejmout.
2. **Nejdéle N dní** (`qr_ttl_days`, výchozí 14) — nespárované zavedení
   expiruje a přihlášení vrací důvod `expired`; správce vydá nový QR
   (odvolat + spárovat). Deklarovaný správce s expirovaným nespárovaným
   zavedením dostane nový QR automaticky při dalším reconcile.

## Klíče aplikací

Aplikace získává přístup k realmu **registrací** — vznikne klíč, který se
zobrazí **právě jednou**; na serveru zůstává jen jeho sha256 otisk
(`components.json`), takže únik úložiště klíče nevyzradí:

```python
klic = admin.register_component("app:report",
                                origins=("10.42.0.0/16",),  # odkud klic plati
                                detail=False)               # smi videt duvody?
print(klic)                       # am_k1_... — TED, pak uz nikdy
admin.components()                # zaznamy s key_id a otiskem
admin.revoke_component("app:report")
```

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
