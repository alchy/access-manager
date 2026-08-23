# Realms: jmenné prostory, konzole a klíče aplikací — návrh

*Stav: **odsouhlaseno** 2026-08-23. Navazuje na [docs/design.md](../../design.md)
(závazný) a na refaktoringový plán
[2026-08-23-refaktoring-klientske-knihovny.md](../plans/2026-08-23-refaktoring-klientske-knihovny.md).
Vzniklo dialogem nad webovým artefaktem „Access-manager Realms“; tento soubor je
úplný zápis rozhodnutí a v repu platí on.*

**Pořadí výstavby:** refaktoring souborové vrstvy (hotový plán) → realms
v knihovně (tento spec) → REST služba + kontejner → webová konzole. Každý krok
má vlastní spec → plán → implementaci.

---

## 1. Koncept

**Realm** je striktní jmenný prostor nad vším, co access-manager drží:
identifikátor nadřazeného celku, typicky FQDN (`example.com`), ale klidně
libovolný název. Uvnitř realmu žijí uživatelé, skupiny, správci, aplikace
s klíči i auditní stopa; **přes hranici realmu nevede nic.** Stejné jméno ve
dvou realmech jsou dvě různé identity.

Model počítá s horším případem — realmy si mohou být navzájem **cizí** (více
organizací na jedné instanci). Že je někdo použije jen na oddělení vlastních
domén, je věc nasazení, ne návrhu.

Služba má dvoje dveře:

- **veřejné API** — jen čte a ověřuje (aplikace, viewBase core),
- **webová konzole** — modul služby, ve kterém se odehrává veškerá správa
  realmu. Správcovské API na drátě neexistuje.

Hranice komponenty se nemění: odpovídá na „jsi to ty?“ a „kam patříš?“
(plochý uzávěr), nikdy na „smíš to?“; nedrží relace uživatelů, tokeny ani
politiku (design.md §5).

## 2. Úložiště a záznamy

**Konfigurace deklaruje, stav vzniká provozem.** Do `conf.d/` píše člověk
a služba ho jen čte; do `DATA/` píše jen služba (konzole, reconcile) a člověk
ho needituje. Jediný most mezi nimi je reconcile — přečte deklaraci a dorovná
stav, nikdy obráceně. Fragmenty konfigurace se při startu sčítají; skaláry
v konfliktu zavřou start (design.md §7.2).

```
# deklarace — píše člověk, služba jen čte
conf.d/
  service.json               ← listenery, důvěryhodné proxy, výchozí hodnoty
                               (qr_ttl_days, audit_retention_days)
  realms/
    example.com.json         ← realm: jméno a bootstrap správci (§3)

# stav — vyrábí služba, člověk needituje
DATA/
  realm-example.com/
    admin-jindrich/          ← správce; bez vazby na případného user-jindrich
      totp.secret            ← tajemství (0600); nikdy se nepřepisuje
      totp.issued            ← kdy bylo vydáno párování — hodiny expirace QR
      totp.uri  totp.txt     ← QR; jen do spárování, pak se mažou (§5)
      totp.paired            ← vzniká prvním úspěšným přihlášením
      used.json              ← anti-replay, per účel
    user-jindrich.nemec@yahoo.com/
      …stejné artefakty…  [disabled]
    groups.json              ← skupiny a zřetězení, jak jsou napsané
    components.json          ← aplikace: key_id, otisk klíče, origins, detail —
                               spravuje konzole (§6); klíč sám tu nikdy neleží
    gen                      ← generace realmu; zvedne ji každý zápis
    .lock                    ← výhradní zámek realmu
    audit/
      2026-08-23.jsonl       ← denní auditní soubory (§9)
```

Realm je subadresář s **přesně dnešním layoutem** — hotová souborová vrstva
platí beze změny, mění se jen kořen, na který se `FileStore` postaví. Zámek,
generace i vyhrazené skupiny (`users`, `public`) jsou tím per realm zadarmo.
**Žádný výchozí realm neexistuje** a plochá instalace se nemigruje (projekt je
nevydaný, čistý řez je teď zadarmo).

**Jména.** Realm, uživatel, správce i skupina procházejí jednou kontrolou:
písmena, číslice, `-`, `_`, tečka uvnitř (FQDN projde). U uživatelů a správců
je navíc povolen právě jeden `@`, takže **identifikátorem může být e-mailová
adresa** — `user-jindrich.nemec@yahoo.com/` je platný adresář
a `user:jindrich.nemec@yahoo.com` platný principál. Všechna jména se
**normalizují na malá písmena**: `Example.com` a `example.com` nesmí být dva
realmy, `Jindrich@…` a `jindrich@…` dva lidé.

## 3. Vznik realmu

Realm se neregistruje v konzoli ani přes API: vznikne **přidáním JSON objektu
do konfigurace**. Služba pak při startu (nebo na pokyn) provede **reconcile**
ve stylu `pair_missing` — doplní, co je deklarované a chybí, a ničeho
existujícího se nedotkne.

```json
{ "name": "example.com",
  "admins": ["jindrich"] }
```

Víc toho v deklaraci není — a je to záměr. **Aplikace do konfigurace
nepatří** (§6). Provozovatel zakládá realm a jeho první správce; o vnitřku
realmu neví nic. Realm může nanejvýš přebít výchozí hodnoty ze `service.json`
(`qr_ttl_days`, `audit_retention_days`).

Sled kroků od deklarace k fungujícímu realmu:

1. **Provozovatel** přidá JSON soubor do `conf.d/realms/`.
2. **Služba** (reconcile) založí `realm-example.com/`, adresáře deklarovaných
   správců a párovací QR — **jen těm, kdo žádné nemají**. Restart ve 3 ráno
   nikomu nic nevymění. Každé založení jde do auditu realmu jako `operator`.
3. **Provozovatel** přečte textový QR přes ssh (`cat totp.txt`) a předá ho
   správci mimo pásmo. Tajemství samotné server neopouští.
4. **Správce** sejme QR do autentikátoru. Položka nese plný štítek
   `example.com-admin-jindrich` (§4). Žádné heslo neexistuje.
5. **Správce** se přihlásí do konzole dvěma sousedními kódy (§4).
6. **Správce** přebírá správu: lidé, skupiny, aplikace, tokeny, další
   správci, audit. Provozovatele už nepotřebuje — s jedinou výjimkou:
   fyzické smazání realmu je opět jen jeho úkon na serveru.

**Zmizení z konfigurace ≠ smazání.** Když realm z deklarace zmizí, služba ho
přestane obsluhovat — data zůstávají. Konfigurace umí jen přidávat;
`admins` v JSONu je bootstrap, další správci se přidávají už jen v konzoli
a sjednocením konfigurace nejde nikoho odebrat.

## 4. Správci a identity rolí

Správce realmu je **oddělená identita** (`admin-<jméno>/`): není uživatel,
nemá skupiny, nefiguruje ve výpisech ani v principals a běžným `authenticate`
neprojde. Jeho subjekt je `admin:<jméno>`, principals prázdné.

**Žádná vazba na stejnojmenného uživatele.** Tentýž člověk, který realm
spravuje a zároveň je v něm členem, dostává dvě samostatné autentizační
identity: dvě tajemství, dvě párování, dvě položky v autentikátoru. Plný
autentizační identifikátor má tvar `<realm>-<role>-<jméno>`, role je `admin`
nebo `member`: `example.com-admin-jindrich` vs. `example.com-member-jindrich`;
odvolání jedné se druhé nedotkne.

**Štítek se nikdy neparsuje.** Tvar `<realm>-<role>-<jméno>` je párovací
štítek pro lidské oči a autentikátor; pomlčka se může vyskytovat uvnitř realmu
i jména, takže zpětně se z něj nic neodvozuje. Úložiště, API i audit pracují
vždy s trojicí (realm, role, jméno) zvlášť.

Realm může mít správců víc — ztracený telefon jediného správce by jinak zamkl
celý realm. **Posledního správce nejde odebrat ani mu odvolat token**; to smí
jen provozovatel zásahem na serveru.

**Přihlášení dvěma sousedními kódy.** Vstup do konzole vyžaduje dva kódy
z po sobě jdoucích oken, odeslané v jednom požadavku: pro první kód se najde
krok *s* (s dnešní tolerancí hodin `WINDOW`), druhý musí sedět **přesně na
krok s+1**, jinak `bad_code`. Oba kroky se spotřebují v anti-replay. Jedno
odkoukané číslo nestačí — dokazuje se souvislé držení autentikátoru. Služba
mezi požadavky nedrží žádný stav. Důvody se recyklují: `bad_code`, `replay`,
`no_secret`, `unknown_user`, `disabled`, `expired`.

**Relace konzole.** Přihlášení není veřejný endpoint — je to vstup do
konzole. Relaci drží konzolová vrstva; restart služby ji ukončí, a to je
vědomé rozhodnutí: týká se jen správců (zadají dva kódy znovu), nikdy
uživatelů aplikací, jejichž relace drží volající jako dosud.

## 5. Platnost párovacího QR

QR je zobrazené tajemství, ne registrační tiket — proto má omezenou platnost
dvěma nezávislými mechanismy, stejně pro uživatele i správce:

- **Do spárování.** Po prvním úspěšném přihlášení vznikne `totp.paired`
  a `totp.txt` i `totp.uri` se smažou — tajemství zůstává a ověřuje dál, ale
  už není co sejmout. Nový QR existuje jedině cestou odvolání + nového
  párování.
- **Nejdéle N dní.** Zavedení, které se nikdy nespárovalo, po `qr_ttl_days`
  dnech od `totp.issued` (výchozí 14, v konfiguraci) expiruje: `authenticate`
  vrací `denied` s důvodem `expired` a správce vydá nový QR. Důvod `expired`
  tím přestává být jménem pro stav, který nemůže nastat — má výrobce.

Deklarovaný správce, jehož zavedení expirovalo nespárované, dostane při
dalším reconcile QR nový: výměna tajemství, které nikdo nikdy nepoužil,
nikoho nezamyká. Realm se tak nezasekne s expirovaným prvním správcem.

## 6. Aplikace a jejich klíče

Aplikace (komponenty) **registruje správce realmu v konzoli** — nejsou věcí
konfigurace ani provozovatele:

- Konzole vygeneruje klíč a zobrazí ho **jednou**; správce ho zkopíruje do
  konfigurace aplikace. Ve stavu realmu (`components.json`) zůstane jen
  `key_id` (identifikátor do auditu), **otisk klíče** (`sha256` — u
  256bitového náhodného klíče rychlý hash stačí, argon2 je na hesla),
  `origins` (CIDR) a `detail` (bool). Klíč sám na serveru nikdy neleží;
  ztracený klíč se nevzpomíná, vydá se nový.
- Odvolání a výměna klíče, omezení původu i povolení `detail` — vše
  v konzoli, vše v auditu.
- Registrace aplikace je zápis stavu jako každý jiný: zvedne generaci
  a platí hned, **bez restartu i bez reloadu** služby.
- Jméno komponenty je neprůhledný řetězec (`core`, `app:workbench.graph`);
  služba mu nerozumí, jen vyžaduje unikátnost v realmu a stálost. Není to
  cesta na disku, takže pravidla jmen z §2 se na něj nevztahují.

## 7. Veřejné API

**Realm na drátě není**: určuje ho klíč, který aplikaci vydal správce
v konzoli jejího realmu — vazba je strukturální a do cizího realmu klíč
nedosáhne ani omylem. Cesty tak zůstávají **přesně podle závazného
design.md** a aplikace o realmech nemusí vědět vůbec.

**Veřejné API nemá jediný zapisovací endpoint.**

| metoda a cesta | co dělá |
|---|---|
| `POST /v1/authenticate` | ověření člověka v realmu klíče; `username`, `credentials` (mapa mechanismus → hodnota), `purpose` |
| `GET /v1/users/{name}` | `enabled` + plochý tranzitivní uzávěr principálů |
| `GET /v1/users` · `/v1/groups` · `/v1/groups/{name}` | výpisy; skupina tak, jak je napsaná |
| `POST /v1/principals/check` | hromadně: které principály neexistují |
| `GET /v1/whoami` | čí je tento klíč: `{component, realm, key_id}` |
| `GET /v1/generation` | generace realmu klíče |
| `GET /healthz` · `/readyz` · `/v1/version` | provoz |

Odpovědi ověření jsou vždy `200` a mají přesně čtyři tvary (`ok`, `denied`,
`need_factor`, `throttled`); podrobný důvod jde do auditu, ne na drát
(design.md §3.1). Co venku záměrně není: jakýkoli zápis (jen konzole),
ověření správce (vstup do konzole), registrace realmu (jen konfigurace)
a fyzické smazání realmu (jen provozovatel).

Konzole poslouchá na **vlastním listeneru** (port či prefix s vlastními
pravidly původu dle design.md §2b) — vystavení veřejného API do internetu
samo o sobě nevystaví konzoli.

## 8. Důvěra aplikace ↔ autentikátor

| směr | mechanismus |
|---|---|
| aplikace → služba | **Klíč komponenty** (Bearer), per aplikace, vydaný v konzoli realmu; na serveru jen otisk. **Původ požadavku** (CIDR) jako druhý nezávislý faktor, kontrolovaný před čtením čehokoli — uniklý klíč z cizí sítě je bezcenný, počítadla se pro zablokovaný původ nezvedají. Kdo potřebuje víc než filtr adres, chce mTLS: adresa je filtr, ne totožnost. |
| služba → aplikace | **TLS s ověřením certifikátu** — kotva důvěry je URL + CA v konfiguraci aplikace. Knihovna ověření **vynucuje a nemá k němu vypínač**: správná odpověď na self-signed ve vývoji je přidat CA do konfigurace, ne vypnout ověření. K tomu při startu kontrola verze API a tvrzeného realmu proti `/v1/whoami` — nesoulad selže hlasitě hned. |

Co si strany svěřují: aplikace při přihlášení vidí a přeposílá TOTP kód —
model vědomě počítá s tím, že aplikace je důvěryhodná pro sběr pověření
(žádné přesměrování na přihlašovací stránku služby; to by vyžadovalo relace
a tokeny, které služba záměrně nedrží). Škodu omezuje jednorázovost kódu,
anti-replay a účel. Opačně autentikátor aplikaci **nikdy nedá tajemství** —
jen verdikt a principals; podrobný důvod jen komponentě s `"detail": true`.
`Access.local` řeší důvěru filesystémem (stejný stroj, práva souborů) —
vědomě obchází síťové kontroly, proto patří vývoji a službě samotné.

## 9. Auditní log

Každý realm loguje všechny aktivity do vlastního prostoru:
`realm-…/audit/RRRR-MM-DD.jsonl`, jedna událost na řádek. Denní soubory
dělají z retence (`audit_retention_days`, výchozí 90) prosté mazání souborů
a ze čtení rozsahu pro konzoli levnou operaci.

```
{"t":"2026-08-23T09:14:07Z","kind":"authenticate","user":"hana","purpose":"login","component":"app:workbench.graph","outcome":"ok","gen":41}
{"t":"2026-08-23T09:14:41Z","kind":"authenticate","user":"hana","purpose":"login","component":"app:workbench.graph","outcome":"denied","reason":"replay"}
{"t":"2026-08-23T09:20:12Z","kind":"write","actor":"admin:jindrich","op":"add_member","group":"ucetni","user":"hana"}
{"t":"2026-08-23T06:00:03Z","kind":"write","actor":"operator","op":"reconcile","created":["admin-jindrich"]}
```

- **Ověření** — čas, jméno, účel, kdo se ptal (jméno komponenty), výsledek
  s podrobným důvodem. Právě sem patří důvody, které na drát nesmějí.
- **Každý zápis** — kdo (`admin:…` z konzole, `operator` při reconcile), co
  a s čím; včetně vydání a odvolání klíčů aplikací. Z veřejného API žádný
  zápis nepřichází.
- **Nikdy** tajemství ani kód — jen jména, výsledky a čísla kroků.

Správce vidí audit svého realmu v konzoli; přes hranici realmu nevidí nikdo
nic.

## 10. Knihovna

Veřejný povrch zůstává dvojí (`Access`, `Admin`), realm se váže při
konstrukci:

```python
# aplikace — čte a ověřuje, nic víc
access = Access.remote(url, key=klic,          # klíč z konzole (copy/paste)
                       realm="example.com")    # tvrzení; nesoulad = pád při startu
access = Access.local(home, realm="example.com")   # bez klíče je realm povinný

# správa realmu — dnešní operace plus správci a aplikace; drží ho konzole
admin = Admin.local(home, realm="example.com")
admin.add_admin("petr") · admin.admins() · admin.remove_admin("petr")
admin.revoke_admin_credential("petr") · admin.pair_admin("petr")
admin.register_component("app:graf", origins=[...]) -> klíč (vrácen jednou)
admin.revoke_component("app:graf")

# provozovatel — deklarace a reconcile, žádné API
reconcile(home, deklarace)     # doplní jen to, co chybí
```

Ověření správce (`authenticate_admin` — dva sousední kódy) je **interní
vrstva konzole**, ne veřejný povrch knihovny. `Admin` dál neumí žádné
ověřování a `Access` žádný zápis.

## 11. Co se nemění

- Žádné relace uživatelů, tokeny ani politika ve službě; restart nikoho
  neodhlásí (výjimka: relace správců konzole, §4).
- Verdikt má čtyři tvary; existující tajemství se nikdy nepřepíše; tajemství
  nejde do logů ani reprezentací; žádné povinné závislosti; testy bez sítě.
- `docs/design.md` zůstává závazný — o realms se rozšíří při implementaci
  služby (subprojekt 3); do té doby je zdrojem rozhodnutí tento spec.
- Refaktoringový plán platí beze změny; realms na něm stavějí. Jediný dotyk:
  důvod `expired` (plán, úkol 2) dostává v §5 výrobce — plán ho už drží ve
  výčtu, nic se nemění.

## 12. Otevřené body (do specu služby a konzole)

1. Mechanika relace konzole (podepsaná cookie s klíčem generovaným při
   startu se nabízí — restart pak přirozeně odhlásí).
2. Throttling (`throttled`) — návrh v design.md §7.3, běží až po kontrole
   původu.
3. mTLS — konfigurace a kdy ho vyžadovat.
4. Databázový backend pro víc replik (anti-replay a počítadla sdílená) —
   design.md §7.1.
