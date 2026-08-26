# Access-manager: REST API a klientská knihovna

*Samostatná služba s vlastním procesem. Používá ji víc aplikací najednou,
takže nemůže bydlet uvnitř žádné z nich; běží klidně v jiném kontejneru
než ony.*

*Rozsah: **čistě autentikátor a adresář skupin.** Politiku ani relace nedrží
— proč, je v §5.*

*Tenhle dokument popisuje **to, co je postavené**. Co v něm není, neexistuje;
otevřené otázky jsou v §7.*

---

## 1. Co to je a co to není

Access-manager odpovídá na otázky o **identitě**. O oknech, právech ani
relacích nerozhoduje.

Umí přesně tři věci:

| otázka | endpoint |
|---|---|
| je tohle hana? *(kód z autentikátoru)* | `POST /v1/authenticate` |
| v jakých je skupinách? | `GET /v1/users/hana` |
| existuje `group:ucetni`? | `POST /v1/principals/check` |

Všechny aplikace se ptají na totéž a dostanou totéž. Žádná nemá zvláštní
postavení; kdo potřebuje jen přihlašovací službu, vezme si `authenticate`
a o zbytek se nestará.

Co **zůstává volající aplikaci** a nikdy sem nepřejde:

| co | proč |
|---|---|
| oprávnění a všechna jejich pravidla | access-manager ty objekty nezná — §5 |
| relace | jinak by restart access-manageru odhlásil všechny |
| tokeny, které aplikace vydává svým klientům | tabulka vydaných tokenů má tutéž vlastnost jako relace: restart ve 3 ráno by je zneplatnil všechny |

**Hranice jednou větou:** access-manager říká *kdo jsi a kam patříš*;
volající počítá *co z toho plyne pro jeho objekt*.

**Mechanismus je dnes jediný: TOTP** — kód z autentikátoru v telefonu.
Nic dalšího (heslo, WebAuthn, certifikát) implementované není.

### 1.1 Slovník

Termíny níže jsou **normativní**. Platí pro dokumentaci, rozhraní konzole
i hlášky služby; ostatní dokumenty se na ně odkazují a nezavádějí vlastní.
Kde se rozchází pojmenování v kódu, je to uvedeno.

| termín | co to je | kde leží |
|---|---|---|
| **pověření** | tajemství, kterým se člověk prokazuje; ověřuje, dokud ho někdo nezneplatní | `totp.secret` |
| **párovací token** | zobrazitelná podoba pověření — QR a týž obsah k opsání; předává se člověku | `totp.uri`, `totp.txt` |
| **spárování** | okamžik, kdy člověk pověření poprvé úspěšně použil | `totp.paired` |
| **klíč aplikace** | čím se prokazuje aplikace, ne člověk; server drží jen jeho otisk | `components.json` |
| **realm** | jmenný prostor; přes jeho hranici nevede nic | `realm-<název>/` |
| **auditní stopa** | co se stalo uvnitř realmu | `realm-<x>/audit/` |
| **provozní log** | jak se vede procesu — viz §3.5 | `stdout`/`stderr` |

Dvojice **pověření / párovací token** není pedantství: každý má jinou
životnost a plete se to i v kódu. Párovací token zaniká **spárováním nebo
expirací**, pověření žije dál a ověřuje; zaniká až zneplatněním. Proto se
po prvním přihlášení nedá QR znovu zobrazit, ale člověk se přihlašuje dál.

Úkony a jejich přesný dosah:

| úkon | co zanikne | co zůstane | v kódu |
|---|---|---|---|
| **vydat párovací token** | — | — | `pair`, `pair_admin` |
| **zneplatnit párovací token / spárování** | pověření i token | členství, skupiny, auditní stopa, účet | `revoke_credential` |
| **zamknout uživatele** | nic | vše; přihlášení vrací `disabled` | `disable_user` |
| **smazat uživatele** | účet i členství | auditní stopa | `remove_user` |
| **zneplatnit klíč** | klíč aplikace | auditní stopa | `revoke_component` |

Sloveso **zneplatnit** (v kódu `revoke`) znamená vždy *„od teď to neplatí"*,
nikdy *„uklidilo se to"*. **Zamknout** je vratné a nic neničí. Rozdíl mezi
nimi musí být z rozhraní patrný dřív, než člověk klikne.

## 2. Kdo se ptá a čím se prokáže

Kanál je **autentizovaný od začátku**, ne „až v provozu" — jinak si
`SubjectContext` pošle kdokoli, kdo na službu dosáhne.

```
Authorization: Bearer <klíč aplikace>
```

Klíč je **per aplikace**, ne jeden sdílený: únik klíče jedné aplikace nesmí
být klíčem ke všemu. Server drží jen jeho otisk (sha256) a mapu na **jméno
aplikace** (`app:mzdy`); to jméno se s požadavkem nese dál — do auditu a do
ACL na původ (§2b). V kódu se ta věc jmenuje `Component`.

**Jaké to jméno je, je access-manageru jedno.** Nerozumí mu a nic z něj
neodvozuje — stejně jako u `purpose`: neprůhledné, ale ne dekorativní.
Potřebuje od něj dvě věci: aby bylo pro každou aplikaci jiné a aby se
neměnilo pod rukama. Kdyby dvě aplikace sdílely jméno, audit přestane
odpovídat na otázku „kdo se ptal" a zneplatnění jedné z nich vypne obě.

Kdo se neprokáže, dostane `401` a **žádný jiný rozdíl** — neexistující
a nepovolený endpoint vypadají stejně.

## 2b. Odkud se ptá — ACL na původ

Služba bude vystavená, klidně do internetu. Klíč je jeden faktor; **původ
požadavku je druhý, nezávislý.** Uniklý klíč z vývojářského notebooku pak
neplatí odkudkoli na světě.

### Co se počítá za původ

Pravdu drží **peer socketu**. Hlavička s předaným původem se bere v úvahu
**jen tehdy, když je peer v seznamu důvěryhodných proxy** — jinak se
ignoruje. Bez toho si `X-Forwarded-For: 10.0.0.1` pošle kdokoli a celé ACL
je ozdoba.

```json
{ "trusted_proxies": ["10.0.0.0/8"],
  "forwarded_header": "X-Forwarded-For",
  "hops": 1 }
```

`hops` je tam proto, že klient si může poslat vlastní `X-Forwarded-For`
a proxy k němu svůj údaj **připojí zprava**. Brát levý prvek znamená brát
to, co napsal útočník.

### Na co ACL sedí

Na **jednu jedinou věc: kde platí klíč aplikace.** Žádná další úroveň
neexistuje — ACL se nedá navěsit na endpoint, na uživatele ani na způsob
ověření.

```json
{ "components": {
    "app:mzdy":   { "key_id": "k1", "origins": ["10.42.0.0/16"] },
    "app:report": { "key_id": "k2", "origins": ["10.42.3.7"] } } }
```

Adresy jsou CIDR, IPv4 i IPv6 — pod v Kubernetes dostane často v6 a seznam
jednotlivých adres by tam nebyl k ničemu. Zapisují se v konzoli nebo přes
`add_origin`/`remove_origin`; klíč se u toho nemění.

Kdo hledá složitější pravidla, hledá marně a je to záměr: **origin ACL je
filtr plochy, ne autorizace.** Co smí projít dál, rozhoduje volající (§5).

### Odmítnutí

Nepovolený původ dostane `403` a **nic dalšího se nestane**. Kontrola běží
**jako první**: před parsováním těla, před hledáním uživatele, před
počítadly omezení. Ten pořádek není kosmetický — kdyby se počítadla zvedala
i pro zablokovaný původ, může kdokoli z internetu **zamknout cizí účet** tím,
že na něj bude z blokované adresy střílet. Filtr, který dopustí tohle, je
horší než žádný.

`403` neodporuje pravidlu „vždy 200" z §3.1. To pravidlo chrání před
prozrazením, jestli uživatel existuje — a tady ještě žádné jméno nikdo
nečetl. Prozradí se jen to, že tahle adresa sem nesmí, což ten, kdo na ní
sedí, stejně ví.

Odmítnutí jde do auditu s původem a **identifikátorem klíče, ne klíčem**.

### Tři věci, které to neumí

- **ACL na původ nikdy nic nepovoluje.** Neexistuje „z 10.0.0.0/8 klíč
  netřeba". Jen zužuje, kde platí klíč, který stejně musí být. Opačné
  zapojení je nejstarší chyba vnitřní sítě.
- **Adresa je filtr, ne totožnost.** Kdo potřebuje víc, chce mTLS; ACL na
  původ zmenšuje plochu, neověřuje volajícího.
- **V Kubernetes se zdrojová adresa často ztratí.** Maskaráda ukáže adresu
  uzlu u všeho — ACL pak vypadá, že funguje, a přitom nerozlišuje nic. Proto
  **chybějící `origins` znamená jen smyčku**, ne „kdokoli", a start to napíše
  do logu. Kdo chce jinak, napíše to; do internetu se nikdo nevystaví omylem.

## 3. Endpointy

Cesty jsou verzované (`/v1/`), aby klientská knihovna poznala neslučitelnou
verzi hned při startu, ne až u prvního dotazu.

**API je čtecí.** Celý jeho seznam:

```http
POST /v1/authenticate         §3.1    ověření totožnosti
GET  /v1/users · /v1/users/<jméno>    §3.2, §3.2b
GET  /v1/groups · /v1/groups/<jméno>  §3.2b
POST /v1/principals/check     §3.3    existují tyhle principály?
GET  /v1/whoami                       kdo jsem já, ta aplikace
GET  /v1/generation           §3.4    kdy zahodit cache
GET  /healthz · /readyz · /v1/version §3.4  provozní cesty, bez klíče
```

**Zapisuje se knihovnou nebo konzolí, ne po drátě.** Zakládání lidí, skupin
a aplikací, vydávání a zneplatňování pověření — to všechno dělá `Admin`
(§6) na stroji se službou, nebo správce v konzoli. Zápisový klíč, který
by obešel obojí, neexistuje a přes REST se dostat nedá.

### 3.1 Ověření člověka

**Ověřuje se pověření, ne oprávnění.** `authenticate` ověřuje **totožnost**;
o **oprávnění** rozhoduje volající a sem se ta otázka nedostane (§5). Ta dvě
slova znamenají různé věci a celý model stojí na tom, že se nesmažou.

```http
POST /v1/authenticate
{ "username": "hana",
  "credentials": { "totp": "123456" },
  "purpose": "login" }

200 { "outcome": "ok", "subject_id": "user:hana",
      "principals": ["group:public", "group:ucetni", "group:users",
                     "group:zamestnanci", "user:hana"],
      "gen": 41 }
200 { "outcome": "denied", "gen": 41 }
200 { "outcome": "need_factor", "required": ["totp"], "gen": 41 }
200 { "outcome": "throttled", "retry_after": 27, "gen": 41 }
```

**To jsou všechny čtyři tvary.** `principals` je setříděné, jinak nejde
odpověď porovnat ani cachovat. `gen` je číslo generace přibalené ke každé
odpovědi — bez něj by se na `GET /v1/generation` muselo chodit zvlášť, aby
volající věděl, kdy zahodit cache.

**Pověření je mapa mechanismus → hodnota**, ne jedno pole. Dnes má ta mapa
**jediný platný klíč, `totp`**; tvar je mapa proto, aby přidání dalšího
mechanismu nebylo změnou protokolu.

```json
{ "credentials": { "totp": "123456" } }
```

**Co je potřeba, rozhoduje služba, ne volající.** Jinak si klient sám vybere
slabší způsob. Proto verdikt `need_factor` s tím, co chybí — nikoli „second
factor": když je TOTP jediný mechanismus, není druhý. Neznámé jméno
mechanismu se chová, jako by nepřišlo.

- **`purpose` je povinný** a má tvar `login` nebo `unlock:<cíl>`. Anti-replay
  má účel: týž kód je legitimně potřeba dvakrát během jednoho
  třicetisekundového okna (přihlášení + krok navíc) a autentikátor mezitím
  žádný nový nevydá — společný seznam napříč vším je chyba 3.6. Cíl u
  odemykání je tam ze stejného důvodu o patro níž: kdo si ráno odemkne mzdy
  a hned nato terminál, narazí jinak na tutéž past.

  Access-manager účelu **nerozumí** — je to neprůhledný klíč přihrádky
  s použitými kódy. Nekontroluje, jestli `mzdy` něčemu odpovídá; o objektech
  volajícího neví nic (§1). Ověřuje jen **tvar**, aby se z volného řetězce
  nedalo udělat „pokaždé nový účel" a anti-replay tím vypnout.

  Účel skládá **volající aplikace**, ne její uživatel: nechodí z prohlížeče,
  sestaví ho server z toho, co se odemyká.

- **Použité kódy se prořezávají** po uplynutí platnosti. Šestimístná hodnota
  se časem vrátí, takže bez prořezávání seznam nejen roste, ale po čase
  začne odmítat legitimní kódy.

- **Verdikt, ne `true`/`false` — ale ten podrobný patří do auditu.** Tři
  různé příčiny hlášené stejnou hláškou už jednou stály hodinu hledání.
  Ta hodina se hledala **v logu**, takže tam ten rozdíl musí být:

  `ok` · `bad_code` · `need_factor` · `replay` · `throttled` · `no_secret` ·
  `unknown_user` · `disabled` · `expired`

  Ven jde jen ta čtveřice nahoře. Kdyby odpověď nesla `unknown_user`, umí si
  kdokoli vypsat uživatele — a byl by to **týž postranní kanál** jako `404`,
  jen o patro níž. Důvěryhodnému klientovi se to dá povolit v jeho záznamu
  (`"detail": true`), a pak dostane `{"outcome": "denied", "reason":
  "unknown_user"}`. Výchozí stav je bez `reason`.

  `unknown_user` a `disabled` zůstávají dva různé stavy: zablokovat člověka
  na tři dny je běžný úkon a smazat ho kvůli tomu znamená přijít o jeho
  členství i o auditní stopu.

- **Do auditu patří i „kdo se ptal", ne jen „koho se ptal".** Záznam ověření
  nese vedle `subject` také `component`, `key_id` a `origin` — tedy která
  aplikace o ověření požádala, kterým klíčem a z jaké adresy. Ani jedno
  o výsledku ověření nerozhoduje; je to čistě stopa.

  Bez `origin` má audit dohledatelnost obrácenou: adresu zaznamená jen
  u pokusu, který **odmítlo** origin ACL (`origin_denied`), a u úspěšného ji
  zahodí. „Odkud se včera ověřil `demo`" je přitom ta otázka, která se
  po incidentu ptá jako první.

  Nepředané pole se do řádku **nepíše**. Lokální volání (`Access.local`)
  žádnou adresu ani klíč nemá a prázdná hodnota by předstírala, že se měřily
  a nic nevyšly.

  Přihlášení správce do konzole komponentu nemá — je to konzole, ne aplikace —
  ale adresu ano, a měří ji `resolve_origin`, tedy **stejně** jako origin ACL
  (§2b). Kdyby to konzole počítala po svém, ukazoval by audit u téhož
  požadavku dvě různé adresy.

- Odpověď je **vždy `200`**. Rozlišitelný stavový kód by z HTTP udělal
  postranní kanál. Jediná výjimka je `403` za nepovolený původ (§2b), a ta
  padá dřív, než kdokoli přečte jméno.

### 3.2 Kdo je kdo

```http
GET /v1/users/hana
200 { "exists": true, "subject_id": "user:hana", "enabled": true,
      "principals": ["group:public", "group:ucetni", "group:users",
                     "group:zamestnanci", "user:hana"] }
200 { "exists": false }
```

Vrací se **plochý tranzitivní uzávěr**, ne přímé členství. Je to nejčastější
dotaz vůbec (obnova každé relace) a zároveň přesně to, co potřebuje
`allowed(principals, acl)` — jeden průnik množin.

**Zřetězení skupin rozbaluje access-manager, ne volající.** Kdyby volající
dostával graf a rozbaloval si ho sám, přibude druhé místo, kde se počítá
příslušnost — a v každém dalším klientovi znovu. Detekce cyklu patří sem,
jednou. Je to tatáž bolest jako u LDAPu, kde si vnořené členství počítá
každý klient a polovina špatně.

Používá se při **obnově relace**: principálové se počítají při každém
dotazu, ne při přihlášení — právě to dělá ze smazání uživatele účinný zásah
(chyba 3.5).

### 3.2b Výpis a členství

```http
GET  /v1/groups                    200 { "groups": [...] }
GET  /v1/groups/ucetni             200 { "exists": true, "members": [...],
                                          "includes": ["group:mzdy"] }
GET  /v1/users                     200 { "users": [...] }

PUT    /v1/groups/ucetni/members/hana
DELETE /v1/groups/ucetni/members/hana
```

`includes` je zřetězení: `group:ucetni` obsahuje `group:mzdy`, takže kdo je
v mzdách, je i v účtárně. **ACL se ukládá tak, jak je napsané** — rozbaluje
se až při dotazu. Kdyby se rozbalovalo při zápisu, přidání člověka do
skupiny by nezabralo na ACL, která už existují.

### 3.2c Životní cyklus pověření

**Po drátě nevede.** Zakládání lidí, vydávání a zneplatňování pověření,
členství ve skupinách — to všechno dělá `Admin` (§6) na stroji se službou,
nebo správce ve webové konzoli. Slovník těch úkonů a jejich přesný dosah je
v §1.1.

Je to záměr, ne mezera: kdyby zápis visel na témž klíči jako čtení, umí
každá aplikace se svým klíčem založit identitu a vydat jí pověření —
a rozdíl mezi „ptám se" a „rozhoduju, kdo existuje" tím zmizí. Kdo potřebuje
zapisovat vzdáleně, sáhne po ssh na stroj se službou; není to nedopatření,
je to ta hranice.

### 3.3 Existují tyhle principály?

```http
POST /v1/principals/check
{ "principals": ["group:users", "group:ucetni", "user:hana"] }

200 { "unknown": ["group:ucetni"] }
```

Dva použití, obě dnes existují a nemají zdroj:

- **při startu instance** — `default_access`, který jmenuje neexistující
  skupinu, je slib, který instance nemůže splnit; dnes to skončí prázdnou
  obrazovkou,
- **při změně ACL za běhu** — tichý překlep znamená okno, které nikdo
  neuvidí. Zápis se **neodmítne** (identita může vzniknout později), ale jde
  varování do auditu.

Hromadný dotaz schválně: při `serve()` se ověřuje celá deklarace najednou.

### 3.4 Provoz

```http
GET /healthz       200 { "status": "ok" }        // proces žije
GET /readyz        200 { "status": "ok" }        // úložiště odpovídá
GET /v1/version    200 { "api": "1", "build": "…" }
GET /v1/generation 200 { "gen": 41 }
```

**Generace** řeší napětí mezi dvěma pravidly, která platí obě: *„odvolání je
okamžité"* a *„expiraci si hlídá každý komponent sám"*. Když si komponenta
drží odpověď minutu, odvolání okamžité není. Jeden triviální dotaz to
zavírá bez push kanálu: nezměněné číslo znamená, že cache platí dál;
změněné, že se má zahodit.

### 3.5 Dva záznamy, jedna dělicí čára

Služba vede **dvě** stopy a každá odpovídá na jinou otázku:

- **auditní stopa** — co se stalo *uvnitř realmu*: kdo co zapsal, jak dopadlo
  ověření. Leží v `realm-<x>/audit/`, má retenci, čte ji konzole.
- **provozní log** — jak se vede *procesu*: co odmítl dřív, než vůbec věděl,
  o který realm jde. Jde na `stdout`/`stderr`, čte ho provozovatel.

Pravidlo, které mezi ně dělí, plyne z rozvržení úložiště, ne ze vkusu:
**auditní stopa je per-realm**. Událost, která nastane dřív, než je realm
určený — neplatný klíč komponenty (§2), zdeformovaný nebo neexistující realm
při přihlášení do konzole — nemá kam být zapsána. Právě ta patří do provozního
logu.

> Je-li znám realm, událost jde do auditu — a nikam jinam.
> Do provozního logu jde právě to, co do auditu zapsat nelze.

Žádná událost tedy není v obou. Dvě kopie by se musely držet v souladu
a jednu z nich by rotace provozního logu stejně zahodila; kdo hledá, musí
vědět, kde se dívá, a ne přeskakovat mezi dvěma místy, z nichž každé ví něco
jiného.

**Proud dělá triáž.** Běžný provoz jde na `stdout`, potíže na `stderr`.
Odmítnutý požadavek **není** chyba procesu — služba se právě zachovala
správně. Kdyby ležel na chybovém proudu vedle „přenačtení SELHALO", nerozliší
provozovatel jedno od druhého a `stream` v logu kontejneru nenese žádnou
informaci.

Podrobný důvod odmítnutí patří do obou stop podle téhož klíče (§3.1) — ven,
k volajícímu, jde pořád jen čtveřice tvarů. Kód, klíč ani hlavička
`Authorization` se do logu nedostanou nikdy.

## 4. Co z Kubernetes plyne pro API

**Běží ve víc replikách.** Proto musí být služba **bezstavová vůči
požadavku**: anti-replay použitých kódů i počítadlo pokusů patří do sdíleného
úložiště, ne do paměti procesu. Kdyby byly v paměti, druhá replika by
spotřebovaný kód přijala znovu — a `purpose` by ztratil smysl.

**Restartuje se.** Krátký výpadek se proto **přečkává, neselhává**: klient
zkouší znovu s krátkým backoffem. A start volající aplikace nesmí selhat
okamžitě — obojí se často nasazuje spolu, takže by z toho byla crash-loop.
Ověření má **deadline**, ne nulovou trpělivost.

**Restart nikoho neodhlásí,** protože relace vlastní volající. To není
náhoda, to je pravidlo.

## 5. Politika sem nepatří

Access-manager nikdy nedostane otázku *„smí hana číst tenhle dokument?"* —
a nedostane ani otázku *„jaká pravidla pro něj platí?"*. **Politiku nedrží
vůbec.** Je to čistě autentikátor a adresář skupin: odpoví, kdo jsi a kam
patříš. Co z toho plyne pro konkrétní objekt, počítá volající, protože je
jediný, kdo ten objekt zná.

**Hlavní důvod: access-manager ty objekty nezná.** Vznikají a zanikají za
běhu v kódu volajícího; aby na ně uměl odpovědět, musel by je mít u sebe
všechny — a registrovat každý vzniklý objekt do cizí služby není nepohodlí,
ale nesmysl. Ten důvod platí, i kdyby bylo API krásně typované: řetězcové
`authorize(subject, action, resource)` sice nejde vynutit ani otestovat, ale
to je argument o disciplíně, který by šel obejít lepším typováním. Tenhle
obejít nejde.

K tomu tři provozní důvody, které míří ke stejnému závěru:

1. **Byla by v horké cestě.** Kdo čte práva až v okamžiku doručení — a to
   je celý smysl pozdní vazby — dělal by přes síť jeden dotaz na každou
   doručenou zprávu. U živého provozu jsou to stovky za vteřinu.
2. **Cache ten problém neřeší, jen posune.** Odpověď zestárne přesně ve
   chvíli, kdy se práva změní — tedy v jediném okamžiku, na kterém záleží.
3. **Autorizace se musí dát otestovat bez sítě.** Dnes se celá testuje bez
   serveru; je to tvrdé pravidlo, ne náhoda.

Plyne z toho jedna věc pro volajícího: **jeho pravidla zůstávají u něj**
a jsou jediným zdrojem pravdy. Přebíjení politiky ze služby by udělalo zdroj
druhý, a dva zdroje pravdy o právech jsou horší stav než jeden nepohodlný.

## 6. Klientská knihovna je normativní

Závazná je **knihovna**, ne drát — tvar zpráv je její vnitřek a mění se
s verzí. Volný drát kupuje jedinou svobodu, totiž napsat si klienta ručně,
a přesně z ní vzejde znovu vymyšlený anti-replay. Kdo přesto potřebuje mluvit
po drátě, drží se §3; zaručené je ale rozhraní knihovny.

```python
from access_manager import Access, Admin

# kontejner jinde
access = Access.remote(os.environ["ACCESS_MANAGER_URL"],
                       key=os.environ["ACCESS_MANAGER_KEY"],
                       component="app:mzdy")

# jeden stroj, bez služby
access = Access.local("~/.access-manager")
```

**Dva objekty, ne jeden.** Aplikace dostane `Access`, správcovský nástroj
`Admin`:

```python
access.authenticate(username, credentials, purpose=…)  -> Verdict
access.user(name)                                      -> User | None
access.users() · access.groups()                       -> list[str]
access.group(name)                                     -> Group | None
access.unknown_principals(names)                       -> list[str]
access.generation()                                    -> int
access.ready()                                         -> str | None

admin.add_user(name)                                   -> Enrolment
admin.pair_missing()                                   -> list[Enrolment]
admin.add_group(name)
admin.add_member(group, name)
admin.include(parent, child)
admin.remove_group(name)                              # včetně odkazů v zřetězení
```

Kdyby zavádění viselo na témž objektu, umí každá apka se svým klíčem založit
uživatele a strčit ho do `group:spravci` — únik klíče jedné apky by byl klíč
ke všemu. Rozdělení je **tvar**; skutečné vynucení je na službě, která se
dívá na rozsah klíče (§2).

Co knihovna dělá, aby to nedělal každý sám:

- **retry s backoffem a deadlinem** — restart repliky se přečká,
- **krátkou cache** u `user`, s invalidací podle `gen`; nikdy u
  `authenticate`,
- **kontrolu verze API** při startu — neslučitelná major verze skončí hlasitě
  hned, ne u prvního dotazu,
- **mapování verdiktů na typy**, ať se `bad_code` nedá splést s `throttled`
  tím, že oba jsou „nepravda",
- **sanaci a redakci** toho, co jde do logu: kód ani klíč se do něj nedostanou.

Knihovna nemá **žádné povinné závislosti**. HTTP vrstva i TOTP jsou volitelné
extra, takže aplikace, která jen volá `authenticate`, si kvůli ní
nenainstaluje nic.

## 7. Otevřené body

Uzavřené — rozhodnuté a postavené:

- ~~Kdo drží politiku~~ — **nikdo tady**; access-manager ji nedrží vůbec (§5).
- ~~Vydávání tokenů, které aplikace dává svým klientům~~ — **zůstává
  volajícímu**; tabulka vydaných tokenů má tutéž vlastnost jako relace
  a restart ve 3 ráno by je zneplatnil všechny.
- ~~Omezování pokusů~~ (`throttled`) — postavené. Běží **až po** kontrole
  původu (§2b): kdyby běželo dřív, zamkne kdokoli z internetu cizí účet
  střelbou z blokované adresy.
- ~~Fragmentovaná konfigurace~~ — postavená. `conf.d/*.json` se při startu
  sečtou, skalární konflikt **zavře start**. Má to důsledek, který musí být
  napsaný, než na něj někdo doplatí: **sjednocením nejde nic odebrat.**
  Neexistuje fragment, který řekne „hanu z účtárny pryč" — musí se změnit
  ten, který ji tam dává.

Otevřené:

1. **Úložiště pro víc replik.** Dnes soubory: čtení se paralelizuje,
   `gen` řekne volajícímu, kdy zahodit cache, a souběžný zápis drží zámek
   nad realmem. Víc replik ukazuje na databázi, protože anti-replay
   spotřebovaných kódů a počítadlo pokusů musí být **sdílené** — v paměti
   procesu by druhá replika spotřebovaný kód přijala znovu a `purpose` by
   ztratil smysl. Do té doby je nasazení **jednoprocesové**.

2. **Druhý mechanismus ověření.** Dnes je jediný, TOTP (§1). Tvar
   `credentials` je mapa právě proto, aby přidání dalšího nebylo změnou
   protokolu — ale žádný další navržený není a `need_factor` proto dnes
   znamená vždycky totéž: chybí `totp`.
