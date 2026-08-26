# Access-manager: REST API a klientská knihovna

*Access-manager je samostatná komponenta s vlastním procesem — používá ho
**core i apky**, takže nemůže bydlet uvnitř ani jednoho. Může běžet v jiném
kontejneru než oba.*

*Rozsah: **čistě autentikátor a adresář skupin.** Politiku ani relace nedrží
— proč, je v §5.*

---

## 1. Co to je a co to není

Access-manager odpovídá na otázky o **identitě**. O oknech, právech ani
relacích nerozhoduje.

| ptá se ho | na co |
|---|---|
| **core** | je tohle hana? v jakých je skupinách? existuje `group:ucetni`? |
| **apka** | je tohle jindřich? v jakých je skupinách? |

Apka se ptá na totéž co core, a to je záměr: aplikace, která nemá s viewBase
nic společného, si ho může vzít jako přihlašovací službu a nic dalšího
neřešit.

| co zůstává ve viewBase | proč |
|---|---|
| `allowed(principals, acl)` a všechna ACL | komponenta naše objekty nezná — §5 |
| relace | jinak každý restart access-manageru odhlásí všechny diváky |
| tokeny pro apky | tabulka vydaných tokenů má tutéž vlastnost jako relace: restart ve 3 ráno by je zneplatnil všechny |
| topologie | které okno ukazuje který obsah, kdo ho založil, jaké nabídky visí kde |

**Hranice jednou větou:** access-manager říká *kdo jsi a kam patříš*;
viewBase počítá *co z toho plyne pro tenhle objekt*.

## 2. Kdo se ptá a čím se prokáže

Kanál je **autentizovaný od začátku**, ne „až v provozu" — jinak si
`SubjectContext` pošle kdokoli, kdo na službu dosáhne.

```
Authorization: Bearer <klíč komponenty>
```

Klíč je per komponenta, ne jeden sdílený: únik klíče jedné apky nesmí být
klíčem ke všemu. Konfigurace mapuje klíč na **jméno komponenty** (`core`,
`app:workbench.graph`) a to jméno se s požadavkem nese dál — do auditu
a do ACL na původ (§2b).

**Jaké to jméno je, je access-manageru jedno.** Nerozumí mu a nic z něj
neodvozuje — stejně jako u `purpose`: neprůhledné, ale ne dekorativní.
Potřebuje od něj dvě věci: aby bylo pro každou komponentu jiné a aby se
neměnilo pod rukama. Kdyby dvě apky sdílely jméno, audit přestane odpovídat
na otázku „kdo se ptal" a odvolání jedné z nich vypne obě.

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

```yaml
origins:
  trusted_proxies: ["10.0.0.0/8"]      # nginx / ingress
  forwarded_header: X-Forwarded-For    # co ta proxy posílá
  hops: 1                              # kolik prvků zprava jsou naše proxy
```

`hops` je tam proto, že klient si může poslat vlastní `X-Forwarded-For`
a proxy k němu svůj údaj **připojí zprava**. Brát levý prvek znamená brát
to, co napsal útočník.

### Na co ACL sedí

```yaml
components:
  core:
    key_id: k1
    origins: ["10.42.0.0/16"]          # pod CIDR
  app:workbench.graph:
    key_id: k2
    origins: ["10.42.3.7"]

endpoints:
  "/v1/users/*/credentials":
    origins: ["10.9.0.0/24"]           # zavádění jen ze správcovské sítě

mechanisms:
  password:
    origins: ["10.0.0.0/8"]            # samotné heslo jen zevnitř
```

Tři úrovně, protože oddělují tři různé věci: **kdo** (klíč komponenty platí
jen odsud), **co** (zavádění pověření jen ze správcovské sítě) a **čím**
(holé heslo jen zevnitř). To poslední je ta „chování podle původu u každého
typu ověření" — nezakazuje přihlášení zvenčí, jen zvedá laťku: z neuvedeného
původu se `password` chová, jako by nebyl nabídnut, a odpověď je
`need_factor`.

Adresy jsou CIDR, IPv4 i IPv6 — pod v Kubernetes dostane často v6 a seznam
jednotlivých adres by tam nebyl k ničemu.

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

Cesty jsou verzované (`/v1/`), aby wrapper poznal neslučitelnou verzi hned
při startu, ne až u prvního dotazu.

### 3.1 Ověření člověka

**Ověřuje se pověření, ne oprávnění.** `authenticate` odpovídá „jsi to ty?";
„smíš to?" je otázka na viewBase a nikdy sem nechodí (§5). Ta dvě slova
znamenají různé věci a celý model stojí na tom, že se nesmažou.

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

**Pověření je mapa mechanismus → hodnota**, ne jedno pole — díky tomu jsou
mechanismy zásuvné a dvoufázové přihlášení se vejde do téhož volání:

```json
{ "credentials": { "password": "…" } }
{ "credentials": { "password": "…", "totp": "123456" } }
```

**Co je potřeba, rozhoduje komponenta, ne volající.** Jinak si klient sám
vybere slabší způsob. Proto verdikt `need_factor` s tím, co chybí — nikoli
„second factor": když je TOTP jediný mechanismus, není druhý. Komponenta
říká *co* chybí, ne kolikáté to je.

Součástí toho rozhodnutí je **původ požadavku** (§2b): tentýž člověk s týmž
pověřením může zevnitř projít a zvenčí dostat `need_factor`.

- **`purpose` je povinný** a má tvar `login` nebo `unlock:<cíl>`. Anti-replay
  má účel: týž kód je legitimně potřeba dvakrát během jednoho
  třicetisekundového okna (přihlášení + krok navíc) a autentikátor mezitím
  žádný nový nevydá — společný seznam napříč vším je chyba 3.6. Cíl u
  odemykání je tam ze stejného důvodu o patro níž: kdo si ráno odemkne mzdy
  a hned nato terminál, narazí jinak na tutéž past.

  Komponenta účelu **nerozumí** — je to neprůhledný klíč přihrádky
  s použitými kódy. Nekontroluje, jestli `mzdy` je skutečné okno; o oknech
  neví nic (§1). Ověřuje jen **tvar**, aby se z volného řetězce nedalo
  udělat „pokaždé nový účel" a anti-replay tím vypnout.

  Účel skládá **viewBase**, ne divák: klient ho neposílá, server ho sestaví
  z okna, které se odemyká.

- **Použité kódy se prořezávají** po uplynutí platnosti. Šestimístná hodnota
  se časem vrátí, takže bez prořezávání seznam nejen roste, ale po čase
  začne odmítat legitimní kódy.

- **Verdikt, ne `true`/`false` — ale ten podrobný patří do auditu.** Ve
  viewBase2 se tři různé příčiny hlásily stejnou hláškou a stálo to hodinu
  hledání. Ta hodina se hledala **v logu**, takže tam ten rozdíl musí být:

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

- Odpověď je **vždy `200`**. Rozlišitelný stavový kód by z HTTP udělal
  postranní kanál. Jediná výjimka je `403` za nepovolený původ (§2b), a ta
  padá dřív, než kdokoli přečte jméno.

### 3.1b Hesla — až přijdou

**Dnes je mechanismus jediný: autentikátor v telefonu (TOTP).** Heslo
implementované není a `bad_password` proto ve verdiktech nefiguruje — jméno
pro stav, který nemůže nastat, je slib.

Až heslo přijde, nese vlastní pravidla; levnější je napsat je teď než po
prvním incidentu:

- **hash, nikdy plaintext** — argon2id, parametry v konfiguraci, ne v kódu,
- **ověření trvá stejně dlouho** u neexistujícího uživatele jako
  u existujícího; jinak je odezva postranní kanál na výčet uživatelů,
- **heslo se nikdy nedostane do logu** — redakce podle klíčů platí i uvnitř
  komponenty,
- **změna hesla ukončí relace** — jinak zůstane přihlášený právě ten, komu
  ho měníš kvůli úniku.

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

**Zřetězení skupin rozbaluje komponenta, ne viewBase.** Kdyby viewBase
dostávalo graf a rozbalovalo si ho samo, přestane být celá autorizace jednou
funkcí a přibude druhé místo, kde se počítá příslušnost. Detekce cyklu patří
sem, jednou — ne do každého volajícího.

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

### 3.2c Zavedení a životní cyklus pověření

```http
POST   /v1/users                      { "username": "hana" }
POST   /v1/users/hana/credentials     { "mechanism": "totp" }   -> secret, QR
DELETE /v1/users/hana/credentials/totp
POST   /v1/users/hana/disable
POST   /v1/users/hana/enable
DELETE /v1/users/hana
```

Bez rotace a odvolání nemá **ztracený telefon** řešení.

Má to jeden důsledek pro dnešní kód: `python -m viewbase.admin adduser`
zakládá TOTP tajemství do `~/.viewbase`. Jakmile identity vlastní tahle
komponenta, **stěhuje se sem** — jinak jsou evidence dvě a rozejdou se.

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
zkouší znovu s krátkým backoffem. A `Instance()` nesmí při startu selhat
okamžitě — viewBase a access-manager se nasazují spolu, takže by z toho byla
crash-loop. Ověření má **deadline**, ne nulovou trpělivost.

**Restart nikoho neodhlásí,** protože relace vlastní viewBase. To není
náhoda, to je pravidlo.

## 5. Politika sem nepatří

Access-manager nikdy nedostane otázku *„smí hana číst
`screen:provoz/window:mzdy`?"* — a nedostane ani otázku *„jaké ACL platí pro
tu adresu?"*. **Politiku nedrží vůbec.** Je to čistě autentikátor a adresář
skupin: odpoví, kdo jsi a kam patříš. Co z toho plyne pro konkrétní okno,
počítá viewBase, protože je jediný, kdo ta okna zná.

**Hlavní důvod: komponenta ty objekty nezná.** Plochy, okna a obsahy vznikají
a zanikají za běhu z kódu vývojáře; aby na ně uměla odpovědět, musela by je
mít u sebe všechny — a registrovat každé otevřené okno do cizí služby není
nepohodlí, ale nesmysl. Ten důvod platí, i kdyby bylo API krásně typované.
(Review to odmítalo argumentem, že řetězcové `authorize(subject, action,
resource)` nejde vynutit ani otestovat — pravda, ale je to argument o naší
disciplíně, který by šel obejít lepším typováním. Tenhle obejít nejde.)

K tomu tři provozní důvody, které míří ke stejnému závěru:

1. **Vysílací smyčka by měla službu v horké cestě.** Práva se čtou až
   v okamžiku doručení — to je pozdní vazba a celý smysl modelu. Přes síť by
   to znamenalo jeden dotaz na každou doručenou zprávu; při deseti divácích
   a živém grafu stovky za vteřinu.
2. **Cache ten problém neřeší, jen posune.** Odpověď zestárne přesně ve
   chvíli, kdy se práva změní — tedy v jediném okamžiku, na kterém záleží.
3. **Autorizace se musí dát otestovat bez sítě.** Dnes se celá testuje bez
   serveru; je to tvrdé pravidlo, ne náhoda.

Plyne z toho jedna věc dovnitř viewBase: **ACL zůstávají v manifestu**, který
je jediný zdroj pravdy (D-53). Přebíjení politiky ze služby by z něj udělalo
zdroj druhý, a dva zdroje pravdy o právech jsou horší stav než jeden
nepohodlný.

## 6. Klientská knihovna je normativní

Závazná je **knihovna**, ne drát — tvar zpráv je její vnitřek a mění se
s verzí. Je to totéž rozhodnutí jako u appkitu: ten protokol mluví jenom
viewBase se svými komponentami, takže volný drát kupuje jedinou svobodu —
napsat si klienta ručně — a přesně z ní vzejde znovu vymyšlený anti-replay.

```python
from access_manager import Access, Admin

# kontejner jinde
access = Access.remote(os.environ["ACCESS_MANAGER_URL"],
                       key=os.environ["ACCESS_MANAGER_KEY"],
                       component="core")

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
extra, takže apka, která jen volá `authenticate`, si nenainstaluje nic —
a viewBase kvůli ní nemusí měnit svoje.

## 7. Otevřené body

Rozhodnuté a tím uzavřené:

- ~~Kdo drží politiku~~ — **nikdo tady**; komponenta politiku nedrží vůbec (§5).
- ~~Vydávání tokenů~~ — **zůstává ve viewBase**; tabulka vydaných tokenů má
  tutéž vlastnost jako relace a restart ve 3 ráno by je zneplatnil všechny.

Otevřené:

1. **Ukládání** — zatím soubor: čtení se paralelizuje, expiraci si hlídá
   každý komponent sám a `gen` mu řekne, kdy zahodit cache. Víc replik
   v Kubernetes ukazuje na databázi, protože anti-replay a počítadlo pokusů
   musí být sdílené — v paměti procesu by druhá replika spotřebovaný kód
   přijala znovu.
2. **Fragmentovaná konfigurace** — uživatelé, skupiny i klienti jako
   jednotlivé soubory, které se při startu sečtou. Množiny se sjednocují,
   skaláry v konfliktu **zavřou start**. Má to jeden důsledek, který musí být
   napsaný, než na něj někdo doplatí: **sjednocením nejde nic odebrat.**
   Neexistuje soubor, který řekne „hanu z účtárny pryč" — musí se změnit ten,
   který ji tam dává. Zatím neimplementováno.
3. **Omezování pokusů** (`throttled`) — navržené, neimplementované. Musí
   běžet **až po** kontrole původu, jinak kdokoli z internetu zamkne cizí účet
   střelbou z blokované adresy.
