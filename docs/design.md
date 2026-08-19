# Access-manager: REST API a klientská knihovna

*Návrh před implementací. Access-manager je samostatná komponenta s vlastním
procesem — používá ho **core i apky**, takže nemůže bydlet uvnitř ani
jednoho. Může běžet v jiném kontejneru než oba.*

---

## 1. Co to je a co to není

Access-manager odpovídá na otázky o **identitě** a **politice**. Nerozhoduje
o oknech.

| ptá se ho | na co |
|---|---|
| **core** | je tohle hana? v jakých je skupinách? existuje `group:ucetni`? jaké ACL platí pro `screen:provoz`? |
| **apka** | je tenhle token platný a kdo je jeho držitel? |

| co zůstává ve viewBase | proč |
|---|---|
| `allowed(principals, acl)` | přes drát chodí **data, ne verdikt** — viz §5 |
| relace | jinak každý restart access-manageru odhlásí všechny diváky |
| topologie | které okno ukazuje který obsah, kdo ho založil, jaké nabídky visí kde |

**Hranice jednou větou:** access-manager říká, *kdo jsi* a *co je napsáno*;
viewBase počítá, *co z toho plyne pro tenhle objekt*.

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
`need_second_factor`.

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

200 { "verdict": "ok", "subject_id": "user:hana",
      "principals": ["user:hana", "group:hana", "group:ucetni",
                     "group:zamestnanci", "group:users", "group:public"] }
200 { "verdict": "bad_code" }
200 { "verdict": "need_second_factor", "required": ["totp"] }
```

**Pověření je mapa mechanismus → hodnota**, ne jedno pole — díky tomu jsou
mechanismy zásuvné a dvoufázové přihlášení se vejde do téhož volání:

```json
{ "credentials": { "password": "…" } }
{ "credentials": { "password": "…", "totp": "123456" } }
```

**Co je potřeba, rozhoduje komponenta, ne volající.** Jinak si klient sám
vybere slabší způsob. Proto verdikt `need_second_factor` s tím, co chybí.

Součástí toho rozhodnutí je **původ požadavku** (§2b): tentýž člověk
s týmž heslem projde z vnitřní sítě a zvenčí dostane `need_second_factor`.

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

- **Verdikt, ne `true`/`false`.** Ve viewBase2 se tři různé příčiny hlásily
  stejnou hláškou a stálo to hodinu hledání:

  `ok` · `bad_code` · `bad_password` · `need_second_factor` · `replay` ·
  `throttled` · `no_secret` · `unknown_user` · `disabled` · `expired`

  Volajícímu se posílá tak, aby neprozradil víc, než má; do auditu jde vždy
  celý. `unknown_user` a `disabled` jsou dva různé stavy: zablokovat člověka
  na tři dny je běžný úkon a smazat ho kvůli tomu znamená přijít o jeho
  členství i o auditní stopu.

- Odpověď je **vždy `200`**. Rozlišitelný stavový kód by z HTTP udělal
  postranní kanál (`404` = uživatel neexistuje).

### 3.1b Hesla nesou vlastní pravidla

Heslo není jen další klíč v té mapě. Levnější je to napsat teď než po
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
      "principals": ["user:hana", "group:hana", "group:ucetni",
                     "group:zamestnanci", "group:users", "group:public"] }
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

### 3.4 Politika

```http
GET /v1/policy?address=screen:provoz

200 { "address": "screen:provoz",
      "read": ["group:ucetni"], "write": ["group:ucetni"],
      "require_authentication": false }
200 { "address": "screen:provoz" }        // nic nastaveno; platí deklarace v kódu
```

**Politika ze služby PŘEBÍJÍ kód.** Správce musí umět opravit špatné ACL bez
nasazení nové verze aplikace. Prázdná odpověď znamená „nic nepřebíjím", ne
„nikdo" — to jsou dvě různé věci a jejich splynutí je díra.

```http
GET /v1/policy/bulk?prefix=screen:provoz
```

Hromadná varianta, aby se při startu nedělalo N dotazů.

### 3.5 Tokeny pro apky

```http
POST /v1/tokens
{ "subject_id": "user:hana", "audience": "app:workbench.graph", "ttl": 3600 }
200 { "token": "vbt1_…", "expires_at": 1787153000 }

POST /v1/tokens/introspect
{ "token": "vbt1_…", "audience": "app:workbench.graph" }
200 { "active": true, "subject_id": "user:hana", "expires_at": 1787153000 }
200 { "active": false }

DELETE /v1/tokens/{token}
```

- **`audience` je povinná na obou stranách.** Bez ní je token pro apku X
  klíčem k apce Y, jakmile ho X získá.
- **Introspekce, ne podpis.** Pravdu drží tabulka, takže odvolání je smazání
  řádku a je okamžité. Podepsaný token by přinesl klíč k rotaci, generace
  kvůli odvolávání a hodiny k synchronizaci.
- **Token nenese rukojeť ani skupiny.** Říká *kdo*; *co s tím smí* je otázka
  na viewBase, protože k tomu je potřeba topologie (zakladatel obsahu,
  průnik okno ∩ obsah).

### 3.6 Provoz

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

## 5. Přes drát chodí data, ne verdikt

Access-manager nikdy nedostane otázku *„smí hana číst
`screen:provoz/window:mzdy`?"*. Dostane otázku *„jaké ACL platí pro tu
adresu?"* a odpověď spočítá viewBase.

**Hlavní důvod je jednodušší, než se zdá: komponenta ty objekty nezná.**
Plochy, okna a obsahy vznikají a zanikají za běhu z kódu vývojáře;
aby na ně uměla odpovědět, musela by je všechny mít u sebe — a registrovat
každé otevřené okno do cizí služby není nepohodlí, ale nesmysl. Ten důvod
platí, i kdyby bylo API krásně typované. (Review to odmítalo argumentem, že
řetězcové `authorize(subject, action, resource)` nejde vynutit ani
otestovat — to je pravda, ale je to argument o naší disciplíně, který by šel
obejít lepším typováním. Tenhle obejít nejde.)

K tomu tři provozní důvody:

1. **ACL se dá bezpečně cachovat, „ano/ne" ne.** Odpověď zestárne přesně ve
   chvíli, kdy se práva změní — a pozdní vazba publika je celý smysl modelu.
2. **Vysílací smyčka by měla službu v horké cestě.** Každá doručená zpráva =
   jeden dotaz; při deseti divácích a živém grafu jsou to stovky za vteřinu.
3. **Autorizace se musí dát otestovat bez sítě.** Dnes se celá testuje bez
   serveru a je to tvrdé pravidlo, ne náhoda.

## 6. Klientská knihovna je normativní

Závazná je **knihovna**, ne drát — tvar zpráv je její vnitřek a mění se s
verzí. Je to totéž rozhodnutí jako u appkitu: ten protokol mluví jenom
viewBase se svými komponentami, takže volný drát kupuje jedinou svobodu —
napsat si klienta ručně — a přesně z ní vzejde znovu vymyšlený anti-replay.

```python
from access_manager import AccessManager, Files

# kontejner jinde
authority = AccessManager("http://access:8080", key=os.environ["VB_KEY"])

# jeden stroj, bez služby
authority = Files()          # ~/.viewbase, tedy to, co založí `viewbase.admin adduser`
```

Obě za **jedním rozhraním**:

```python
authority.authenticate(username, code, purpose) -> Verdict
authority.user(username)                        -> User | None
authority.unknown(principals)                   -> list[str]
authority.policy(address)                       -> Policy | None
authority.issue(subject_id, audience, ttl)      -> Token
authority.introspect(token, audience)           -> Subject | None
authority.alive(deadline)                       -> bool
```

Co knihovna dělá, aby to nedělal každý sám:

- **retry s backoffem a deadlinem** — restart repliky se přečká,
- **cache s krátkou platností** u `policy` a `user`, s okamžitou invalidací
  při zápisu; nikdy u `authenticate`,
- **kontrolu verze API** při startu — neslučitelná major verze skončí hlasitě
  hned, ne u prvního dotazu,
- **mapování verdiktů na typy**, ať se `bad_code` nedá splést s `throttled`
  tím, že oba jsou „nepravda",
- **sanaci a redakci** toho, co jde do logu: kód, token ani session id se do
  něj nedostanou.

`access-manager` se balíčkuje **samostatně** — apka ho má umět použít, aniž
by si nainstalovala celý viewBase.

## 7. Otevřené body

1. **Kdo drží politiku** — jen přebíjení nad deklarací v kódu (§3.4), nebo
   celé ACL včetně oken a obsahů? První je menší krok a stačí na to, co dnes
   chybí; druhé znamená, že viewBase službě posílá svůj objektový graf.
2. **Ukládání** — soubor pod jednou autoritou (jako vb2), nebo databáze?
   K8s a víc replik ukazuje na databázi, ale první verze se dá udělat obojí.
3. **Vydávání tokenů** (§3.5) — patří sem, nebo zůstává ve viewBase? Sem
   patří, pokud má apka ověřovat token bez viewBase; jinak je to zbytečný
   přesun.
