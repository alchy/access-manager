# Připojení aplikace

*Jak aplikace ověřuje lidi a čte adresář skupin — lokálně i přes službu.*

## Dvě zapojení, jedno API

```python
from access_manager import Access

# Jeden stroj, bez sluzby (vyvoj, jednostrojove nasazeni):
access = Access.local("~/.access-manager", realm="example.com")

# Pres sluzbu (kontejner jinde):
access = Access.remote("https://auth.example.com",
                       key=os.environ["ACCESS_MANAGER_KEY"],
                       realm="example.com")   # tvrzeni; nesoulad = pad hned
```

Obě zapojení vracejí tytéž typy a chovají se stejně — kód aplikace se při
přechodu z vývoje na službu mění jen v tomto jednom řádku. `realm` je vždy
povinný u lokálního zapojení; u vzdáleného je volitelné **tvrzení** — klíč
realm určuje sám a nesoulad s tvrzením je hlasitá chyba při startu, ne tiché
ptaní se jinam.

`Access.remote` navíc: vyžaduje `https://` (výjimkou jen loopback pro vývoj;
vlastní CA přes `ca="/cesta/ca.pem"` — ověření certifikátu nemá vypínač),
při startu zkontroluje verzi API a `whoami`, síťové výpadky přečkává retry
s backoffem a krátce cachuje odpovědi `user()` s invalidací podle generace.

## Přihlášení („jsi to ty?“)

```python
verdikt = access.authenticate("hana", {"totp": kod}, purpose="login")

if verdikt.outcome == "need_factor":
    ...                        # co chybi, rika verdikt.required (["totp"])
if verdikt.outcome == "throttled":
    ...                        # zkuste to za verdikt.retry_after sekund
if not verdikt:                # pravdivy je JEN outcome "ok"
    ...                        # ven JEDNA hlaska; duvod patri do auditu

verdikt.subject_id             # "user:hana"
verdikt.principals             # frozenset: {"user:hana", "group:ucetni",
                               #  "group:users", "group:public", ...}
verdikt.gen                    # cislo generace pro invalidaci cache
```

Čtyři veřejné tvary: `ok`, `denied`, `need_factor`, `throttled` — nic pátého.
Podrobný důvod odmítnutí (`verdikt.reason`: `bad_code`, `replay`,
`unknown_user`…) vidí lokální zapojení vždy a vzdálené jen tehdy, když má
komponenta v registraci `detail: true`; jinak je `None` — kdo umí rozlišit
`unknown_user` od `bad_code`, umí si vypsat uživatele.

**Účel (`purpose`) je povinný** a má tvar `login` nebo `unlock:<cíl>` —
anti-replay je per účel, takže týž kód legitimně poslouží přihlášení
i navazujícímu odemčení v témže třicetisekundovém okně, ale nikdy dvakrát
témuž účelu.

Dvě věci, které je třeba vědět předem:

1. **Nedostanete relaci, dostanete verdikt.** Držet člověka přihlášeného je
   práce volající aplikace — restart access-manageru pak nikoho neodhlásí.
2. **`group:users` a `group:public` jsou vyhrazené** — „kdokoli ověřený“
   a „kdokoli“; člověk je má vždy a nejdou mu odebrat.

## Adresář („kam patříš?“)

```python
user = access.user("hana")         # User | None
user.enabled                       # False = docasne vypnuty
user.principals                    # PLOCHY tranzitivni uzaver — zadne
                                   # rozbalovani skupin na strane aplikace
user.is_in("group:ucetni")         # dotaz nad uzaverem, ne dalsi kolo po siti

access.users()                     # ["hana", "petr", ...]
access.groups()                    # ["mzdy", "ucetni", ...]
access.group("ucetni")             # Group(members=..., includes=...) | None
```

Zřetězení skupin rozbaluje komponenta: `ucetni` obsahuje `mzdy`, takže kdo je
ve mzdách, má v uzávěru obojí. Autorizace v aplikaci je pak jediný průnik
množin — `bool(user.principals & acl)`.

Identifikátorem uživatele může být i e-mail (`jindrich.nemec@yahoo.com`);
všechna jména se normalizují na malá písmena.

## Provozní drobnosti

```python
access.generation()        # nezmenene cislo = drzena odpoved plati dal
access.ready()             # None = uloziste pripravene; jinak duvod
access.unknown_principals(["group:ucetni", "user:hana"])
                           # ktere z deklarovanych principalu neexistuji —
                           # kontrola pri startu instance, at "prazdna
                           # obrazovka" nevznikne tichym preklepem
```

## Celý přihlašovací tok (příklad)

```python
import os
from access_manager import Access

access = Access.remote(os.environ["ACCESS_MANAGER_URL"],
                       key=os.environ["ACCESS_MANAGER_KEY"],
                       realm="example.com")

def prihlas(jmeno: str, kod: str) -> dict | None:
    verdikt = access.authenticate(jmeno, {"totp": kod}, purpose="login")
    if not verdikt:
        return None                       # jedna hlaska ven, duvod v auditu
    session = vytvor_relaci(verdikt.subject_id)      # relace je VASE prace
    session["principals"] = verdikt.principals
    session["gen"] = verdikt.gen
    return session

def obnov_relaci(session) -> bool:
    if access.generation() != session["gen"]:        # neco se zmenilo
        user = access.user(session["subject_id"].removeprefix("user:"))
        if user is None or not user.enabled:
            return False                             # smazan / vypnut → ven
        session["principals"] = user.principals
        session["gen"] = access.generation()
    return True
```

Klíč aplikaci vydává správce realmu (viz [admin.md](admin.md)); patří do
prostředí či secret storu, nikdy do gitu — `.gitignore` repozitáře vzory
`*.key` už zná.
