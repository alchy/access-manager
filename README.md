# access-manager

Samostatna komponenta, ktera odpovida na dve otazky:

* **kdo jsi** - overeni cloveka proti zasuvnym mechanismum (dnes TOTP),
* **co je napsano** - jake ACL plati pro danou adresu.

Na treti otazku - *"smi to?"* - **neodpovida zamerne**. Ta patri tomu, kdo
sve objekty zna; access-manager je nezna a znat je nema. Duvod je v
[docs/design.md](docs/design.md), par. 5.

Ma vlastni proces a vlastni REST API, protoze ho pouziva **jak jadro, tak
aplikace** - nemuze tedy bydlet uvnitr ani jednoho. Muze bezet v jinem
kontejneru nez oba.

## Pouziti z aplikace

Aplikace, ktera jen prihlasuje lidi, potrebuje tohle a nic vic:

```python
import os
from access_manager import Access

access = Access.remote(
    os.environ["ACCESS_MANAGER_URL"],
    key=os.environ["ACCESS_MANAGER_KEY"],
    component="mojeapka",
)

verdikt = access.authenticate("jindrich", {"totp": kod}, purpose="login")

if verdikt.outcome == "need_factor":
    ...                                   # co chybi, rekla komponenta
if not verdikt:
    ...                                   # ven JEDNA hlaska, do logu duvod

verdikt.subject_id     # "user:jindrich"
verdikt.principals     # {"user:jindrich", "group:users", "group:public"}
```

Dve veci, ktere je treba vedet predem:

1. **Nedostanete relaci, dostanete verdikt.** Access-manager nedrzi
   prihlasene lidi - kdyby ano, jeho restart ve 3 rano odhlasi vsechny.
   Drzet cloveka prihlaseneho je prace volajiciho.
2. **`group:users` a `group:public` jsou vyhrazene.** Znamenaji "kdokoli
   overeny" a "kdokoli"; clovek je dostane tak jako tak a nejdou mu odebrat.

## Instalace

```bash
pip install access-manager          # klient
pip install access-manager[totp]    # + zakladani TOTP identit
```

Klient nema zadne povinne zavislosti. HTTP vrstva a TOTP jsou volitelne
extra, takze apka, ktera jen vola `authenticate`, si netahne nic.

## Stav

Rozpracovane. Hotovy je souborovy backend s overenim a rozbalenim skupin
(35 testu, bezi bez site i bez serveru); klient `Access.remote` a sama
sluzba jeste ne. Navrh REST API je v [docs/design.md](docs/design.md) a
plati jako zavazny - knihovna se pise podle nej, ne naopak.

## Licence

Apache 2.0, viz [LICENSE](LICENSE).
