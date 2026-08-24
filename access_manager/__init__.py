"""Klientska knihovna access-manageru.

Ven vedou tri dvirka a kazda jsou pro nekoho jineho:

    from access_manager import Access       # aplikace: cte a overuje
    from access_manager import Admin        # spravce: zaklada a meni
    from access_manager import reconcile    # provozovatel: sjednocuje podle deklaraci

Uloziste ani jmena vyhrazenych principalu se neexportuji. `group:users`
a `group:public` uz jsou definovane ve viewBase; dve definice tehoz jmena
na drate by se jednou rozesly a byla by to ticha chyba v pravech, ne pad.
"""
from .access import Access
from .admin import Admin
from .principals import Component, Enrolment, Group, User
from .realms import reconcile
from .verdicts import Verdict

__all__ = [
    "Access",
    "Admin",
    "Component",
    "Enrolment",
    "Group",
    "User",
    "Verdict",
    "reconcile",
]
