"""Klientska knihovna access-manageru.

Ven vedou dve dvirka a kazda jsou pro nekoho jineho:

    from access_manager import Access    # aplikace: cte a overuje
    from access_manager import Admin     # spravce: zaklada a meni

Uloziste ani jmena vyhrazenych principalu se neexportuji. `group:users`
a `group:public` uz jsou definovane ve viewBase; dve definice tehoz jmena
na drate by se jednou rozesly a byla by to ticha chyba v pravech, ne pad.
"""
from .access import Access
from .admin import Admin
from .principals import Enrolment, Group, User
from .verdicts import Verdict

__all__ = ["Access", "Admin", "Enrolment", "Group", "User", "Verdict"]
