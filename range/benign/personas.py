"""Personas and weird-but-legitimate inputs for the benign traffic generator.

Everything here is something an honest user could plausibly type. Much of it
is deliberately the kind of text that trips naive WAF rules (SQL words,
apostrophes, angle brackets, percent signs, non-Latin scripts, very long
input). A defence that blocks any of this is breaking real users.

Do NOT add actual attack payloads here. If a string only makes sense as an
attack, it belongs in range/attacks/, not in the benign corpus.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

# --- personas -----------------------------------------------------------------

# Playwright device descriptor names (playwright.devices keys).
DEVICES = [
    None,  # plain desktop Chromium
    None,
    "Desktop Firefox",  # UA only; we always drive Chromium
    "iPhone 13",
    "Pixel 7",
    "iPad Mini",
    "Galaxy S9+",
]

LOCALES = [
    ("en-GB", "Europe/London"),
    ("en-GB", "Europe/London"),
    ("en-US", "America/New_York"),
    ("de-DE", "Europe/Berlin"),
    ("ja-JP", "Asia/Tokyo"),
    ("ar-SA", "Asia/Riyadh"),
    ("hi-IN", "Asia/Kolkata"),
    ("pt-BR", "America/Sao_Paulo"),
    ("zh-CN", "Asia/Shanghai"),
    ("ga-IE", "Europe/Dublin"),
]

NAMES = [
    "Sunny Aaron", "Siobhán O'Neill", "Zoë Müller", "José Ñúñez", "李小龙",
    "Аарон Ганди", "محمد الأحمد", "D'Arcy McAllister", "Ngozi Okonkwo-Smith",
    "Robert'); Tables", "Bobby Tables", "Åsa Ødegård", "Nguyễn Văn An",
    "Jean-Luc Picard", "O'Brien", "Seán Ó Briain", "Ελένη Παπαδοπούλου",
]


@dataclass(frozen=True)
class Persona:
    name: str
    device: str | None
    locale: str
    timezone: str
    slow_mo_ms: int  # >0 = slow client


def random_persona(rng: random.Random) -> Persona:
    locale, tz = rng.choice(LOCALES)
    slow = rng.random() < 0.15
    return Persona(
        name=rng.choice(NAMES),
        device=rng.choice(DEVICES),
        locale=locale,
        timezone=tz,
        slow_mo_ms=rng.randint(150, 600) if slow else 0,
    )


# --- inputs -------------------------------------------------------------------

SEARCH_NORMAL = [
    "apple", "banana", "juice", "lemon", "owasp", "t-shirt", "sticker",
    "melon", "carrot", "eggfruit", "green smoothie", "mug", "hoodie",
]

SEARCH_WEIRD = [
    "O'Brien hummus",
    "Bobby Tables' review",
    "select a gift",
    "drop shipping",
    "union jack mug",
    "1 or 2 apples",
    "rock & roll",
    "50% off",
    "<3 juice",
    "café crème",
    "пицца",
    "寿司",
    "عصير",
    "🍎🍌",
    "apple -banana",
    "\"exact phrase\"",
    "C:\\Users\\me\\wishlist",
    "#1 best seller",
    "size: XL; colour: red",
    "where is my order?",
    "juice " * 60,  # very long query
]

REVIEWS = [
    "Lovely stuff, would buy again.",
    "Best juice ever!!! <3 <3 <3",
    "I <b>really</b> liked it, my kids did too :)",
    "Tastes like 1=1 perfect apples, no complaints.",
    "Arrived late -- but worth it. 5/5",
    "Not bad. Select this one if you like sweet drinks; drop the other one.",
    "My daughter's school report literally said <script> was her favourite word, lol",
    "Price went from £3 to £5 -- 66% increase?! Still good though.",
    "Tried it with 50% water & 50% juice. Fine.",
    "Sehr lecker! Würde ich wieder kaufen. 👍",
    "とても美味しいです。また買います。",
    "رائع جدا، أنصح به",
    "Ok.",
    "Long review incoming. " + "It was genuinely good and I want to explain why in detail. " * 40,
    "Path to happiness: ../../kitchen/fridge/this-juice",
    "Email me at d'arcy.mc+juice@example.com if you want more reviews",
]

ADDRESSES = [
    dict(country="United Kingdom", name="Siobhán O'Neill", mobile="7700900123",
         zip="BT7 1NN", street="Flat 3/2, 10 O'Connell St", city="Belfast", state="Antrim"),
    dict(country="Germany", name="Zoë Müller", mobile="1511234567",
         zip="80331", street="Maximilianstraße 1", city="München", state="Bayern"),
    dict(country="Japan", name="李小龙", mobile="9012345678",
         zip="100-0001", street="千代田1-1", city="東京都", state="Tokyo"),
    dict(country="Brazil", name="José Ñúñez", mobile="1198765432",
         zip="01310100", street="Av. Paulista, 1000 - apto. 12", city="São Paulo", state="SP"),
    dict(country="India", name="Sunny Aaron", mobile="9876543210",
         zip="530045", street="Door No. 12-3/4, Rushikonda", city="Visakhapatnam", state="Andhra Pradesh"),
    dict(country="USA", name="Robert'); Tables", mobile="2025550123",
         zip="20500", street="1600 Pennsylvania Ave NW #1", city="Washington", state="DC"),
]


def email_for(name: str, rng: random.Random) -> str:
    local = "".join(c for c in name.lower() if c.isascii() and (c.isalnum() or c in ".'-")) or "user"
    local = local.strip(".'-")[:20] or "user"
    tag = rng.choice(["", "+shop", f"+{rng.randint(1, 999)}", ".work"])
    return f"{local}{tag}{rng.randint(1000, 99999)}@example.com"


def password(rng: random.Random) -> str:
    # Strong, symbol-heavy passwords: legitimate users have quotes and
    # semicolons in their passwords too.
    alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!#$%&'()*+,-./:;<=>?@[]^_{|}~"
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(12, 24)))
