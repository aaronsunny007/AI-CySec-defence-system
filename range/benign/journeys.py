"""Benign user journeys against OWASP Juice Shop, driven through the real UI.

Each journey is an async function (page, ctx) -> None. It raises on failure.
Steps wrapped in `optional(...)` are nice-to-have browsing noise; a failure
there does not fail the journey. Everything else is a step a real user needs
to succeed -- if the WAF breaks it, that is a broken legitimate journey, which
is the headline safety metric.

Selectors follow Juice Shop's own e2e tests (ids / aria-labels), which are the
most stable hooks the app offers.
"""

from __future__ import annotations

import asyncio
import random
import urllib.parse
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from playwright.async_api import Page

import personas as P

STEP_TIMEOUT_MS = 15_000


@dataclass
class Account:
    email: str
    password: str
    name: str


@dataclass
class JourneyContext:
    base: str
    rng: random.Random
    persona: P.Persona
    accounts: list[Account]  # shared pool for this generator run
    think: tuple[float, float]
    steps: list[str] = field(default_factory=list)
    returning: bool | None = None  # returning visitor: banners already dismissed

    async def pause(self) -> None:
        lo, hi = self.think
        extra = self.persona.slow_mo_ms / 1000
        await asyncio.sleep(self.rng.uniform(lo, hi) + extra)

    def step(self, name: str) -> None:
        self.steps.append(name)


async def optional(coro: Awaitable) -> bool:
    try:
        await coro
        return True
    except Exception:
        return False


# --- shared helpers -------------------------------------------------------------

async def rendered(page: Page) -> None:
    """Wait for the Angular app shell. Never wait for 'networkidle': Juice Shop
    keeps a socket.io connection open, so the network is never idle."""
    # 'attached', not 'visible': on phone-sized screens the navbar collapses.
    await page.wait_for_selector("app-navbar", state="attached", timeout=STEP_TIMEOUT_MS)
    await page.wait_for_load_state("load")


async def open_app(page: Page, ctx: JourneyContext, route: str = "/") -> None:
    ctx.step(f"open {route}")
    if ctx.returning is None:
        # Most visitors have been here before: the app remembers dismissed
        # banners in these cookies. New visitors dismiss them by hand.
        ctx.returning = ctx.rng.random() < 0.7
        if ctx.returning:
            await page.context.add_cookies([
                {"name": "welcomebanner_status", "value": "dismiss", "url": ctx.base},
                {"name": "cookieconsent_status", "value": "dismiss", "url": ctx.base}])
    await page.goto(ctx.base + "/#" + route, wait_until="domcontentloaded")
    await rendered(page)
    if not ctx.returning:
        # The welcome dialog can appear seconds after load on slow/mobile
        # clients, so wait for it rather than poll briefly.
        # (Visible text says "Dismiss"; the aria-label is the stable hook.)
        await optional(page.click('button[aria-label="Close Welcome Banner"]', timeout=8000))
        await optional(page.click('a[aria-label="dismiss cookie message"]', timeout=3000))
        ctx.returning = True  # dismissed now; later pages won't show them


async def goto(page: Page, ctx: JourneyContext, route: str) -> None:
    ctx.step(f"goto {route}")
    await page.goto(ctx.base + "/#" + route, wait_until="domcontentloaded")
    await rendered(page)


async def search(page: Page, ctx: JourneyContext, term: str) -> None:
    ctx.step(f"search {term[:30]!r}")
    await goto(page, ctx, "/search?q=" + urllib.parse.quote(term))
    await ctx.pause()


async def login(page: Page, ctx: JourneyContext, acct: Account, typo_first: bool = False) -> None:
    await open_app(page, ctx, "/login")
    if typo_first:
        ctx.step("login with typo")
        await page.fill("#email", acct.email)
        await page.fill("#password", acct.password[:-1] + "x")
        await page.click("#loginButton")
        await page.wait_for_selector(".error", timeout=STEP_TIMEOUT_MS)
        await ctx.pause()
    ctx.step("login")
    await page.fill("#email", acct.email)
    await page.fill("#password", acct.password)
    await page.click("#loginButton")
    await page.wait_for_url("**/#/search**", timeout=STEP_TIMEOUT_MS)


async def logout(page: Page, ctx: JourneyContext) -> None:
    ctx.step("logout")
    if await page.is_visible("#navbarAccount"):
        await page.click("#navbarAccount")
        await page.click("#navbarLogoutButton")
    else:  # phone layout: account actions live in the side menu
        await page.click('button[aria-label="Open Sidenav"]')
        await page.locator("mat-sidenav").get_by_text("Logout").click()


async def need_account(page: Page, ctx: JourneyContext) -> Account:
    if not ctx.accounts:
        await j_register(page, ctx)
    return ctx.rng.choice(ctx.accounts)


# --- journeys -------------------------------------------------------------------

async def j_browse(page: Page, ctx: JourneyContext) -> None:
    """Land on the shop, scroll, open a couple of products."""
    await open_app(page, ctx, "/")
    for _ in range(ctx.rng.randint(1, 3)):
        await page.mouse.wheel(0, ctx.rng.randint(300, 1500))
        await ctx.pause()
    cards = page.locator("mat-card")
    await cards.first.wait_for(timeout=STEP_TIMEOUT_MS)  # products load async
    n = await cards.count()
    for i in ctx.rng.sample(range(n), k=min(2, n)):
        ctx.step(f"open product {i}")
        await cards.nth(i).locator("img").first.click()
        await page.wait_for_selector("mat-dialog-container", timeout=STEP_TIMEOUT_MS)
        await ctx.pause()
        await page.keyboard.press("Escape")
        await ctx.pause()


async def j_search_normal(page: Page, ctx: JourneyContext) -> None:
    await open_app(page, ctx, "/")
    for term in ctx.rng.sample(P.SEARCH_NORMAL, k=ctx.rng.randint(1, 3)):
        await search(page, ctx, term)


async def j_search_weird(page: Page, ctx: JourneyContext) -> None:
    """Searches with apostrophes, SQL-ish words, symbols, unicode, long text.

    Note: Juice Shop's search is deliberately SQL-injectable, so a lone
    apostrophe makes the APP return 500. That is the app's bug, not the
    journey's: we only require the request to get through the defence.
    """
    await open_app(page, ctx, "/")
    for term in ctx.rng.sample(P.SEARCH_WEIRD, k=ctx.rng.randint(1, 3)):
        ctx.step(f"search {term[:30]!r}")
        resp = await page.request.get(
            ctx.base + "/rest/products/search?q=" + urllib.parse.quote(term))
        if resp.status == 403:
            raise RuntimeError(f"search blocked: {term[:40]!r}")
        await goto(page, ctx, "/search?q=" + urllib.parse.quote(term))
        await ctx.pause()


async def j_register(page: Page, ctx: JourneyContext) -> None:
    acct = Account(email=P.email_for(ctx.persona.name, ctx.rng),
                   password=P.password(ctx.rng), name=ctx.persona.name)
    await open_app(page, ctx, "/register")
    ctx.step("register")
    await page.fill("#emailControl", acct.email)
    await page.fill("#passwordControl", acct.password)
    await page.fill("#repeatPasswordControl", acct.password)
    # The floating label overlays the select itself; click the field box, as a
    # person would.
    field_box = page.locator('mat-form-field:has(mat-select[name="securityQuestion"])')
    opts = page.locator("mat-option")
    for attempt in range(3):  # the dropdown sometimes ignores the first click
        await field_box.click()
        if await optional(opts.first.wait_for(timeout=3000)):
            break
    else:
        raise RuntimeError("security question dropdown did not open")
    await opts.nth(ctx.rng.randrange(await opts.count())).click()
    await page.fill("#securityAnswerControl", ctx.rng.choice(
        ["Fluffy", "O'Malley", "München", "the 'Red' one", "42", "東京"]))
    await ctx.pause()
    await page.click("#registerButton")
    await page.wait_for_url("**/#/login**", timeout=STEP_TIMEOUT_MS)
    ctx.accounts.append(acct)


async def j_login_logout(page: Page, ctx: JourneyContext) -> None:
    acct = await need_account(page, ctx)
    # ~1 in 4 real users mistype their password once. A defence that flags a
    # single typo as credential stuffing is broken.
    await login(page, ctx, acct, typo_first=ctx.rng.random() < 0.25)
    await ctx.pause()
    await logout(page, ctx)


async def j_basket(page: Page, ctx: JourneyContext) -> None:
    acct = await need_account(page, ctx)
    await login(page, ctx, acct)
    await search(page, ctx, ctx.rng.choice(P.SEARCH_NORMAL))
    buttons = page.locator('button[aria-label="Add to Basket"]')
    n = await buttons.count()
    if n == 0:
        await goto(page, ctx, "/search")
        n = await buttons.count()
    for i in ctx.rng.sample(range(n), k=min(ctx.rng.randint(1, 3), n)):
        ctx.step(f"add to basket {i}")
        await buttons.nth(i).click()
        await ctx.pause()
    await goto(page, ctx, "/basket")
    await page.wait_for_selector("#checkoutButton", timeout=STEP_TIMEOUT_MS)
    await optional(page.locator("mat-row button").first.click(timeout=3000))  # +/- qty
    await ctx.pause()


async def j_review(page: Page, ctx: JourneyContext) -> None:
    acct = await need_account(page, ctx)
    await login(page, ctx, acct)
    await goto(page, ctx, "/search")
    cards = page.locator("mat-card")
    await cards.first.wait_for(timeout=STEP_TIMEOUT_MS)
    await cards.nth(ctx.rng.randrange(await cards.count())).locator("img").first.click()
    box = page.locator('textarea[aria-label="Text field to review a product"]')
    await box.wait_for(timeout=STEP_TIMEOUT_MS)
    text = ctx.rng.choice(P.REVIEWS)
    ctx.step(f"review {text[:30]!r}")
    await box.fill(text)
    await ctx.pause()
    async with page.expect_response(lambda r: "/reviews" in r.url and r.request.method == "PUT") as rinfo:
        await page.click("#submitButton")
    resp = await rinfo.value
    if resp.status >= 400:
        raise RuntimeError(f"review rejected: HTTP {resp.status}")


async def j_address(page: Page, ctx: JourneyContext) -> None:
    acct = await need_account(page, ctx)
    await login(page, ctx, acct)
    await goto(page, ctx, "/address/create")
    a = ctx.rng.choice(P.ADDRESSES)
    ctx.step(f"address {a['city']}")
    for key in ("country", "name", "mobile", "zip", "address", "city", "state"):
        value = a["street"] if key == "address" else a[key]
        await page.fill(f'input[placeholder*="{key}" i], textarea[placeholder*="{key}" i]',
                        str(value), timeout=STEP_TIMEOUT_MS)
    await ctx.pause()
    async with page.expect_response(lambda r: "/api/Addresss" in r.url and r.request.method == "POST") as rinfo:
        await page.click("#submitButton")
    resp = await rinfo.value
    if resp.status >= 400:
        raise RuntimeError(f"address rejected: HTTP {resp.status}")


async def j_account_pages(page: Page, ctx: JourneyContext) -> None:
    """Logged-in user wandering around: orders, wallet, about, photo wall."""
    acct = await need_account(page, ctx)
    await login(page, ctx, acct)
    for route in ctx.rng.sample(
            ["/order-history", "/wallet", "/about", "/photo-wall",
             "/deluxe-membership", "/privacy-security/privacy-policy", "/saved-payment-methods"],
            k=ctx.rng.randint(2, 4)):
        await goto(page, ctx, route)
        await ctx.pause()


async def j_language(page: Page, ctx: JourneyContext) -> None:
    """Switch UI language the way the app stores it (cookie), then browse."""
    lang = ctx.rng.choice(["de_DE", "ja_JP", "ar_SA", "hi_IN", "pt_BR", "zh_CN", "ga_IE", "en"])
    ctx.step(f"language {lang}")
    await page.context.add_cookies([{"name": "language", "value": lang, "url": ctx.base}])
    await open_app(page, ctx, "/")
    await search(page, ctx, ctx.rng.choice(P.SEARCH_NORMAL + P.SEARCH_WEIRD))


async def j_profile(page: Page, ctx: JourneyContext) -> None:
    """Set a unicode / apostrophe username on the (server-rendered) profile page."""
    acct = await need_account(page, ctx)
    await login(page, ctx, acct)
    ctx.step("profile")
    await page.goto(ctx.base + "/profile", wait_until="domcontentloaded")
    await page.fill("#username", ctx.persona.name, timeout=STEP_TIMEOUT_MS)
    await ctx.pause()
    async with page.expect_response(lambda r: r.url.endswith("/profile") and r.request.method == "POST") as rinfo:
        await page.click("#submit")
    resp = await rinfo.value
    if resp.status == 403:
        raise RuntimeError("profile update blocked")


Journey = Callable[[Page, JourneyContext], Awaitable[None]]

# name -> (function, weight). Weights roughly follow a shop's real mix:
# mostly browsing and searching, fewer account changes.
JOURNEYS: dict[str, tuple[Journey, int]] = {
    "browse": (j_browse, 20),
    "search_normal": (j_search_normal, 18),
    "search_weird": (j_search_weird, 10),
    "register": (j_register, 6),
    "login_logout": (j_login_logout, 8),
    "basket": (j_basket, 12),
    "review": (j_review, 6),
    "address": (j_address, 5),
    "account_pages": (j_account_pages, 7),
    "language": (j_language, 5),
    "profile": (j_profile, 3),
}
