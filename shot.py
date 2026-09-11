import asyncio, sys, json
from playwright.async_api import async_playwright

BASE = "http://localhost:8501"
PAGES = [
    ("overview_empty", "/#/overview"),
    ("analyze", "/#/analyze"),
    ("incidents", "/#/incidents"),
    ("risk_profiles", "/#/profiles"),
    ("threat_intel", "/#/intel"),
    ("reports", "/#/reports"),
    ("settings", "/#/settings"),
]

async def main():
    errors = {}
    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        page = await browser.new_page(viewport={"width": 1440, "height": 900})
        collected = []
        page.on("console", lambda m: collected.append(f"[{m.type}] {m.text[:200]}") if m.type in ("error", "warning") else None)
        page.on("response", lambda r: collected.append(f"[http{r.status}] {r.url}") if r.status >= 400 else None)
        for name, path in PAGES:
            collected.clear()
            try:
                await page.goto(BASE + path, wait_until="networkidle", timeout=30000)
            except Exception as e:
                collected.append(f"[nav-timeout] {str(e)[:120]}")
            await page.wait_for_timeout(2500)
            body_text = await page.evaluate("() => document.body.innerText.length")
            st_errs = await page.evaluate("() => Array.from(document.querySelectorAll('.stException, [data-baseweb=\"toast\"], #toast.show')).map(e => e.innerText)")
            for t in st_errs:
                collected.append(f"[page-error] {t[:300]}")
            # uncaught JS errors land in console
            await page.screenshot(path=f"shots/{name}.png", full_page=False)
            visible_text = await page.evaluate("() => document.body.innerText.slice(0, 600)")
            errors[name] = {"len": body_text, "issues": collected, "preview": visible_text}
            print(f"=== {name} (body {body_text} chars) ===")
            for c in collected:
                print("  ", c)
        await browser.close()
    with open("shots/report.json", "w", encoding="utf-8") as f:
        json.dump(errors, f, indent=2, ensure_ascii=False)

asyncio.run(main())
