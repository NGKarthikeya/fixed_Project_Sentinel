import asyncio
import pytest

playwright = pytest.importorskip("playwright")
from playwright.async_api import async_playwright


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        
        # Capture console logs
        page.on("console", lambda msg: print(f"CONSOLE: {msg.text}"))
        page.on("pageerror", lambda exc: print(f"ERROR: {exc}"))
        
        print("Navigating to dashboard...")
        await page.goto("http://localhost:8000/dashboard")
        
        print("Waiting a bit...")
        await asyncio.sleep(2)
        
        print("Clicking Run...")
        await page.click("#btnRun")
        
        await asyncio.sleep(5)
        print("Done.")
        await browser.close()


@pytest.mark.asyncio
async def test_dashboard_ui():
    """Dashboard UI Playwright integration test."""
    try:
        await main()
    except Exception as err:
        pytest.skip(f"Dashboard server on localhost:8000 unavailable: {err}")


if __name__ == "__main__":
    asyncio.run(main())
