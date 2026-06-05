import asyncio
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        print("Browser Started")
        await browser.close()

asyncio.run(main())