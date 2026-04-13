import asyncio
import sys
import json
from playwright.async_api import async_playwright

async def main():
    if len(sys.argv) < 3:
        print("[error] Usage: browser_harness.py <url> <js_script>")
        sys.exit(1)
        
    url = sys.argv[1]
    js_script = sys.argv[2]
    
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            
            # Navigate
            await page.goto(url, wait_until="networkidle")
            
            # Execute agent's script
            result = await page.evaluate(js_script)
            
            # Return result and DOM state
            html = await page.content()
            
            output = {
                "script_result": result,
                "dom_preview": html[:2000] + ("..." if len(html) > 2000 else "")
            }
            print(json.dumps(output))
            await browser.close()
    except Exception as e:
        print(json.dumps({"error": str(e)}))

if __name__ == "__main__":
    asyncio.run(main())
