"""
Red Iris Info Gather - Web Screenshot Node

Captures screenshots of discovered web servers using Selenium.
Uses headless Chrome with webdriver-manager for automatic driver management.
"""
import os
import time
import hashlib
from typing import List
from pathlib import Path
from urllib.parse import urlparse

from state import ScanState, ScreenshotResult
import config


def get_driver():
    """Get headless Chrome driver"""
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.chrome.options import Options
    from webdriver_manager.chrome import ChromeDriverManager
    
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--disable-gpu')
    options.add_argument('--window-size=1920,1080')
    options.add_argument('--ignore-certificate-errors')
    options.add_argument('--ignore-ssl-errors')
    options.add_argument('--disable-web-security')
    options.add_argument('--allow-insecure-localhost')
    
    # Suppress logging
    options.add_argument('--log-level=3')
    options.add_experimental_option('excludeSwitches', ['enable-logging'])
    
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)
    driver.set_page_load_timeout(30)
    
    return driver


def capture_screenshot(url: str, output_dir: Path) -> ScreenshotResult:
    """Capture screenshot of a single URL"""
    # Generate filename from URL hash
    url_hash = hashlib.md5(url.encode()).hexdigest()[:12]
    parsed = urlparse(url)
    safe_host = parsed.netloc.replace(':', '_')
    filename = f"{safe_host}_{url_hash}.png"
    filepath = output_dir / filename
    
    driver = None
    try:
        driver = get_driver()
        driver.get(url)
        
        # Wait for page to load
        time.sleep(3)
        
        # Try to wait for body to be present
        try:
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
        except:
            pass
        
        # Capture screenshot
        driver.save_screenshot(str(filepath))
        
        return ScreenshotResult(
            url=url,
            path=str(filepath),
            success=True,
            error=None
        )
        
    except Exception as e:
        return ScreenshotResult(
            url=url,
            path='',
            success=False,
            error=str(e)
        )
    finally:
        if driver:
            try:
                driver.quit()
            except:
                pass


def run(state: ScanState) -> dict:
    """
    Web Screenshot Node - Entry point
    
    Captures screenshots of all discovered web servers.
    """
    web_servers = state.get('web_servers', [])
    
    logs = []
    errors = []
    screenshots: List[ScreenshotResult] = []
    
    logs.append(f"[WebScreenshot] Capturing screenshots for {len(web_servers)} web servers")
    
    if not web_servers:
        logs.append("[WebScreenshot] No web servers to screenshot")
        return {
            'screenshots': [],
            'errors': errors,
            'logs': logs
        }
    
    # Ensure output directory exists
    output_dir = config.SCREENSHOTS_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Capture screenshots sequentially (browser resources are heavy)
    success_count = 0
    for i, url in enumerate(web_servers):
        logs.append(f"[WebScreenshot] ({i+1}/{len(web_servers)}) Capturing: {url}")
        result = capture_screenshot(url, output_dir)
        screenshots.append(result)
        
        if result['success']:
            success_count += 1
            logs.append(f"[WebScreenshot] Success: {result['path']}")
        else:
            errors.append(f"[WebScreenshot] Failed {url}: {result['error']}")
    
    logs.append(f"[WebScreenshot] Captured {success_count}/{len(web_servers)} screenshots")
    
    return {
        'screenshots': screenshots,
        'errors': errors,
        'logs': logs
    }
