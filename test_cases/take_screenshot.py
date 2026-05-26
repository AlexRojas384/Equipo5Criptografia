import os
import subprocess
import time
import urllib.request
from PIL import Image
from playwright.sync_api import sync_playwright

def wait_for_server(url, timeout=10):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with urllib.request.urlopen(url) as response:
                if response.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.5)
    return False

def main():
    print("Starting Django server on port 8000...")
    # Start the django server
    env = os.environ.copy()
    env["DJANGO_SETTINGS_MODULE"] = "config.settings"
    
    server_process = subprocess.Popen(
        ["venv\\Scripts\\python", "manage.py", "runserver", "8000"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    login_url = "http://127.0.0.1:8000/usuarios/login/"
    
    try:
        print("Waiting for server to become responsive...")
        if not wait_for_server(login_url, timeout=15):
            print("Error: Django server did not start in time.")
            server_process.terminate()
            return
            
        print("Django server is ready. Launching Playwright...")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            
            # Set high-resolution viewport for premium look
            page.set_viewport_size({"width": 1200, "height": 950})
            
            print(f"Navigating to {login_url}...")
            page.goto(login_url)
            
            print("Filling login form...")
            page.fill("#id_username", "admin_prod")
            page.fill("#id_password", "adminprod")
            
            print("Submitting form...")
            page.click("button.btn-login")
            
            # Wait for dashboard navigation
            print("Waiting for navigation to dashboard...")
            page.wait_for_url("**/expediente/dashboard/")
            print(f"Successfully logged in! Current URL: {page.url}")
            
            # Open security and permissions panel
            print("Opening 'Seguridad y Permisos' panel...")
            page.click("#toggle-status")
            
            # Wait for transition/panel expansion (1 second)
            time.sleep(1.0)
            
            # Take screenshot
            png_path = r"test_cases\01_autenticacion\TC-01-01.png"
            webp_path = r"test_cases\01_autenticacion\TC-01-01.webp"
            
            print(f"Saving temporary screenshot to {png_path}...")
            page.screenshot(path=png_path)
            
            print(f"Converting to WebP and saving to {webp_path}...")
            im = Image.open(png_path)
            im.save(webp_path, "WEBP", quality=95)
            
            # Remove temporary PNG
            if os.path.exists(png_path):
                os.remove(png_path)
                
            print("Screenshot successfully captured and converted!")
            browser.close()
            
    finally:
        print("Stopping Django server...")
        server_process.terminate()
        server_process.wait()
        print("Server stopped.")

if __name__ == "__main__":
    main()
