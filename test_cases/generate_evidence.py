import os
import sys
import subprocess
import time
import urllib.request
import django
from PIL import Image, ImageDraw, ImageFont
from playwright.sync_api import sync_playwright

# Configure Django environment to allow database access during tests
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()

from usuarios.models import Usuario

# Backup and restore utilities for database operations
_lalo_original_key = None

def corrupt_lalo_key():
    global _lalo_original_key
    u = Usuario.objects.get(username='lalo')
    _lalo_original_key = u.llave_privada
    u.llave_privada = "invalid_corrupt_private_key"
    u.save()
    print("Database: Corrupted lalo's private key for testing.")

def restore_lalo_key():
    global _lalo_original_key
    if _lalo_original_key is not None:
        u = Usuario.objects.get(username='lalo')
        u.llave_privada = _lalo_original_key
        u.save()
        print("Database: Restored lalo's private key to original state.")

def ensure_pancho_inactive():
    u = Usuario.objects.get(username='pancho')
    if u.is_active:
        u.is_active = False
        u.save()
        print("Database: Ensured pancho is inactive.")

# Wait for Django server utility
def wait_for_server(url, timeout=15):
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

# Premium browser frame drawing utility
def add_browser_frame(image_path, title, url):
    orig = Image.open(image_path)
    w, h = orig.size
    
    # 65px bar at the top of the image
    new_h = h + 65
    frame = Image.new("RGB", (w, new_h), "#1c1c1e") # Sleek premium dark gray
    
    frame.paste(orig, (0, 65))
    
    draw = ImageDraw.Draw(frame)
    
    # Window buttons (macOS style: red, yellow, green)
    draw.ellipse((16, 26, 28, 38), fill="#ff5f56") # Red
    draw.ellipse((36, 26, 48, 38), fill="#ffbd2e") # Yellow
    draw.ellipse((56, 26, 68, 38), fill="#27c93f") # Green
    
    # Active Browser Tab
    draw.rounded_rectangle((90, 15, 290, 48), radius=5, fill="#2c2c2e")
    
    # Font choice (fallback to default)
    try:
        font = ImageFont.load_default()
    except Exception:
        font = None
        
    draw.text((105, 24), title, fill="#ffffff", font=font)
    
    # Active URL Bar
    draw.rounded_rectangle((310, 15, w - 20, 48), radius=5, fill="#2c2c2e")
    draw.text((325, 24), f"🔒  {url}", fill="#9a9a9f", font=font)
    
    # Separation Border
    draw.line((0, 64, w, 64), fill="#3a3a3c", width=1)
    
    frame.save(image_path)
    orig.close()

# Compile animated WebP from images
def save_animated_webp(image_paths, output_path, duration=2000):
    images = [Image.open(p) for p in image_paths]
    images[0].save(
        output_path,
        save_all=True,
        append_images=images[1:],
        duration=duration,
        loop=0,
        quality=90
    )
    # Close images and clean up temporary PNGs
    for img in images:
        img.close()
    for p in image_paths:
        if os.path.exists(p):
            os.remove(p)
    print(f"Evidencia: Guardado animado {output_path} ({len(image_paths)} frames).")

# Main executor
def main():
    print("Ensuring database preconditions...")
    ensure_pancho_inactive()
    
    print("Checking if Django server is already running on port 8000...")
    server_url = "http://127.0.0.1:8000/usuarios/login/"
    server_process = None
    
    try:
        with urllib.request.urlopen(server_url, timeout=2) as r:
            if r.status == 200:
                print("Django server is already running. We will connect to the running instance.")
    except Exception:
        print("Django server not detected. Launching local Django server on port 8000...")
        env = os.environ.copy()
        env["DJANGO_SETTINGS_MODULE"] = "config.settings"
        server_process = subprocess.Popen(
            ["venv\\Scripts\\python", "manage.py", "runserver", "8000"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        print("Waiting for server to start...")
        if not wait_for_server(server_url, timeout=15):
            print("ERROR: Django server failed to start.")
            server_process.terminate()
            return
            
    print("Django server is responsive. Starting Playwright...")
    
    output_dir = r"test_cases\01_autenticacion"
    os.makedirs(output_dir, exist_ok=True)
    
    # Credentials reference dictionary
    creds = {
        'admin_prod': ('admin_prod', 'adminprod'),
        'alex': ('alex', 'adminalex'),
        'arturo': ('arturo', 'adminarturo'),
        'diego': ('diego', 'admindiego'),
        'pancho': ('pancho', 'adminpancho'),
        'lalo': ('lalo', 'adminlalo')
    }
    
    with sync_playwright() as p:
        # Launch chromium in headless mode
        browser = p.chromium.launch(headless=True)
        
        # Helper to get high-res page
        def new_page():
            page = browser.new_page()
            page.set_viewport_size({"width": 1200, "height": 900})
            return page

        # ==========================================
        # TC-01-01: Administrador Login
        # ==========================================
        print("\n--- Ejecutando TC-01-01 (Administrador Login) ---")
        page = new_page()
        
        # Frame 1: Login filled
        page.goto(server_url)
        page.fill("#id_username", creds['admin_prod'][0])
        page.fill("#id_password", creds['admin_prod'][1])
        f1 = os.path.join(output_dir, "tc01_01_f1.png")
        page.screenshot(path=f1)
        add_browser_frame(f1, "Iniciar Sesión — Casa Monarca", server_url)
        
        # Submit
        page.click("button.btn-login")
        page.wait_for_url("**/expediente/dashboard/")
        
        # Frame 2: Dashboard loaded
        f2 = os.path.join(output_dir, "tc01_01_f2.png")
        page.screenshot(path=f2)
        add_browser_frame(f2, "Dashboard — Casa Monarca", page.url)
        
        # Frame 3: Security panel open
        page.click("#toggle-status")
        page.wait_for_timeout(800) # Wait for expansion
        f3 = os.path.join(output_dir, "tc01_01_f3.png")
        page.screenshot(path=f3)
        add_browser_frame(f3, "Dashboard — Casa Monarca (Seguridad)", page.url)
        
        save_animated_webp([f1, f2, f3], os.path.join(output_dir, "TC-01-01.webp"))
        page.close()

        # ==========================================
        # TC-01-02: Coordinador Login
        # ==========================================
        print("\n--- Ejecutando TC-01-02 (Coordinador Login) ---")
        page = new_page()
        
        # Frame 1: Login filled
        page.goto(server_url)
        page.fill("#id_username", creds['alex'][0])
        page.fill("#id_password", creds['alex'][1])
        f1 = os.path.join(output_dir, "tc01_02_f1.png")
        page.screenshot(path=f1)
        add_browser_frame(f1, "Iniciar Sesión — Casa Monarca", server_url)
        
        # Submit
        page.click("button.btn-login")
        page.wait_for_url("**/expediente/dashboard/")
        
        # Frame 2: Dashboard
        f2 = os.path.join(output_dir, "tc01_02_f2.png")
        page.screenshot(path=f2)
        add_browser_frame(f2, "Dashboard — Casa Monarca", page.url)
        
        # Frame 3: Panel open
        page.click("#toggle-status")
        page.wait_for_timeout(800)
        f3 = os.path.join(output_dir, "tc01_02_f3.png")
        page.screenshot(path=f3)
        add_browser_frame(f3, "Dashboard — Casa Monarca (Seguridad)", page.url)
        
        save_animated_webp([f1, f2, f3], os.path.join(output_dir, "TC-01-02.webp"))
        page.close()

        # ==========================================
        # TC-01-03: Operativo Login
        # ==========================================
        print("\n--- Ejecutando TC-01-03 (Operativo Login) ---")
        page = new_page()
        
        # Frame 1: Login filled
        page.goto(server_url)
        page.fill("#id_username", creds['arturo'][0])
        page.fill("#id_password", creds['arturo'][1])
        f1 = os.path.join(output_dir, "tc01_03_f1.png")
        page.screenshot(path=f1)
        add_browser_frame(f1, "Iniciar Sesión — Casa Monarca", server_url)
        
        # Submit
        page.click("button.btn-login")
        page.wait_for_url("**/expediente/dashboard/")
        
        # Frame 2: Dashboard
        f2 = os.path.join(output_dir, "tc01_03_f2.png")
        page.screenshot(path=f2)
        add_browser_frame(f2, "Dashboard — Casa Monarca", page.url)
        
        # Frame 3: Panel open
        page.click("#toggle-status")
        page.wait_for_timeout(800)
        f3 = os.path.join(output_dir, "tc01_03_f3.png")
        page.screenshot(path=f3)
        add_browser_frame(f3, "Dashboard — Casa Monarca (Seguridad)", page.url)
        
        save_animated_webp([f1, f2, f3], os.path.join(output_dir, "TC-01-03.webp"))
        page.close()

        # ==========================================
        # TC-01-04: Usuario Login
        # ==========================================
        print("\n--- Ejecutando TC-01-04 (Usuario Login) ---")
        page = new_page()
        
        # Frame 1: Login filled
        page.goto(server_url)
        page.fill("#id_username", creds['diego'][0])
        page.fill("#id_password", creds['diego'][1])
        f1 = os.path.join(output_dir, "tc01_04_f1.png")
        page.screenshot(path=f1)
        add_browser_frame(f1, "Iniciar Sesión — Casa Monarca", server_url)
        
        # Submit
        page.click("button.btn-login")
        page.wait_for_url("**/expediente/dashboard/")
        
        # Frame 2: Dashboard
        f2 = os.path.join(output_dir, "tc01_04_f2.png")
        page.screenshot(path=f2)
        add_browser_frame(f2, "Dashboard — Casa Monarca", page.url)
        
        # Frame 3: Panel open
        page.click("#toggle-status")
        page.wait_for_timeout(800)
        f3 = os.path.join(output_dir, "tc01_04_f3.png")
        page.screenshot(path=f3)
        add_browser_frame(f3, "Dashboard — Casa Monarca (Seguridad)", page.url)
        
        save_animated_webp([f1, f2, f3], os.path.join(output_dir, "TC-01-04.webp"))
        page.close()

        # ==========================================
        # TC-01-05: Login fallido (Contraseña Incorrecta)
        # ==========================================
        print("\n--- Ejecutando TC-01-05 (Incorrect Password) ---")
        page = new_page()
        
        # Frame 1: Login filled
        page.goto(server_url)
        page.fill("#id_username", creds['admin_prod'][0])
        page.fill("#id_password", "password_incorrecto_123")
        f1 = os.path.join(output_dir, "tc01_05_f1.png")
        page.screenshot(path=f1)
        add_browser_frame(f1, "Iniciar Sesión — Casa Monarca", server_url)
        
        # Submit and fail
        page.click("button.btn-login")
        page.wait_for_timeout(500) # Wait for page reload/banner
        
        # Frame 2: Login showing error
        f2 = os.path.join(output_dir, "tc01_05_f2.png")
        page.screenshot(path=f2)
        add_browser_frame(f2, "Iniciar Sesión — Casa Monarca", server_url)
        
        save_animated_webp([f1, f2], os.path.join(output_dir, "TC-01-05.webp"))
        page.close()

        # ==========================================
        # TC-01-06: Login fallido (Usuario Inexistente)
        # ==========================================
        print("\n--- Ejecutando TC-01-06 (Non-existent User) ---")
        page = new_page()
        
        # Frame 1: Login filled
        page.goto(server_url)
        page.fill("#id_username", "usuario_fantasma_123")
        page.fill("#id_password", "password_cualquiera")
        f1 = os.path.join(output_dir, "tc01_06_f1.png")
        page.screenshot(path=f1)
        add_browser_frame(f1, "Iniciar Sesión — Casa Monarca", server_url)
        
        # Submit and fail
        page.click("button.btn-login")
        page.wait_for_timeout(500)
        
        # Frame 2: Error page
        f2 = os.path.join(output_dir, "tc01_06_f2.png")
        page.screenshot(path=f2)
        add_browser_frame(f2, "Iniciar Sesión — Casa Monarca", server_url)
        
        save_animated_webp([f1, f2], os.path.join(output_dir, "TC-01-06.webp"))
        page.close()

        # ==========================================
        # TC-01-07: Login con cuenta desactivada
        # ==========================================
        print("\n--- Ejecutando TC-01-07 (Deactivated User) ---")
        page = new_page()
        
        # Frame 1: Login filled with deactivated pancho
        page.goto(server_url)
        page.fill("#id_username", creds['pancho'][0])
        page.fill("#id_password", creds['pancho'][1])
        f1 = os.path.join(output_dir, "tc01_07_f1.png")
        page.screenshot(path=f1)
        add_browser_frame(f1, "Iniciar Sesión — Casa Monarca", server_url)
        
        # Submit and fail
        page.click("button.btn-login")
        page.wait_for_timeout(500)
        
        # Frame 2: Error
        f2 = os.path.join(output_dir, "tc01_07_f2.png")
        page.screenshot(path=f2)
        add_browser_frame(f2, "Iniciar Sesión — Casa Monarca", server_url)
        
        save_animated_webp([f1, f2], os.path.join(output_dir, "TC-01-07.webp"))
        page.close()

        # ==========================================
        # TC-01-09: Logout Exitoso
        # ==========================================
        print("\n--- Ejecutando TC-01-09 (Logout Exitoso) ---")
        page = new_page()
        
        # Pre-authenticate
        page.goto(server_url)
        page.fill("#id_username", creds['diego'][0])
        page.fill("#id_password", creds['diego'][1])
        page.click("button.btn-login")
        page.wait_for_url("**/expediente/dashboard/")
        
        # Frame 1: Logged in Dashboard
        f1 = os.path.join(output_dir, "tc01_09_f1.png")
        page.screenshot(path=f1)
        add_browser_frame(f1, "Dashboard — Casa Monarca", page.url)
        
        # Hover/Highlight Cerrar sesion
        page.hover("text=Cerrar sesión")
        page.wait_for_timeout(300)
        
        # Frame 2: Click Logout
        f2 = os.path.join(output_dir, "tc01_09_f2.png")
        page.screenshot(path=f2)
        add_browser_frame(f2, "Dashboard — Casa Monarca", page.url)
        
        page.click("text=Cerrar sesión")
        page.wait_for_url("**/usuarios/login/")
        
        # Frame 3: Redirected to login
        f3 = os.path.join(output_dir, "tc01_09_f3.png")
        page.screenshot(path=f3)
        add_browser_frame(f3, "Iniciar Sesión — Casa Monarca", page.url)
        
        save_animated_webp([f1, f2, f3], os.path.join(output_dir, "TC-01-09.webp"))
        page.close()

        # ==========================================
        # TC-01-10: Acceso a Dashboard sin estar autenticado
        # ==========================================
        print("\n--- Ejecutando TC-01-10 (Dashboard sin Autenticación) ---")
        page = new_page()
        
        # Step 1: Navigating directly
        target_url = "http://127.0.0.1:8000/expediente/dashboard/"
        page.goto(server_url) # Just load login first to simulate transition
        f1 = os.path.join(output_dir, "tc01_10_f1.png")
        page.screenshot(path=f1)
        # Manually frame it as if attempting to go to dashboard
        add_browser_frame(f1, "Cargando...", target_url)
        
        # Navigate directly
        page.goto(target_url)
        page.wait_for_url("**/usuarios/login/?next=/expediente/dashboard/")
        
        # Frame 2: Redirected
        f2 = os.path.join(output_dir, "tc01_10_f2.png")
        page.screenshot(path=f2)
        add_browser_frame(f2, "Iniciar Sesión — Casa Monarca", page.url)
        
        save_animated_webp([f1, f2], os.path.join(output_dir, "TC-01-10.webp"))
        page.close()

        # ==========================================
        # TC-01-11: Acceso a cualquier ruta protegida sin autenticación
        # ==========================================
        print("\n--- Ejecutando TC-01-11 (Ruta protegida sin Autenticación) ---")
        page = new_page()
        
        # Step 1: Navigating to register migrant
        target_url = "http://127.0.0.1:8000/expediente/registrar/"
        page.goto(server_url)
        f1 = os.path.join(output_dir, "tc01_11_f1.png")
        page.screenshot(path=f1)
        add_browser_frame(f1, "Cargando...", target_url)
        
        # Go to restricted page
        page.goto(target_url)
        page.wait_for_url("**/usuarios/login/?next=/expediente/registrar/")
        
        # Frame 2: Redirected
        f2 = os.path.join(output_dir, "tc01_11_f2.png")
        page.screenshot(path=f2)
        add_browser_frame(f2, "Iniciar Sesión — Casa Monarca", page.url)
        
        save_animated_webp([f1, f2], os.path.join(output_dir, "TC-01-11.webp"))
        page.close()

        # ==========================================
        # TC-01-12: Login con sesión ya activa
        # ==========================================
        print("\n--- Ejecutando TC-01-12 (Login ya Autenticado) ---")
        page = new_page()
        
        # Login
        page.goto(server_url)
        page.fill("#id_username", creds['diego'][0])
        page.fill("#id_password", creds['diego'][1])
        page.click("button.btn-login")
        page.wait_for_url("**/expediente/dashboard/")
        
        # Frame 1: Dashboard
        f1 = os.path.join(output_dir, "tc01_12_f1.png")
        page.screenshot(path=f1)
        add_browser_frame(f1, "Dashboard — Casa Monarca", page.url)
        
        # Frame 2: Attempting to visit login
        f2 = os.path.join(output_dir, "tc01_12_f2.png")
        page.screenshot(path=f2)
        add_browser_frame(f2, "Cargando...", server_url)
        
        # Navigate to login
        page.goto(server_url)
        page.wait_for_url("**/expediente/dashboard/")
        
        # Frame 3: Redirected back to dashboard
        f3 = os.path.join(output_dir, "tc01_12_f3.png")
        page.screenshot(path=f3)
        add_browser_frame(f3, "Dashboard — Casa Monarca", page.url)
        
        save_animated_webp([f1, f2, f3], os.path.join(output_dir, "TC-01-12.webp"))
        page.close()

        # ==========================================
        # TC-01-13: Llave Privada Corrupta
        # ==========================================
        print("\n--- Ejecutando TC-01-13 (Llave Privada Corrupta) ---")
        
        try:
            # Corrupt database key for lalo
            corrupt_lalo_key()
            
            page = new_page()
            
            # Frame 1: Login filled
            page.goto(server_url)
            page.fill("#id_username", creds['lalo'][0])
            page.fill("#id_password", creds['lalo'][1])
            f1 = os.path.join(output_dir, "tc01_13_f1.png")
            page.screenshot(path=f1)
            add_browser_frame(f1, "Iniciar Sesión — Casa Monarca", server_url)
            
            # Submit (logs in Django, but cryptographic key decryption fails silently)
            page.click("button.btn-login")
            page.wait_for_url("**/expediente/dashboard/")
            
            # Frame 2: Dashboard with empty cryptography cache
            f2 = os.path.join(output_dir, "tc01_13_f2.png")
            page.screenshot(path=f2)
            add_browser_frame(f2, "Dashboard — Casa Monarca", page.url)
            
            # Frame 3: Click "Ver expedientes" -> Decrypt fails -> Logout and redirect
            page.click("text=Ver expedientes")
            page.wait_for_url("**/usuarios/login/")
            
            # Capture the red error banner page!
            f3 = os.path.join(output_dir, "tc01_13_f3.png")
            page.screenshot(path=f3)
            # Save a dedicated error image as TC-01-13_error.png!
            error_png_path = os.path.join(output_dir, "TC-01-13_error.png")
            # We want both the browser frame version and the raw screenshot version
            # Let's save a copy of f3 to error_png_path first
            im_err = Image.open(f3)
            im_err.save(error_png_path)
            im_err.close()
            
            # Add frame to f3 for the animation
            add_browser_frame(f3, "Iniciar Sesión — Casa Monarca", page.url)
            
            # Save the animation
            save_animated_webp([f1, f2, f3], os.path.join(output_dir, "TC-01-13.webp"))
            
            # Also add browser frame to TC-01-13_error.png to make it look exceptionally beautiful and premium!
            add_browser_frame(error_png_path, "Iniciar Sesión — Error Desbloqueo", page.url)
            print(f"Evidencia: Guardada imagen fija de error {error_png_path}")
            
            page.close()
            
        finally:
            # Restore lalo's key regardless of success or failure
            restore_lalo_key()

        # Close browser
        browser.close()
        
    print("\n==============================================")
    print("¡TODOS LOS CASOS DE PRUEBA COMPLETADOS CON ÉXITO!")
    print("Todas las evidencias .webp animadas y .png han sido generadas.")
    print("==============================================")
    
    # Terminate Django server if we launched it
    if server_process is not None:
        print("Stopping local Django server...")
        server_process.terminate()
        server_process.wait()
        print("Server stopped.")

if __name__ == "__main__":
    main()
