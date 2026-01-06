#!/usr/bin/env python3
"""
qrtunnel: Simple cross-platform file sharing via QR code.
Features account-free SSH tunneling (default on Linux/macOS) and ngrok support.

Smart Mode Limitations:
- AP Isolation: Some guest Wi-Fi networks prevent devices from talking to each other.
- Firewalls: The host computer must allow incoming traffic on the local port (default 8000).
- Subnets/VLANs: Heuristic assumes a /24 subnet. If client and server are on different
  local subnets, Smart Mode will correctly fall back to the Internet tunnel.
- VPNs: Active VPNs may interfere with LAN IP detection or routing.

Usage: qrtunnel <file_path1> [<file_path2> ...]
       qrtunnel (for upload mode)
"""

__version__ = "3.0.0"

import os
import sys
import threading
import time
import argparse
import platform
import subprocess
import re
import json
import socket
import ipaddress
import random
import uuid
import http.cookies
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote
from pathlib import Path
from socketserver import ThreadingMixIn
from werkzeug.wsgi import LimitedStream
from streaming_form_data import StreamingFormDataParser
from streaming_form_data.targets import FileTarget


# Terminal colors and icons
CLR_G = "\033[92m"  # Green
CLR_Y = "\033[93m"  # Yellow
CLR_R = "\033[91m"  # Red
CLR_B = "\033[94m"  # Blue
CLR_RST = "\033[0m" # Reset
DOT = "●"

# Success/Error/Warning markers
OK = f"{CLR_G}{DOT}{CLR_RST}"
ERR = f"{CLR_R}{DOT}{CLR_RST}"
WRN = f"{CLR_Y}{DOT}{CLR_RST}"
INFO = f"{CLR_B}{DOT}{CLR_RST}"


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    daemon_threads = True


def getch():
    """Reads a single character from stdin without blocking or requiring Enter."""
    if platform.system() == 'Windows':
        import msvcrt
        if msvcrt.kbhit():
            return msvcrt.getch().decode(errors='ignore')
        return None
    else:
        import sys
        import termios
        import tty
        import select

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            if select.select([sys.stdin], [], [], 0.1)[0]:
                return sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return None


class Config:
    """Configuration constants"""
    LOCAL_PORT = 8000
    OTP = None
    CONFIG_DIR = Path.home() / ".qrtunnel"
    CONFIG_FILE = CONFIG_DIR / "config.json"


class HotspotHelper:
    """Helper for Wi-Fi Hotspot configuration and QR generation"""
    
    def __init__(self):
        self.config_file = Config.CONFIG_FILE
        
    def load_config(self):
        """Load configuration from file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}

    def save_config(self, config):
        """Save configuration to file"""
        Config.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)

    def setup_interactive(self):
        """Interactive setup for Hotspot credentials"""
        print("\n" + "="*60)
        print("WI-FI HOTSPOT SETUP")
        print("="*60)
        print("Store your Hotspot/Wi-Fi credentials securely to generate")
        print("Quick-Join QR codes for your other devices.")
        print("-" * 60)
        
        try:
            ssid = input("SSID (Network Name): ").strip()
            if not ssid:
                print(f"{ERR} SSID cannot be empty.")
                return

            print("\nSecurity Type:")
            print("  1. WPA/WPA2/WPA3 (Most common)")
            print("  2. WEP (Old)")
            print("  3. None (Open)")
            sec_choice = input("Select [1-3] (default 1): ").strip()
            
            security = "WPA"
            if sec_choice == '2': security = "WEP"
            elif sec_choice == '3': security = "nopass"
            
            password = ""
            if security != "nopass":
                password = input("Password: ").strip()
            
            config = self.load_config()
            config['hotspot'] = {
                'ssid': ssid,
                'password': password,
                'security': security
            }
            self.save_config(config)
            print(f"\n{OK} Hotspot configuration saved.")
            print(f"   Config location: {self.config_file}")
            
        except KeyboardInterrupt:
            print("\n\n[*] Setup cancelled.")

    def get_qr_data(self):
        """Get hotspot data for QR code"""
        config = self.load_config().get('hotspot')
        if not config: return None
        
        ssid = config.get('ssid')
        password = config.get('password', '')
        security = config.get('security', 'WPA')
        
        if not ssid: return None
        
        # Escape special characters for WIFI string format
        # standard: escape \ ; , :
        def escape(s):
            return s.replace('\\', '\\\\').replace(';', '\\;').replace(',', '\\,').replace(':', '\\:')
            
        qr_str = f"WIFI:T:{security};S:{escape(ssid)};"
        if security != 'nopass':
            qr_str += f"P:{escape(password)};"
        qr_str += "H:false;;"
        
        return qr_str, ssid, password


def get_lan_ip():
    """Get the primary LAN IP address of the host (IPv4 preferred)."""
    try:
        # Create a dummy socket to determine the preferred interface
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't need to be reachable, just needs to be a public IP
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        
        addr = ipaddress.ip_address(ip)
        if addr.is_private and not addr.is_loopback:
            return str(ip)
    except Exception:
        pass
        
    # Fallback to hostname-based detection
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            addr = ipaddress.ip_address(ip)
            if addr.is_private and not addr.is_loopback:
                return str(ip)
    except Exception:
        pass
    return None


def is_same_lan(client_ip, server_ip):
    """
    Check if the client IP is on the same LAN as the server IP.
    Uses private IP ranges, subnet heuristics, and optional ARP check.
    """
    try:
        c_ip = ipaddress.ip_address(client_ip)
        s_ip = ipaddress.ip_address(server_ip)

        # 1. Basic check: both must be private
        if not (c_ip.is_private and s_ip.is_private):
            return False

        # 2. If they are exactly the same, it's the host itself
        if c_ip == s_ip:
            return True

        # 3. ARP check (Linux only) - strongest confirmation of local adjacency
        if platform.system() == 'Linux':
            try:
                with open('/proc/net/arp', 'r') as f:
                    arp_table = f.read()
                    if client_ip in arp_table:
                        return True
            except:
                pass

        # 4. Subnet heuristic: same /24 is common for home/small office LANs
        # Without knowing the exact netmask, we assume /24 as it is the most 
        # frequent configuration.
        c_net = ipaddress.ip_network(f"{client_ip}/24", strict=False)
        return s_ip in c_net
    except:
        return False





class FileTransferHandler(BaseHTTPRequestHandler):
    """HTTP request handler for file sharing and uploading"""
    
    file_paths = None
    upload_mode = False
    server_lan_ip = None
    
    # Security: Authorized session tokens
    authorized_sessions = set()

    def check_auth(self):
        """Check if request is authorized (LAN requires password, Tunnel/Localhost does not)"""
        # 1. Allow localhost (Tunnel agent or local user)
        if self.client_address[0] in ["127.0.0.1", "::1"]:
            return True
        
        # 2. Allow ping for discovery (returns 1x1 GIF)
        if self.path == '/ping' or self.path.startswith('/ping?'):
            return True
            
        # 3. Check Cookie for valid session
        cookie_header = self.headers.get('Cookie')
        if cookie_header:
            try:
                cookies = http.cookies.SimpleCookie(cookie_header)
                if 'session' in cookies:
                    token = cookies['session'].value
                    if token in self.authorized_sessions:
                        return True
            except:
                pass
        
        return False

    def handle_login(self):
        """Handle login form submission"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            
            from urllib.parse import parse_qs
            params = parse_qs(post_data)
            password = params.get('password', [''])[0]
            
            if password == Config.OTP:
                # Generate session token
                session_token = str(uuid.uuid4())
                self.authorized_sessions.add(session_token)
                
                # Set cookie and redirect
                self.send_response(303) # See Other
                self.send_header('Location', '/')
                self.send_header('Set-Cookie', f'session={session_token}; Path=/; HttpOnly; Max-Age=86400')
                self.end_headers()
                print(f"{OK} Auth success from {self.client_address[0]}")
            else:
                print(f"{WRN} Failed auth attempt from {self.client_address[0]}")
                self.send_login_page(error="Incorrect password")
                
        except Exception as e:
            print(f"{ERR} Auth error: {e}")
            self.send_error(500, "Internal Server Error")

    def send_login_page(self, error=None):
        """Send password entry page"""
        error_html = f'<p class="error">{error}</p>' if error else ''
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>qrtunnel - Security Check</title>
    <style>
        body {{
            font-family: -apple-system, system-ui, sans-serif;
            background: #1a1a2e;
            color: #eee;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
        }}
        .box {{
            background: #16213e;
            padding: 40px;
            border-radius: 8px;
            text-align: center;
            width: 100%;
            max-width: 320px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.4);
        }}
        input {{
            width: 100%;
            padding: 12px;
            margin: 20px 0;
            background: #0f0f1a;
            border: 1px solid #2a3a5e;
            color: white;
            border-radius: 4px;
            font-size: 18px;
            text-align: center;
            letter-spacing: 2px;
        }}
        button {{
            width: 100%;
            padding: 12px;
            background: #4361ee;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            cursor: pointer;
        }}
        button:hover {{ background: #3a56d4; }}
        .error {{ color: #ff4757; margin-bottom: 10px; }}
        h2 {{ margin-top: 0; }}
    </style>
</head>
<body>
    <div class="box">
        <h2>🔒 Restricted Access</h2>
        <p>Please enter the 6-digit code shown on the host screen.</p>
        {error_html}
        <form action="/login" method="post">
            <input type="text" name="password" pattern="[0-9]*" inputmode="numeric" placeholder="000000" maxlength="6" required autofocus autocomplete="off">
            <button type="submit">Verify</button>
        </form>
    </div>
</body>
</html>"""
        self.send_response(200 if not error else 403)
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-Length', str(len(html)))
        self.end_headers()
        self.wfile.write(html.encode())
    
    def log_message(self, format, *args):
        """Suppress default logging and show smart connection info"""
        client_ip = self.client_address[0]
        is_local = client_ip == "127.0.0.1" or client_ip == "::1"
        if is_local or (self.server_lan_ip and is_same_lan(client_ip, self.server_lan_ip)):
            conn_type = f"{OK} LAN"
        else:
            conn_type = f"{INFO} Tunnel"
        
        # Only log significant requests (downloads/uploads)
        path = self.path
        if "/download/" in path or "/upload" in path or path == "/":
            print(f"[*] {conn_type} request from {client_ip}: {path}")

    def do_GET(self):
        """Handle GET requests"""
        if not self.check_auth():
            self.send_login_page()
            return

        parsed_path = urlparse(self.path)
        if parsed_path.path == '/ping':
            self.send_ping_gif()
        elif self.upload_mode:
            self.send_upload_page()
        else:
            if parsed_path.path.startswith('/download/'):
                filename = unquote(parsed_path.path[len('/download/'):])
                self.serve_single_file(filename)
            elif parsed_path.path == '/' or parsed_path.path == '/index.html':
                self.send_download_page()
            else:
                self.send_error(404, "Not Found")

    def send_ping_gif(self):
        """Send a 1x1 transparent GIF for LAN detection"""
        gif = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;'
        self.send_response(200)
        self.send_header('Content-type', 'image/gif')
        self.send_header('Content-Length', len(gif))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Private-Network', 'true')
        self.end_headers()
        self.wfile.write(gif)

    def get_smart_redirect_js(self):
        """Generate JS for automatic LAN redirection"""
        lan_ip = str(self.server_lan_ip) if self.server_lan_ip else ""
        if not lan_ip or lan_ip == "None" or lan_ip == "127.0.0.1":
            return ""
        
        return f"""
    <script>
        (function() {{
            var lanIp = "{lan_ip}";
            var lanPort = {Config.LOCAL_PORT};
            var lanUrl = "http://" + lanIp + ":" + lanPort;
            
            // Only attempt redirect if we are NOT already on the LAN IP
            if (window.location.hostname !== lanIp) {{
                console.log("Checking LAN connectivity to " + lanUrl + "...");
                var img = new Image();
                img.onload = function() {{
                    console.log("LAN detected! Redirecting to high-speed link...");
                    // Small delay to ensure browser can handle the navigation
                    setTimeout(function() {{
                        window.location.href = lanUrl + window.location.pathname + window.location.search;
                    }}, 100);
                }};
                img.onerror = function() {{
                    console.log("LAN IP found but unreachable (firewall, AP isolation, or different subnet).");
                }};
                // Try to load a tiny image from the LAN server
                img.src = lanUrl + "/ping?t=" + Date.now();
            }}
        }})();
    </script>
        """

    def do_POST(self):
        """Handle POST requests for file uploads"""
        if self.path == '/login':
            self.handle_login()
            return
            
        if not self.check_auth():
            self.send_login_page()
            return

        if self.upload_mode:
            self.handle_upload()
        else:
            self.send_error(405, "Method Not Allowed")

    def handle_upload(self):
        """Handle file upload with streaming"""
        try:
            content_length = int(self.headers['Content-Length'])
            stream = LimitedStream(self.rfile, content_length)
            
            parser = StreamingFormDataParser(headers=self.headers)
            
            # Create a temporary file for the upload
            temp_filename = f"upload_{int(time.time())}.tmp"
            temp_path = Path.cwd() / temp_filename
            
            file_target = FileTarget(str(temp_path))
            parser.register('file', file_target)

            # Feed the data to the parser
            chunk_size = 65536  # 64KB
            while True:
                chunk = stream.read(chunk_size)
                if not chunk:
                    break
                parser.data_received(chunk)

            # Get the filename from the part headers
            if not getattr(file_target, 'multipart_filename', None):
                self.send_error(400, "File not found in form data")
                return

            # Sanitize and rename the file
            sanitized_filename = os.path.basename(unquote(file_target.multipart_filename))
            if not sanitized_filename:
                self.send_error(400, "Invalid filename")
                return

            final_path = Path.cwd() / sanitized_filename
            os.rename(temp_path, final_path)
            
            print(f"{OK} File '{sanitized_filename}' received and saved to {final_path}")

            # Send success response
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            success_html = self.get_upload_success_page(sanitized_filename)
            self.send_header('Content-Length', str(len(success_html)))
            self.end_headers()
            self.wfile.write(success_html.encode())
            self.close_connection = True

        except Exception as e:
            print(f"{ERR} Error during upload: {e}")
            self.send_error(500, "Internal Server Error")

    def get_upload_success_page(self, filename):
        """Generate the HTML for the upload success page"""
        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>qrtunnel - Upload Success</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            color: #eee;
        }}
        .container {{
            background: #16213e;
            border-radius: 8px;
            padding: 40px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.4);
            max-width: 480px;
            width: 100%;
        }}
        .header {{
            text-align: center;
            margin-bottom: 32px;
            padding-bottom: 24px;
            border-bottom: 1px solid #2a3a5e;
        }}
        h1 {{
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 8px;
            color: #fff;
        }}
        .subtitle {{
            font-size: 14px;
            color: #888;
        }}
        .success-message {{
            text-align: center;
            margin-bottom: 20px;
            color: #4CAF50;
            font-size: 1.2em;
        }}
        .link-button {{
            display: block;
            width: 100%;
            padding: 16px 24px;
            background: #4361ee;
            color: #fff;
            border: none;
            border-radius: 6px;
            font-size: 15px;
            font-weight: 500;
            cursor: pointer;
            text-decoration: none;
            text-align: center;
            transition: background 0.2s ease;
            margin-top: 20px;
        }}
        .link-button:hover {{
            background: #3a56d4;
        }}
        .footer {{
            text-align: center;
            margin-top: 24px;
            font-size: 12px;
            color: #555;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Upload Status</h1>
        </div>
        <div class="success-message">
            <p>File '<strong>{filename}</strong>' uploaded successfully!</p>
        </div>
        <a href="/" class="link-button">Upload Another File</a>
        <p class="footer">qrtunnel</p>
    </div>
</body>
</html>"""

    def send_upload_page(self):
        """Send HTML page for file uploading"""
        lan_ip = str(self.server_lan_ip) if self.server_lan_ip else ""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>qrtunnel - File Upload</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            color: #eee;
        }}
        .container {{
            background: #16213e;
            border-radius: 8px;
            padding: 40px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.4);
            max-width: 480px;
            width: 100%;
        }}
        .header {{
            text-align: center;
            margin-bottom: 32px;
            padding-bottom: 24px;
            border-bottom: 1px solid #2a3a5e;
        }}
        h1 {{
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 8px;
            color: #fff;
        }}
        .subtitle {{
            font-size: 14px;
            color: #888;
        }}
        .upload-form {{
            display: flex;
            flex-direction: column;
            gap: 20px;
        }}
        .file-input-wrapper {{
            position: relative;
            width: 100%;
            padding: 16px 24px;
            background: #0f0f1a;
            border: 1px dashed #4361ee;
            border-radius: 6px;
            text-align: center;
            cursor: pointer;
            transition: background 0.2s ease, border-color 0.2s ease;
        }}
        .file-input-wrapper:hover {{
            background: #1f1f2a;
            border-color: #5a78ff;
        }}
        #file-input {{
            opacity: 0;
            position: absolute;
            top: 0; left: 0;
            width: 100%;
            height: 100%;
            cursor: pointer;
        }}
        .file-input-label {{
            font-size: 14px;
            font-weight: 500;
            color: #ccc;
        }}
        #file-name {{
            margin-top: 12px;
            font-size: 12px;
            font-family: 'SF Mono', 'Consolas', monospace;
            color: #888;
        }}
        .submit-button {{
            display: block;
            width: 100%;
            padding: 16px 24px;
            background: #4361ee;
            color: #fff;
            border: none;
            border-radius: 6px;
            font-size: 15px;
            font-weight: 500;
            cursor: pointer;
            text-align: center;
            transition: background 0.2s ease;
            opacity: 0.5;
            pointer-events: none;
        }}
        .submit-button.enabled {{
            opacity: 1;
            pointer-events: auto;
        }}
        .submit-button:hover.enabled {{
            background: #3a56d4;
        }}
        .footer {{
            text-align: center;
            margin-top: 24px;
            font-size: 12px;
            color: #555;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Upload File</h1>
            <p class="subtitle">Select a file to send to this computer</p>
        </div>
        <form id="upload-form" class="upload-form" action="/upload" method="post" enctype="multipart/form-data">
            <div class="file-input-wrapper">
                <label for="file-input" class="file-input-label">Click to select a file</label>
                <input type="file" id="file-input" name="file" required>
                <p id="file-name"></p>
            </div>
            <button type="submit" id="submit-btn" class="submit-button">Upload</button>
        </form>
        <div id="lan-discovery" style="margin-top: 20px; text-align: center; display: none;">
            <p style="font-size: 13px; color: #4CAF50; margin-bottom: 10px;">Same Wi-Fi detected!</p>
            <a id="lan-btn" href="#" style="font-size: 14px; color: #4361ee; text-decoration: none; border: 1px solid #4361ee; padding: 8px 16px; border-radius: 4px;">Switch to High Speed</a>
        </div>
        <p class="footer">qrtunnel</p>
    </div>
    <script>
        const fileInput = document.getElementById('file-input');
        const fileNameDisplay = document.getElementById('file-name');
        const submitButton = document.getElementById('submit-btn');

        fileInput.addEventListener('change', () => {{
            if (fileInput.files.length > 0) {{
                fileNameDisplay.textContent = `Selected: ${{fileInput.files[0].name}}`;
                submitButton.classList.add('enabled');
            }} else {{
                fileNameDisplay.textContent = '';
                submitButton.classList.remove('enabled');
            }}
        }});

        // Manual LAN switch helper
        (function() {{
            var lanIp = "{lan_ip}";
            var lanPort = {Config.LOCAL_PORT};
            var lanUrl = "http://" + lanIp + ":" + lanPort;
            if (lanIp && lanIp !== "None" && window.location.hostname !== lanIp) {{
                var discoveryDiv = document.getElementById('lan-discovery');
                var lanBtn = document.getElementById('lan-btn');
                var img = new Image();
                img.onload = function() {{
                    discoveryDiv.style.display = 'block';
                    lanBtn.href = lanUrl + window.location.pathname + window.location.search;
                }};
                img.src = lanUrl + "/ping?t=" + Date.now();
            }}
        }})();
    </script>
    {self.get_smart_redirect_js()}
</body>
</html>"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-Length', len(html.encode()))
        self.end_headers()
        self.wfile.write(html.encode())

    
    def send_download_page(self):
        """Send HTML page with individual file download links"""
        lan_ip = str(self.server_lan_ip) if self.server_lan_ip else ""
        file_list_html = ""
        for file_path in self.file_paths:
            filename = os.path.basename(file_path)
            file_list_html += f'<li><a href="/download/{filename}" class="file-link">{filename}</a></li>'

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>qrtunnel - File Download</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            color: #eee;
        }}
        .container {{
            background: #16213e;
            border-radius: 8px;
            padding: 40px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.4);
            max-width: 480px;
            width: 100%;
        }}
        .header {{
            text-align: center;
            margin-bottom: 32px;
            padding-bottom: 24px;
            border-bottom: 1px solid #2a3a5e;
        }}
        h1 {{
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 8px;
            color: #fff;
        }}
        .subtitle {{
            font-size: 14px;
            color: #888;
        }}
        .file-section {{
            margin-bottom: 32px;
        }}
        .file-section-title {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #666;
            margin-bottom: 12px;
        }}
        .file-list {{
            list-style: none;
            background: #0f0f1a;
            border-radius: 6px;
            border: 1px solid #2a3a5e;
        }}
        .file-list li {{
            border-bottom: 1px solid #2a3a5e;
        }}
        .file-list li:last-child {{
            border-bottom: none;
        }}
        .file-link {{
            display: block;
            padding: 12px 16px;
            font-size: 14px;
            font-family: 'SF Mono', 'Consolas', monospace;
            color: #ccc;
            text-decoration: none;
            transition: background-color 0.2s ease;
        }}
        .file-link:hover {{
            background-color: #2a3a5e;
        }}
        .footer {{
            text-align: center;
            margin-top: 24px;
            font-size: 12px;
            color: #555;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Files Ready</h1>
            <p class="subtitle">Click a file to download</p>
        </div>
        <div class="file-section">
            <p class="file-section-title">Files ({len(self.file_paths)})</p>
            <ul class="file-list">
                {file_list_html}
            </ul>
        </div>
        <div id="lan-discovery" style="margin-top: 20px; text-align: center; display: none;">
            <p style="font-size: 13px; color: #4CAF50; margin-bottom: 10px;">Same Wi-Fi detected!</p>
            <a id="lan-btn" href="#" style="font-size: 14px; color: #4361ee; text-decoration: none; border: 1px solid #4361ee; padding: 8px 16px; border-radius: 4px;">Switch to High Speed</a>
        </div>
        <p class="footer">qrtunnel</p>
    </div>
    <script>
        (function() {{
            var lanIp = "{lan_ip}";
            var lanPort = {Config.LOCAL_PORT};
            var lanUrl = "http://" + lanIp + ":" + lanPort;
            if (lanIp && lanIp !== "None" && window.location.hostname !== lanIp) {{
                var discoveryDiv = document.getElementById('lan-discovery');
                var lanBtn = document.getElementById('lan-btn');
                var img = new Image();
                img.onload = function() {{
                    discoveryDiv.style.display = 'block';
                    lanBtn.href = lanUrl + window.location.pathname + window.location.search;
                }};
                img.src = lanUrl + "/ping?t=" + Date.now();
            }}
        }})();
    </script>
    {self.get_smart_redirect_js()}
</body>
</html>"""
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-Length', len(html.encode()))
        self.end_headers()
        self.wfile.write(html.encode())

    def parse_range_header(self, file_size):
        """Parse the Range header if present."""
        range_header = self.headers.get('Range')
        if not range_header:
            return None
        
        match = re.match(r'bytes=(\d+)-(\d+)?', range_header)
        if not match:
            return None
        
        start = int(match.group(1))
        end = int(match.group(2)) if match.group(2) else file_size - 1
        
        if start >= file_size or (end is not None and start > end):
            return False  # Invalid range
            
        return start, min(end, file_size - 1)

    def serve_single_file(self, filename):
        """Serve a single file for download with support for Range requests"""
        # Find the full path for the requested filename
        target_path = None
        for file_path in self.file_paths:
            if os.path.basename(file_path) == filename:
                target_path = file_path
                break
        
        if not target_path or not os.path.isfile(target_path):
            self.send_error(404, "File Not Found")
            return

        try:
            file_size = os.path.getsize(target_path)
            range_req = self.parse_range_header(file_size)
            
            if range_req is False:
                self.send_error(416, "Requested Range Not Satisfiable")
                return

            if range_req:
                start, end = range_req
                content_length = end - start + 1
                self.send_response(206)
                self.send_header('Content-Range', f'bytes {start}-{end}/{file_size}')
            else:
                start = 0
                end = file_size - 1
                content_length = file_size
                self.send_response(200)

            self.send_header('Content-type', 'application/octet-stream')
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
            self.send_header('Content-Length', str(content_length))
            self.send_header('Accept-Ranges', 'bytes')
            self.end_headers()

            with open(target_path, 'rb') as f:
                if start > 0:
                    f.seek(start)
                
                if platform.system() == 'Linux' and hasattr(os, 'sendfile'):
                    try:
                        sent = 0
                        while sent < content_length:
                            # os.sendfile(out_fd, in_fd, offset, count)
                            # offset is the absolute offset in the file
                            n = os.sendfile(self.connection.fileno(), f.fileno(), start + sent, content_length - sent)
                            if n == 0: break # EOF or other issue
                            sent += n
                    except BrokenPipeError:
                        print(f"{ERR} Client disconnected during transfer of '{filename}'")
                else:
                    try:
                        remaining = content_length
                        chunk_size = 1024 * 1024 # 1MB
                        while remaining > 0:
                            chunk = f.read(min(chunk_size, remaining))
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                            remaining -= len(chunk)
                    except BrokenPipeError:
                        print(f"{ERR} Client disconnected during transfer of '{filename}'")
            
            if not range_req or (range_req and end == file_size - 1):
                print(f"{OK} File '{filename}' served to {self.client_address[0]}")
        except Exception as e:
            # Don't send another error if it's a broken pipe, as the connection is already gone
            if not isinstance(e, BrokenPipeError) and "Broken pipe" not in str(e):
                print(f"{ERR} Error serving file '{filename}': {e}")
                if not self.wfile.closed:
                    try: self.send_error(500, "Internal Server Error")
                    except: pass


class NgrokAuth:
    """Manages ngrok authentication"""
    
    def __init__(self):
        self.config_dir = Config.CONFIG_DIR
        self.config_file = Config.CONFIG_FILE
        
    def ensure_config_dir(self):
        """Create config directory if it doesn't exist"""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
    def load_config(self):
        """Load configuration from file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def save_config(self, config):
        """Save configuration to file"""
        self.ensure_config_dir()
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    def get_authtoken(self):
        """Get ngrok authtoken from config"""
        config = self.load_config()
        return config.get('ngrok_authtoken')
    
    def save_authtoken(self, token):
        """Save ngrok authtoken to config"""
        config = self.load_config()
        config['ngrok_authtoken'] = token
        self.save_config(config)
    
    def setup_ngrok_account(self):
        """Interactive setup for ngrok account"""
        print("\n" + "="*60)
        print("NGROK ACCOUNT SETUP")
        print("="*60)
        print("\nNgrok is a reliable tunneling service that works on all platforms.")
        print("\n🔑 To get your ngrok authtoken:")
        print("   1. Visit: https://dashboard.ngrok.com/signup")
        print("   2. Sign up for a FREE account (email required)")
        print("   3. Copy your authtoken from: https://dashboard.ngrok.com/get-started/your-authtoken")
        
        # Show default SSH alternative on Mac/Linux
        if platform.system() != 'Windows':
            print("\n" + "-"*60)
            print("💡 TIP: No Sign-up Required by Default")
            print("-"*60)
            print("On Linux/macOS, qrtunnel uses SSH tunneling by default.")
            print("You only need to set up ngrok if you specifically want to use it.")
            print("To use the default mode without account, run without --ngrok:")
            print("\n   qrtunnel <files>")
            print("-"*60)
        
        print("\n" + "="*60)
        
        choice = input("\nDo you have an ngrok authtoken? (y/n): ").strip().lower()
        
        if choice == 'y':
            print("\n📋 Paste your ngrok authtoken below:")
            authtoken = input("Authtoken: ").strip()
            
            if authtoken and len(authtoken) > 20:
                self.save_authtoken(authtoken)
                print(f"\n{OK} Authtoken saved successfully!")
                print(f"   Config location: {self.config_file}")
                return authtoken
            else:
                print(f"\n{ERR} Invalid authtoken. Please try again.")
                return None
        else:
            print("\n[OPTIONS]:")
            print("  1. Sign up at: https://dashboard.ngrok.com/signup")
            print("  2. Run 'qrtunnel --setup' after you get your authtoken")
            if platform.system() != 'Windows':
                print("  3. OR use default SSH mode: qrtunnel <files> (no sign-up needed!)")
            return None
    
    def verify_token(self, token):
        """Verify ngrok token by attempting to set it"""
        try:
            from pyngrok import ngrok, conf
            ngrok.set_auth_token(token)
            return True
        except Exception as e:
            print(f"{ERR} Token verification failed: {e}")
            return False


class NgrokTunnel:
    """Ngrok tunnel with authentication"""
    
    def __init__(self, local_port, auth_manager):
        self.local_port = local_port
        self.auth_manager = auth_manager
        self.public_url = None
        self.tunnel = None
        self.name = "ngrok"
        
    def start(self):
        """Start ngrok tunnel with authentication"""
        try:
            from pyngrok import ngrok, conf
            
            print(f"\n[*] Starting ngrok tunnel...")
            
            # Get authtoken
            authtoken = self.auth_manager.get_authtoken()
            
            if not authtoken:
                print("[!] No ngrok authtoken found")
                
                # Show helpful message about default SSH mode
                if platform.system() != 'Windows':
                    print("\n" + "="*60)
                    print("💡 TIP: You can skip ngrok sign-up!")
                    print("="*60)
                    print("\nSimply run qrtunnel without the --ngrok flag to use")
                    print("the default SSH tunneling (no authentication required):")
                    print("\n   qrtunnel <your_files>")
                    print("\nOr continue below to set up ngrok (requires free account).")
                    print("="*60 + "\n")
                
                authtoken = self.auth_manager.setup_ngrok_account()
                
                if not authtoken:
                    print("[!] Cannot start ngrok without authtoken")
                    if platform.system() != 'Windows':
                        print("\n💡 Remember: Run without --ngrok to skip authentication!")
                        print("   Example: qrtunnel myfile.pdf")
                    return False
            
            # Set authtoken
            try:
                ngrok.set_auth_token(authtoken)
            except Exception as e:
                print(f"[!] Error setting authtoken: {e}")
                print("[*] Your saved token might be invalid. Let's set it up again.")
                authtoken = self.auth_manager.setup_ngrok_account()
                if not authtoken:
                    return False
                ngrok.set_auth_token(authtoken)
            
            # Configure ngrok
            conf.get_default().log_level = "ERROR"
            
            # Start tunnel
            print("[*] Establishing tunnel...")
            self.tunnel = ngrok.connect(self.local_port, bind_tls=True)
            self.public_url = self.tunnel.public_url
            
            # Ensure HTTPS
            if self.public_url.startswith('http://'):
                self.public_url = self.public_url.replace('http://', 'https://')
            
            print(f"{OK} Tunnel established: {self.public_url}")
            return True
            
        except ImportError:
            print(f"{ERR} Error: pyngrok is not installed")
            print("   Install with: pip install pyngrok")
            return False
        except Exception as e:
            error_msg = str(e).lower()
            
            if 'authtoken' in error_msg or 'unauthorized' in error_msg or 'invalid' in error_msg:
                print(f"{ERR} Authentication error: {e}")
                print("\n[*] Your authtoken might be invalid or expired.")
                
                # Show default SSH alternative
                if platform.system() != 'Windows':
                    print("\n" + "="*60)
                    print("💡 ALTERNATIVE: Skip authentication entirely!")
                    print("="*60)
                    print("\nYou can restart without --ngrok to use default SSH tunneling:")
                    print("\n   qrtunnel <your_files>")
                    print("\nNo sign-up or authentication required!")
                    print("="*60)
                
                print("\n[*] Or let's set up your ngrok authtoken again...")
                authtoken = self.auth_manager.setup_ngrok_account()
                if authtoken:
                    # Try one more time with new token
                    try:
                        from pyngrok import ngrok
                        ngrok.set_auth_token(authtoken)
                        self.tunnel = ngrok.connect(self.local_port, bind_tls=True)
                        self.public_url = self.tunnel.public_url
                        if self.public_url.startswith('http://'):
                            self.public_url = self.public_url.replace('http://', 'https://')
                        print(f"{OK} Tunnel established: {self.public_url}")
                        return True
                    except Exception as retry_error:
                        print(f"{ERR} Still failed: {retry_error}")
                        if platform.system() != 'Windows':
                            print("\n💡 Try restarting without --ngrok")
                        return False
                return False
            else:
                print(f"{ERR} Error starting ngrok: {e}")
                return False
    
    def stop(self):
        """Stop ngrok tunnel"""
        if self.tunnel:
            try:
                from pyngrok import ngrok
                ngrok.disconnect(self.tunnel.public_url)
                print("\n[*] Ngrok tunnel closed")
            except:
                pass


class SSHTunnel:
    """SSH-based tunnel (localhost.run - no auth required)"""
    
    def __init__(self, local_port):
        self.local_port = local_port
        self.process = None
        self.public_url = None
        self.name = "localhost.run"
        self.output_thread = None
        self.url_found = threading.Event()
        
    def check_ssh(self):
        """Check if SSH is available"""
        try:
            subprocess.run(['ssh', '-V'], capture_output=True, timeout=2)
            return True
        except:
            return False
    
    def _read_output(self):
        """Read output from SSH process in background thread"""
        url_pattern = re.compile(r'https://[a-zA-Z0-9.-]+\.lhr\.life')
        
        try:
            while self.process and self.process.poll() is None:
                line = self.process.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                line = line.strip()
                if line:
                    # Look for URL in the output
                    match = url_pattern.search(line)
                    if match and not self.public_url:
                        self.public_url = match.group(0)
                        self.url_found.set()
        except:
            pass
    
    def start(self):
        """Start SSH tunnel"""
        if not self.check_ssh():
            print(f"[!] SSH not available, skipping {self.name}")
            return False
        
        print(f"[*] Trying {self.name} (no auth required)...")
        
        cmd = [
            'ssh',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'ServerAliveInterval=60',
            '-o', 'ConnectTimeout=15',
            '-o', 'LogLevel=ERROR',
            '-o', 'AddressFamily=inet',
            '-T',
            '-R', f'80:localhost:{self.local_port}',
            'nokey@localhost.run'
        ]
        
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # Start background thread to read output
            self.output_thread = threading.Thread(target=self._read_output, daemon=True)
            self.output_thread.start()
            
            # Wait for URL with timeout
            if self.url_found.wait(timeout=20):
                print(f"{OK} Connected via {self.name}: {self.public_url}")
                return True
            else:
                print(f"[!] {self.name} timeout - no URL received")
                self.stop()
                return False
            
        except Exception as e:
            print(f"[!] {self.name} error: {e}")
            self.stop()
            return False
    
    def stop(self):
        """Stop SSH tunnel"""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=3)
            except:
                try:
                    self.process.kill()
                except:
                    pass
            self.process = None
            print("\n[*] SSH tunnel closed")


class TunnelManager:
    """Manages tunnel services and LAN discovery"""
    
    def __init__(self, local_port, noauth=False, lan_only=False, lan_ip=None):
        self.local_port = local_port
        self.active_tunnel = None
        self.public_url = None
        self.lan_url = None
        self.lan_ip = lan_ip
        self.auth_manager = NgrokAuth()
        self.noauth = noauth
        self.lan_only = lan_only
        
    def start(self):
        """Start services. In Smart Mode (default), both LAN and Tunnel are prepared."""
        # 1. Detect LAN IP if not provided
        if not self.lan_ip:
            self.lan_ip = get_lan_ip()
            
        if self.lan_ip:
            self.lan_url = f"http://{self.lan_ip}:{self.local_port}"
        
        # 2. Handle LAN-only mode
        if self.lan_only:
            print("\n" + "="*60)
            print("LAN MODE ACTIVE")
            print("="*60)
            if self.lan_ip:
                print(f"{OK} LAN server active: {self.lan_url}")
                print("="*60)
                return True
            else:
                print(f"{ERR} Error: Could not detect LAN IP address.")
                print("  Make sure you are connected to a Wi-Fi or local network.")
                print("="*60)
                return False

        # 3. Smart Mode or Tunnel Mode
        print("\n" + "="*60)
        if self.lan_ip:
            print("SMART MODE ENABLED (LAN + Tunnel)")
        else:
            print("ESTABLISHING PUBLIC TUNNEL")
        print("="*60)
        
        # Try to establish a public tunnel as fallback/primary
        success = False
        if self.noauth:
            # Try SSH tunnel first (localhost.run)
            ssh_tunnel = SSHTunnel(self.local_port)
            if ssh_tunnel.start():
                self.active_tunnel = ssh_tunnel
                self.public_url = ssh_tunnel.public_url
                success = True
            else:
                print("\n[!] No-auth SSH tunnel failed. Falling back to ngrok...")
        
        if not success:
            # Use ngrok (default or fallback)
            ngrok_tunnel = NgrokTunnel(self.local_port, self.auth_manager)
            if ngrok_tunnel.start():
                self.active_tunnel = ngrok_tunnel
                self.public_url = ngrok_tunnel.public_url
                success = True

        if success:
            print("="*60)
            return True
        
        # If tunnel failed but we have LAN IP, we can still work in LAN mode
        if self.lan_ip:
            print("\n[!] Tunnel services failed. Continuing in LAN-only mode.")
            print("="*60)
            return True

        print("="*60)
        print(f"\n{ERR} All connection services failed")
        # ... rest of error message will be in main or here ...
        return False
    
    def stop(self):
        """Stop active tunnel"""
        if self.active_tunnel:
            self.active_tunnel.stop()


def generate_qr_code(primary_url, fallback_url=None):
    """Generate and display QR code in terminal"""
    try:
        import qrcode
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=1,
            border=2,
        )
        
        # QR points to the most likely to work URL (LAN if available, otherwise Tunnel)
        # However, for true reliability, the Tunnel is safer.
        # But for "Smart Mode", we want to promote the high-speed LAN link.
        qr_url = primary_url
        qr.add_data(qr_url)
        qr.make(fit=True)
        
        print("\n" + "="*60)
        if fallback_url:
            print(f"  {CLR_G}{DOT} {CLR_Y}{DOT} {CLR_R}{DOT} {CLR_B}{DOT}{CLR_RST}  qrtunnel - Smart mode enabled")
            print("="*60)
            qr.print_ascii(invert=True)
            print("="*60)
            # The primary URL for the QR is the Tunnel, but we show LAN as the 'Fast' option
            # The JS will auto-switch them if they are on LAN.
            print(f"{INFO} Internet link: {primary_url}")
            print(f"{OK} Fast local link: {fallback_url}")
            print("(Auto-detects and switches to High Speed if on same Wi-Fi)")
        else:
            print("SCAN THIS QR CODE TO ACCESS THE FILES:")
            print("="*60)
            qr.print_ascii(invert=True)
            print("="*60)
            print(f"\n{INFO} URL: {qr_url}")
            
        # Display OTP clearly at the end
        if Config.OTP:
            print("-" * 60)
            print(f"🔒 LAN PASSWORD: {CLR_G}{Config.OTP}{CLR_RST}")
            print("-" * 60)
            
        print("="*60 + "\n")
        
    except ImportError:
        print("\n" + "="*60)
        print(f"{WRN} QR code library not installed")
        print("Install with: pip install qrcode")
        print("="*60)
        print(f"{OK} Link: {primary_url}")
        if fallback_url:
            print(f"{INFO} Fallback: {fallback_url}")
        print("="*60 + "\n")


def format_size(bytes):
    """Format bytes to human-readable size"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes < 1024.0:
            return f"{bytes:.1f} {unit}"
        bytes /= 1024.0
    return f"{bytes:.1f} TB"


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="qrtunnel: Secure cross-platform file sharing and receiving. Features smart LAN detection with auto high-speed fallback, 6-digit OTP security, and randomized port selection.",
        usage="""qrtunnel [file_path1] [file_path2] ... [options]
       qrtunnel (starts in upload mode)"""
    )
    parser.add_argument('file_paths', nargs='*', help='One or more paths to files to share. If no files are provided, starts in upload mode.')
    parser.add_argument('--setup', action='store_true', help='Set up or reconfigure ngrok authtoken')
    parser.add_argument('--setup-hotspot', action='store_true', help='Configure Wi-Fi Hotspot credentials for Quick-Join QR')
    parser.add_argument('--status', action='store_true', help='Check authentication status')
    parser.add_argument('--ngrok', action='store_true', help='Use ngrok for tunneling (Default on Windows)')
    parser.add_argument('--noauth', action='store_true', help='Use SSH tunnel (localhost.run) (Default on Linux/macOS)')
    parser.add_argument('--lan', action='store_true', help='Use local network (Wi-Fi) sharing instead of tunneling. Secured by 6-digit OTP.')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    
    args = parser.parse_args()
    
    # Security Setup: Random Port & OTP
    Config.LOCAL_PORT = random.randint(20000, 60000)
    Config.OTP = f"{random.randint(0, 999999):06d}"
    
    # Handle hotspot setup
    if args.setup_hotspot:
        helper = HotspotHelper()
        helper.setup_interactive()
        sys.exit(0)

    # Handle setup mode
    if args.setup:
        auth = NgrokAuth()
        token = auth.setup_ngrok_account()
        if token:
            print(f"\n{OK} Setup complete! You can now use qrtunnel to share or receive files.")
        else:
            print(f"\n{ERR} Setup incomplete. Please try again.")
        sys.exit(0 if token else 1)
    
    # Handle status check
    if args.status:
        auth = NgrokAuth()
        token = auth.get_authtoken()
        print("\n" + "="*60)
        print("AUTHENTICATION STATUS")
        print("="*60)
        if token:
            masked_token = token[:8] + "..." + token[-4:] if len(token) > 12 else "***"
            print(f"{OK} Ngrok authtoken found: {masked_token}")
            print(f"  Config location: {auth.config_file}")
        else:
            print(f"{ERR} No ngrok authtoken configured")
            print("\nTo set up ngrok:")
            print("  1. Run: qrtunnel --setup")
            print("  2. Or visit: https://dashboard.ngrok.com/get-started/your-authtoken")
        print("="*60 + "\n")
        sys.exit(0 if token else 1)
        
    # Determine mode (upload or download)
    upload_mode = not args.file_paths
    
    # Determine tunnel mode
    if platform.system() == 'Windows':
        # Windows defaults to ngrok
        noauth_mode = False
        if args.noauth:
            print("\n" + "="*60)
            print(f"{WRN} WARNING: --noauth is not supported on Windows")
            print("="*60)
            print("The --noauth option uses SSH tunneling which is not reliably supported on Windows.")
            print("Proceeding with ngrok instead...")
            print("="*60)
    else:
        # Linux/macOS defaults to SSH (noauth) unless --ngrok is specified
        if args.ngrok:
            noauth_mode = False
        else:
            noauth_mode = True
    
    # Validate files in download mode
    if not upload_mode:
        for file_path in args.file_paths:
            if not os.path.exists(file_path):
                print(f"{ERR} Error: File '{file_path}' not found")
                sys.exit(1)
            
            if not os.path.isfile(file_path):
                print(f"{ERR} Error: '{file_path}' is not a file")
                sys.exit(1)

    # Display banner
    print("\n" + "="*60)
    print("qrtunnel - Simple File Transfer")
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Port:     {Config.LOCAL_PORT}")
    print(f"Security: LAN Access Code -> [{CLR_G}{Config.OTP}{CLR_RST}]")

    if upload_mode:
        print("Mode: Upload (receive files)")
    else:
        print("Mode: Download (share files)")

    if args.lan:
        print("Tunnel: LAN (high-speed local network)")
    else:
        print("Tunnel: Smart Mode (LAN + Public Tunnel)")
    print("="*60)
    
    if not upload_mode:
        print("Files to be shared:")
        for file_path in args.file_paths:
            size = os.path.getsize(file_path)
            print(f"  - {os.path.basename(file_path)} ({format_size(size)})")
        print("="*60)
    else:
        print("Upload directory:")
        print(f"  - {os.getcwd()}")
        print("="*60)

    # Set up tunnel manager first to get LAN IP
    # First check if we have LAN connectivity. If not, offer Hotspot flow.
    current_lan_ip = get_lan_ip()
    
    if not current_lan_ip and not args.lan: # Only check if not already forced to LAN mode (which would just fail)
        hotspot_helper = HotspotHelper()
        qr_data = hotspot_helper.get_qr_data()
        
        if qr_data:
            qr_string, ssid, password = qr_data
            
            print("\n" + "="*60)
            print(f"{INFO} 📡 Faster local transfer available")
            print("Turn on your phone hotspot and scan this QR to connect your laptop automatically:")
            # Note: OS confirmation is always required for joining networks.
            # iOS may not always auto-join; users may need to tap "Join".
            print("="*60)
            
            try:
                import qrcode
                qr = qrcode.QRCode()
                qr.add_data(qr_string)
                qr.make(fit=True)
                qr.print_ascii(invert=True)
            except ImportError:
                print(f"{WRN} qrcode library not installed. Cannot display QR.")
            
            print("="*60)
            print(f"SSID:     {ssid}")
            print(f"Password: {password}")
            print("="*60)
            print(f"{INFO} Waiting for connection... (checking for LAN IP)")
            
            # Wait loop - re-check connectivity
            try:
                for i in range(15): # Wait ~30 seconds
                    time.sleep(2)
                    new_ip = get_lan_ip()
                    if new_ip:
                        print(f"\n{OK} LAN Connection Detected: {new_ip}")
                        current_lan_ip = new_ip
                        break
            except KeyboardInterrupt:
                print("\nSkipping LAN wait...")

    tunnel_manager = TunnelManager(Config.LOCAL_PORT, noauth=noauth_mode, lan_only=args.lan, lan_ip=current_lan_ip)
    
    # Set up handler
    FileTransferHandler.file_paths = args.file_paths if not upload_mode else None
    FileTransferHandler.upload_mode = upload_mode
    FileTransferHandler.server_lan_ip = current_lan_ip # Use pre-detected IP
    
    # Start HTTP server
    # We bind to 0.0.0.0 to be accessible from LAN
    bind_address = '0.0.0.0'
    try:
        server = ThreadingHTTPServer((bind_address, Config.LOCAL_PORT), FileTransferHandler)
    except OSError as e:
        print(f"\n{ERR} Error: Could not bind to port {Config.LOCAL_PORT}")
        print(f"   {e}")
        sys.exit(1)
    
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    
    print(f"\n{OK} HTTP server started on all interfaces (port {Config.LOCAL_PORT})")
    
    # Start tunnel(s)
    if not tunnel_manager.start():
        server.shutdown()
        sys.exit(1)
    
    # Generate and display QR code(s)
    if tunnel_manager.lan_url and tunnel_manager.public_url:
        # Smart Mode: Public URL is the "gateway" QR because it works everywhere.
        # The JS on the page will handle promoting to LAN if available.
        generate_qr_code(tunnel_manager.public_url, tunnel_manager.lan_url)
    elif tunnel_manager.public_url:
        generate_qr_code(tunnel_manager.public_url)
    else:
        generate_qr_code(tunnel_manager.lan_url)
    
    print("[*] Server is running. Press 'q' to quit, or Ctrl+C to stop.\n")
    
    # Wait for quit command
    try:
        while True:
            char = getch()
            if char and char.lower() == 'q':
                print("\n[*] 'q' pressed. Shutting down...")
                break
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n[*] Ctrl+C pressed. Shutting down...")
    finally:
        tunnel_manager.stop()
        server.shutdown()
        print("[*] Server stopped. Goodbye!")


if __name__ == '__main__':
    main()
