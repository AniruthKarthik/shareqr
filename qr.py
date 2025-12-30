#!/usr/bin/env python3
"""
qrtunnel: Simple cross-platform file sharing via QR code.
Features account-free SSH tunneling (default on Linux/macOS) and ngrok support.

Usage: qrtunnel <file_path1> [<file_path2> ...]
       qrtunnel (for upload mode)
"""

__version__ = "2.2.0"

import os
import sys
import threading
import time
import argparse
import platform
import subprocess
import re
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote
from pathlib import Path
from socketserver import ThreadingMixIn
from werkzeug.wsgi import LimitedStream
from streaming_form_data import StreamingFormDataParser
from streaming_form_data.targets import FileTarget
import time


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
    CONFIG_DIR = Path.home() / ".qrtunnel"
    CONFIG_FILE = CONFIG_DIR / "config.json"





class FileTransferHandler(BaseHTTPRequestHandler):
    """HTTP request handler for file sharing and uploading"""
    
    file_paths = None
    upload_mode = False
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

    def do_GET(self):
        """Handle GET requests"""
        if self.upload_mode:
            self.send_upload_page()
        else:
            parsed_path = urlparse(self.path)
            if parsed_path.path.startswith('/download/'):
                filename = unquote(parsed_path.path[len('/download/'):])
                self.serve_single_file(filename)
            elif parsed_path.path == '/' or parsed_path.path == '/index.html':
                self.send_download_page()
            else:
                self.send_error(404, "Not Found")

    def do_POST(self):
        """Handle POST requests for file uploads"""
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
            
            print(f"✓ File '{sanitized_filename}' received and saved to {final_path}")

            # Send success response
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            success_html = self.get_upload_success_page(sanitized_filename)
            self.send_header('Content-Length', str(len(success_html)))
            self.end_headers()
            self.wfile.write(success_html.encode())
            self.close_connection = True

        except Exception as e:
            print(f"✗ Error during upload: {e}")
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
        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>qrtunnel - File Upload</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            color: #eee;
        }
        .container {
            background: #16213e;
            border-radius: 8px;
            padding: 40px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.4);
            max-width: 480px;
            width: 100%;
        }
        .header {
            text-align: center;
            margin-bottom: 32px;
            padding-bottom: 24px;
            border-bottom: 1px solid #2a3a5e;
        }
        h1 {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 8px;
            color: #fff;
        }
        .subtitle {
            font-size: 14px;
            color: #888;
        }
        .upload-form {
            display: flex;
            flex-direction: column;
            gap: 20px;
        }
        .file-input-wrapper {
            position: relative;
            width: 100%;
            padding: 16px 24px;
            background: #0f0f1a;
            border: 1px dashed #4361ee;
            border-radius: 6px;
            text-align: center;
            cursor: pointer;
            transition: background 0.2s ease, border-color 0.2s ease;
        }
        .file-input-wrapper:hover {
            background: #1f1f2a;
            border-color: #5a78ff;
        }
        #file-input {
            opacity: 0;
            position: absolute;
            top: 0; left: 0;
            width: 100%;
            height: 100%;
            cursor: pointer;
        }
        .file-input-label {
            font-size: 14px;
            font-weight: 500;
            color: #ccc;
        }
        #file-name {
            margin-top: 12px;
            font-size: 12px;
            font-family: 'SF Mono', 'Consolas', monospace;
            color: #888;
        }
        .submit-button {
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
        }
        .submit-button.enabled {
            opacity: 1;
            pointer-events: auto;
        }
        .submit-button:hover.enabled {
            background: #3a56d4;
        }
        .footer {
            text-align: center;
            margin-top: 24px;
            font-size: 12px;
            color: #555;
        }
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
        <p class="footer">qrtunnel</p>
    </div>
    <script>
        const fileInput = document.getElementById('file-input');
        const fileNameDisplay = document.getElementById('file-name');
        const submitButton = document.getElementById('submit-btn');

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                fileNameDisplay.textContent = `Selected: ${fileInput.files[0].name}`;
                submitButton.classList.add('enabled');
            } else {
                fileNameDisplay.textContent = '';
                submitButton.classList.remove('enabled');
            }
        });
    </script>
</body>
</html>"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-Length', len(html.encode()))
        self.end_headers()
        self.wfile.write(html.encode())

    
    def send_download_page(self):
        """Send HTML page with individual file download links"""
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
        <p class="footer">qrtunnel</p>
    </div>
</body>
</html>"""
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-Length', len(html.encode()))
        self.end_headers()
        self.wfile.write(html.encode())

    def serve_single_file(self, filename):
        """Serve a single file for download"""
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
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
            self.send_header('Content-Length', str(file_size))
            self.end_headers()

            with open(target_path, 'rb') as f:
                if platform.system() == 'Linux' and hasattr(os, 'sendfile'):
                    try:
                        sent = 0
                        while sent < file_size:
                            sent += os.sendfile(self.connection.fileno(), f.fileno(), sent, file_size - sent)
                    except BrokenPipeError:
                        print(f"✗ Client disconnected during transfer of '{filename}'")
                else:
                    try:
                        while True:
                            chunk = f.read(1024 * 1024)
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                    except BrokenPipeError:
                        print(f"✗ Client disconnected during transfer of '{filename}'")
            
            print(f"✓ File '{filename}' served to {self.client_address[0]}")
        except Exception as e:
            # Don't send another error if it's a broken pipe, as the connection is already gone
            if not isinstance(e, BrokenPipeError) and "Broken pipe" not in str(e):
                print(f"✗ Error serving file '{filename}': {e}")
                self.send_error(500, "Internal Server Error")


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
                print("\n✓ Authtoken saved successfully!")
                print(f"   Config location: {self.config_file}")
                return authtoken
            else:
                print("\n✗ Invalid authtoken. Please try again.")
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
            print(f"✗ Token verification failed: {e}")
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
            
            print(f"✓ Tunnel established: {self.public_url}")
            return True
            
        except ImportError:
            print("✗ Error: pyngrok is not installed")
            print("   Install with: pip install pyngrok")
            return False
        except Exception as e:
            error_msg = str(e).lower()
            
            if 'authtoken' in error_msg or 'unauthorized' in error_msg or 'invalid' in error_msg:
                print(f"✗ Authentication error: {e}")
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
                        print(f"✓ Tunnel established: {self.public_url}")
                        return True
                    except Exception as retry_error:
                        print(f"✗ Still failed: {retry_error}")
                        if platform.system() != 'Windows':
                            print("\n💡 Try restarting without --ngrok")
                        return False
                return False
            else:
                print(f"✗ Error starting ngrok: {e}")
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
                print(f"✓ Connected via {self.name}: {self.public_url}")
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
    """Manages tunnel services"""
    
    def __init__(self, local_port, noauth=False):
        self.local_port = local_port
        self.active_tunnel = None
        self.public_url = None
        self.auth_manager = NgrokAuth()
        self.noauth = noauth
        
    def start(self):
        """Start tunnel based on mode"""
        print("\n" + "="*60)
        print("ESTABLISHING PUBLIC TUNNEL")
        print("="*60)
        
        if self.noauth:
            # Try SSH tunnel first (localhost.run)
            ssh_tunnel = SSHTunnel(self.local_port)
            if ssh_tunnel.start():
                self.active_tunnel = ssh_tunnel
                self.public_url = ssh_tunnel.public_url
                print("="*60)
                return True
            else:
                print("\n[!] No-auth SSH tunnel failed. Falling back to ngrok...")
                print("="*60)
        
        # Use ngrok (default or fallback)
        ngrok_tunnel = NgrokTunnel(self.local_port, self.auth_manager)
        if ngrok_tunnel.start():
            self.active_tunnel = ngrok_tunnel
            self.public_url = ngrok_tunnel.public_url
            print("="*60)
            return True
        
        print("="*60)
        print("\n✗ All tunnel services failed")
        print("\n[SOLUTIONS]:")
        if platform.system() != 'Windows' and not self.noauth:
            print("  1. 🚀 EASIEST: Restart without --ngrok to try SSH tunneling")
            print("     Example: qrtunnel <your_files>")
            print()
        print("  2. Make sure you have a valid ngrok authtoken")
        print("  3. Run: qrtunnel --setup (to configure ngrok)")
        print("  4. Check your internet connection")
        print("  5. Check your firewall settings")
        return False
    
    def stop(self):
        """Stop active tunnel"""
        if self.active_tunnel:
            self.active_tunnel.stop()


def generate_qr_code(url):
    """Generate and display QR code in terminal"""
    try:
        import qrcode
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=1,
            border=2,
        )
        qr.add_data(url)
        qr.make(fit=True)
        
        print("\n" + "="*60)
        print("SCAN THIS QR CODE TO ACCESS THE FILES:")
        print("="*60)
        qr.print_ascii(invert=True)
        print("="*60)
        print(f"\n🌐 URL: {url}")
        print("="*60 + "\n")
        
    except ImportError:
        print("\n" + "="*60)
        print("⚠️  QR code library not installed")
        print("Install with: pip install qrcode")
        print("="*60)
        print(f"\n🌐 URL: {url}")
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
        description="qrtunnel: Simple cross-platform file sharing and receiving via QR code. Defaults to account-free SSH tunneling on Linux/macOS.",
        usage="""qrtunnel [file_path1] [file_path2] ... [options]
       qrtunnel (starts in upload mode)"""
    )
    parser.add_argument('file_paths', nargs='*', help='One or more paths to files to share. If no files are provided, starts in upload mode.')
    parser.add_argument('--setup', action='store_true', help='Set up or reconfigure ngrok authtoken')
    parser.add_argument('--status', action='store_true', help='Check authentication status')
    parser.add_argument('--ngrok', action='store_true', help='Use ngrok for tunneling (Default on Windows)')
    parser.add_argument('--noauth', action='store_true', help='Use SSH tunnel (localhost.run) (Default on Linux/macOS)')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    
    args = parser.parse_args()
    
    # Handle setup mode
    if args.setup:
        auth = NgrokAuth()
        token = auth.setup_ngrok_account()
        if token:
            print("\n✓ Setup complete! You can now use qrtunnel to share or receive files.")
        else:
            print("\n✗ Setup incomplete. Please try again.")
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
            print(f"✓ Ngrok authtoken found: {masked_token}")
            print(f"  Config location: {auth.config_file}")
        else:
            print("✗ No ngrok authtoken configured")
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
            print("⚠️  WARNING: --noauth is not supported on Windows")
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
                print(f"✗ Error: File '{file_path}' not found")
                sys.exit(1)
            
            if not os.path.isfile(file_path):
                print(f"✗ Error: '{file_path}' is not a file")
                sys.exit(1)

    # Display banner
    print("\n" + "="*60)
    print("qrtunnel - Simple File Transfer")
    print(f"Platform: {platform.system()} {platform.release()}")

    if upload_mode:
        print("Mode: Upload (receive files)")
    else:
        print("Mode: Download (share files)")

    if noauth_mode:
        print("Tunnel: No-auth (SSH via localhost.run)")
    else:
        print("Tunnel: ngrok (authenticated)")
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

    # Set up handler
    FileTransferHandler.file_paths = args.file_paths if not upload_mode else None
    FileTransferHandler.upload_mode = upload_mode
    
    # Start HTTP server
    try:
        server = ThreadingHTTPServer(('localhost', Config.LOCAL_PORT), FileTransferHandler)
    except OSError as e:
        print(f"\n✗ Error: Could not bind to port {Config.LOCAL_PORT}")
        print(f"   {e}")
        sys.exit(1)
    
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    print(f"\n✓ HTTP server started on localhost:{Config.LOCAL_PORT}")
    
    # Start tunnel
    tunnel_manager = TunnelManager(Config.LOCAL_PORT, noauth=noauth_mode)
    
    if not tunnel_manager.start():
        server.shutdown()
        sys.exit(1)
    
    # Generate and display QR code
    generate_qr_code(tunnel_manager.public_url)
    
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
