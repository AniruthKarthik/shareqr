#!/usr/bin/env python3
"""
ShareQR-SSH: Secure file sharing via QR code with OTP authentication
Usage: python shareqr.py <file_path>
"""

import os
import sys
import random
import socket
import subprocess
import threading
import time
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from pathlib import Path


class Config:
    """Configuration constants"""
    LOCAL_PORT = 8000
    REMOTE_PORT = 80
    SSH_HOST = "nokey@localhost.run"
    OTP_LENGTH = 4
    

class OTPManager:
    """Manages OTP generation and validation"""
    
    def __init__(self):
        self.otp = self.generate_otp()
        self.attempts = 0
        self.max_attempts = 5
        
    def generate_otp(self):
        """Generate a random 4-digit OTP"""
        return ''.join([str(random.randint(0, 9)) for _ in range(Config.OTP_LENGTH)])
    
    def verify(self, input_otp):
        """Verify the provided OTP"""
        self.attempts += 1
        return input_otp == self.otp
    
    def is_locked(self):
        """Check if too many failed attempts"""
        return self.attempts >= self.max_attempts


class FileShareHandler(BaseHTTPRequestHandler):
    """HTTP request handler with OTP authentication"""
    
    # Class variables shared across instances
    file_path = None
    otp_manager = None
    authenticated_ips = set()
    
    def log_message(self, format, *args):
        """Override to add custom logging"""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] {self.client_address[0]} - {format % args}")
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        
        # Check if client IP is already authenticated
        if self.client_address[0] in self.authenticated_ips:
            self.serve_file()
            return
        
        # Parse query parameters for OTP
        query_params = parse_qs(parsed_path.query)
        submitted_otp = query_params.get('otp', [''])[0]
        
        if submitted_otp:
            # OTP was submitted, verify it
            if self.otp_manager.is_locked():
                self.send_error_page("Too many failed attempts. Access denied.")
                return
            
            if self.otp_manager.verify(submitted_otp):
                # Correct OTP - add IP to authenticated list and serve file
                self.authenticated_ips.add(self.client_address[0])
                print(f"✓ Correct OTP from {self.client_address[0]}")
                self.serve_file()
            else:
                # Wrong OTP
                remaining = self.otp_manager.max_attempts - self.otp_manager.attempts
                print(f"✗ Wrong OTP from {self.client_address[0]} (Attempts remaining: {remaining})")
                self.send_error_page(f"Invalid OTP. {remaining} attempts remaining.")
        else:
            # No OTP submitted, show the authentication form
            self.send_auth_page()
    
    def send_auth_page(self):
        """Send HTML page requesting OTP"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShareQR-SSH Authentication</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            background: white;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 400px;
            width: 100%;
        }}
        h1 {{
            color: #333;
            margin-bottom: 10px;
            font-size: 24px;
        }}
        p {{
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }}
        .otp-input {{
            width: 100%;
            padding: 15px;
            font-size: 24px;
            text-align: center;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            margin-bottom: 20px;
            letter-spacing: 10px;
            transition: border-color 0.3s;
        }}
        .otp-input:focus {{
            outline: none;
            border-color: #667eea;
        }}
        button {{
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }}
        button:hover {{
            transform: translateY(-2px);
        }}
        button:active {{
            transform: translateY(0);
        }}
        .file-info {{
            background: #f5f5f5;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        .file-info strong {{
            color: #667eea;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Secure File Access</h1>
        <p>Enter the 4-digit OTP to download the file</p>
        <div class="file-info">
            <strong>File:</strong> {os.path.basename(self.file_path)}
        </div>
        <form method="GET" onsubmit="return validateOTP()">
            <input type="text" 
                   name="otp" 
                   class="otp-input" 
                   placeholder="0000" 
                   maxlength="4" 
                   pattern="[0-9]{{4}}"
                   inputmode="numeric"
                   required
                   autofocus>
            <button type="submit">Download File</button>
        </form>
    </div>
    <script>
        function validateOTP() {{
            const input = document.querySelector('.otp-input');
            const value = input.value;
            if (value.length !== 4 || !/^[0-9]{{4}}$/.test(value)) {{
                alert('Please enter a valid 4-digit OTP');
                return false;
            }}
            return true;
        }}
    </script>
</body>
</html>"""
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-Length', len(html.encode()))
        self.end_headers()
        self.wfile.write(html.encode())
    
    def send_error_page(self, message):
        """Send HTML error page"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            background: white;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 400px;
            width: 100%;
            text-align: center;
        }}
        .error-icon {{
            font-size: 64px;
            margin-bottom: 20px;
        }}
        h1 {{
            color: #f5576c;
            margin-bottom: 15px;
            font-size: 24px;
        }}
        p {{
            color: #666;
            font-size: 16px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">❌</div>
        <h1>Access Denied</h1>
        <p>{message}</p>
    </div>
</body>
</html>"""
        
        self.send_response(403)
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-Length', len(html.encode()))
        self.end_headers()
        self.wfile.write(html.encode())
    
    def serve_file(self):
        """Serve the actual file for download"""
        try:
            with open(self.file_path, 'rb') as f:
                file_data = f.read()
            
            filename = os.path.basename(self.file_path)
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
            self.send_header('Content-Length', len(file_data))
            self.end_headers()
            self.wfile.write(file_data)
            
            print(f"✓ File served successfully to {self.client_address[0]}")
        except Exception as e:
            print(f"✗ Error serving file: {e}")
            self.send_error(500, "Internal server error")


class SSHTunnel:
    """Manages SSH reverse tunnel to serveo.net"""
    
    def __init__(self, local_port, remote_port):
        self.local_port = local_port
        self.remote_port = remote_port
        self.process = None
        self.public_url = None
        
    def start(self):
        """Start the SSH tunnel and extract the public URL"""
        print(f"\n[*] Starting SSH tunnel to {Config.SSH_HOST}...")
        
        # Build SSH command
        cmd = [
            'ssh',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'ServerAliveInterval=60',
            '-R', f'{self.remote_port}:localhost:{self.local_port}',
            Config.SSH_HOST
        ]
        
        # Start SSH process
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            text=True
        )
        
        # Wait for URL in stdout
        print("[*] Waiting for public URL...")
        url_pattern = re.compile(r'https://[a-zA-Z0-9.-]+')
        
        for _ in range(30):  # Wait up to 30 seconds
            line = self.process.stdout.readline()
            if line:
                print(f"[SSH] {line.strip()}")
                match = url_pattern.search(line)
                if match:
                    self.public_url = match.group(0)
                    print(f"✓ Tunnel established: {self.public_url}")
                    return True
            time.sleep(1)
        
        print("✗ Failed to get public URL from SSH tunnel")
        return False
    
    def stop(self):
        """Stop the SSH tunnel"""
        if self.process:
            self.process.terminate()
            self.process.wait()
            print("\n[*] SSH tunnel closed")


def generate_qr_code(url, otp):
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
        print("SCAN THIS QR CODE TO ACCESS THE FILE:")
        print("="*60)
        qr.print_ascii(invert=True)
        print("="*60)
        print(f"\n🔑 OTP: {otp}")
        print(f"🌐 URL: {url}")
        print("="*60 + "\n")
        
    except ImportError:
        # Fallback if qrcode is not installed
        print("\n" + "="*60)
        print("⚠️  QR code library not installed")
        print("Install with: pip install qrcode")
        print("="*60)
        print(f"\n🔑 OTP: {otp}")
        print(f"🌐 URL: {url}")
        print("="*60 + "\n")


def check_dependencies():
    """Check if required dependencies are available"""
    # Check if SSH is available
    try:
        subprocess.run(['ssh', '-V'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("✗ Error: SSH is not installed or not in PATH")
        sys.exit(1)


def main():
    """Main function"""
    if len(sys.argv) != 2:
        print("Usage: python shareqr.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    # Validate file
    if not os.path.exists(file_path):
        print(f"✗ Error: File '{file_path}' not found")
        sys.exit(1)
    
    if not os.path.isfile(file_path):
        print(f"✗ Error: '{file_path}' is not a file")
        sys.exit(1)
    
    # Check dependencies
    check_dependencies()
    
    # Display banner
    print("\n" + "="*60)
    print("ShareQR-SSH - Secure File Sharing with OTP Authentication")
    print("="*60)
    print(f"File: {os.path.basename(file_path)}")
    print(f"Size: {os.path.getsize(file_path)} bytes")
    print("="*60 + "\n")
    
    # Initialize OTP manager
    otp_manager = OTPManager()
    
    # Set up handler with file and OTP manager
    FileShareHandler.file_path = file_path
    FileShareHandler.otp_manager = otp_manager
    
    # Start HTTP server in a separate thread
    server = HTTPServer(('localhost', Config.LOCAL_PORT), FileShareHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    print(f"[*] HTTP server started on localhost:{Config.LOCAL_PORT}")
    
    # Start SSH tunnel
    tunnel = SSHTunnel(Config.LOCAL_PORT, Config.REMOTE_PORT)
    
    if not tunnel.start():
        print("✗ Failed to establish SSH tunnel")
        server.shutdown()
        sys.exit(1)
    
    # Generate and display QR code
    generate_qr_code(tunnel.public_url, otp_manager.otp)
    
    print("[*] Server is running. Press Ctrl+C to stop.\n")
    
    try:
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n[*] Shutting down...")
        tunnel.stop()
        server.shutdown()
        print("[*] Server stopped. Goodbye!")


if __name__ == '__main__':
    main()
