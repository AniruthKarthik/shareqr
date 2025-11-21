#!/usr/bin/env python3
"""
shareqr: Simple file sharing via QR code with SSH tunneling.
Usage: shareqr <file_path1> [<file_path2> ...]
"""

import os
import sys
import socket
import subprocess
import threading
import time
import re
import argparse
import signal
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


def getch():
    """Reads a single character from stdin without echoing or requiring Enter."""
    if os.name == 'nt':
        try:
            import msvcrt
            return msvcrt.getch().decode('utf-8', errors='ignore')
        except Exception:
            return None
    else:
        try:
            import termios
            import tty
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                ch = sys.stdin.read(1)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            return ch
        except Exception:
            return None


def find_free_port():
    """Find a free port on localhost"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


class Config:
    """Configuration constants"""
    LOCAL_PORT = None  # Will be set dynamically


class FileShareHandler(BaseHTTPRequestHandler):
    """HTTP request handler for file sharing"""
    
    file_paths = None
    
    def log_message(self, format, *args):
        """Override to customize logging"""
        logger.info(f"{self.client_address[0]} - {format % args}")
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/download':
            self.serve_files_as_zip()
        elif parsed_path.path == '/health':
            self.send_health_check()
        else:
            self.send_download_page()
    
    def send_health_check(self):
        """Send health check response"""
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')
    
    def send_download_page(self):
        """Send HTML page with a download button"""
        try:
            file_list_html = "".join(
                f"<li><span class='icon'>📄</span> {os.path.basename(p)}</li>" 
                for p in self.file_paths
            )
            
            html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>shareqr - File Download</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            color: white;
        }}
        .container {{
            background: rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 500px;
            width: 100%;
            text-align: center;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }}
        h1 {{
            margin-bottom: 15px;
            font-size: 28px;
            font-weight: 600;
        }}
        p {{
            margin-bottom: 30px;
            font-size: 16px;
            opacity: 0.9;
            line-height: 1.5;
        }}
        .file-list {{
            list-style: none;
            margin-bottom: 40px;
            text-align: left;
            background: rgba(0,0,0,0.2);
            padding: 20px;
            border-radius: 12px;
            max-height: 300px;
            overflow-y: auto;
        }}
        .file-list li {{
            padding: 12px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .file-list li:last-child {{
            border-bottom: none;
        }}
        .icon {{
            font-size: 20px;
        }}
        .download-button {{
            display: inline-block;
            padding: 18px 40px;
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%);
            color: white;
            border: none;
            border-radius: 12px;
            font-size: 18px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(255, 107, 107, 0.4);
        }}
        .download-button:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(255, 107, 107, 0.5);
        }}
        .download-button:active {{
            transform: translateY(0);
        }}
        .footer {{
            margin-top: 30px;
            font-size: 14px;
            opacity: 0.7;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Files Ready</h1>
        <p>Download all files as a single ZIP archive</p>
        <ul class="file-list">
            {file_list_html}
        </ul>
        <a href="/download" class="download-button">📥 Download All Files</a>
        <div class="footer">
            <p>Powered by shareqr</p>
        </div>
    </div>
</body>
</html>"""
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', len(html.encode('utf-8')))
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            self.wfile.write(html.encode('utf-8'))
        except Exception as e:
            logger.error(f"Error sending download page: {e}")
            self.send_error(500, "Internal server error")

    def serve_files_as_zip(self):
        """Create a ZIP archive of all files and serve it"""
        try:
            import zipfile
            from io import BytesIO

            logger.info(f"Creating ZIP archive for {self.client_address[0]}")
            
            zip_buffer = BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path in self.file_paths:
                    try:
                        zipf.write(file_path, os.path.basename(file_path))
                    except Exception as e:
                        logger.error(f"Failed to add {file_path} to ZIP: {e}")
            
            zip_buffer.seek(0)
            zip_data = zip_buffer.getvalue()

            self.send_response(200)
            self.send_header('Content-type', 'application/zip')
            self.send_header('Content-Disposition', 'attachment; filename="shareqr_files.zip"')
            self.send_header('Content-Length', len(zip_data))
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            self.wfile.write(zip_data)
            
            logger.info(f"✓ Successfully served ZIP ({len(zip_data)} bytes) to {self.client_address[0]}")
        except Exception as e:
            logger.error(f"Error creating or serving ZIP file: {e}")
            self.send_error(500, "Internal server error")


class SSHTunnel:
    """Manages SSH reverse tunnel to serveo.net"""

    def __init__(self, local_port):
        self.local_port = local_port
        self.process = None
        self.public_url = None
        self.stderr_thread = None
        self.stdout_thread = None
        self.running = False

    def _read_stderr(self):
        """Read stderr in a separate thread"""
        try:
            while self.running and self.process:
                line = self.process.stderr.readline()
                if line:
                    logger.debug(f"SSH stderr: {line.strip()}")
                elif self.process.poll() is not None:
                    break
        except Exception as e:
            logger.debug(f"Error reading stderr: {e}")

    def _read_stdout(self):
        """Read stdout and extract URL"""
        url_pattern = re.compile(r'https://[a-zA-Z0-9.-]+\.serveo\.net')
        
        try:
            while self.running and self.process:
                line = self.process.stdout.readline()
                if line:
                    line = line.strip()
                    logger.debug(f"SSH stdout: {line}")
                    
                    if not self.public_url:
                        match = url_pattern.search(line)
                        if match:
                            self.public_url = match.group(0)
                            logger.info(f"✓ Public URL obtained: {self.public_url}")
                elif self.process.poll() is not None:
                    break
        except Exception as e:
            logger.debug(f"Error reading stdout: {e}")

    def start(self):
        """Start the SSH tunnel and extract the public URL"""
        logger.info("Starting SSH tunnel to serveo.net...")

        # Build SSH command with robust options
        cmd = [
            'ssh',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'ServerAliveInterval=60',
            '-o', 'ServerAliveCountMax=3',
            '-o', 'ExitOnForwardFailure=yes',
            '-o', 'ConnectTimeout=30',
            '-N',  # Don't execute remote command
            '-T',  # Disable pseudo-terminal allocation
            '-R', f'80:localhost:{self.local_port}',
            'serveo.net'
        ]

        try:
            # Start SSH process
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
                encoding='utf-8',
                errors='replace'
            )

            self.running = True

            # Start output reading threads
            self.stdout_thread = threading.Thread(target=self._read_stdout, daemon=True)
            self.stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
            self.stdout_thread.start()
            self.stderr_thread.start()

            # Wait for URL with timeout
            logger.info("Waiting for public URL (this may take up to 30 seconds)...")
            start_time = time.time()
            timeout = 30
            
            while time.time() - start_time < timeout:
                if self.public_url:
                    logger.info("✓ SSH tunnel established successfully!")
                    return True
                
                if self.process.poll() is not None:
                    logger.error("SSH process terminated unexpectedly")
                    return False
                
                time.sleep(0.5)

            logger.error("Timeout waiting for public URL from SSH tunnel")
            return False

        except FileNotFoundError:
            logger.error("SSH command not found. Please ensure SSH is installed and in PATH")
            return False
        except Exception as e:
            logger.error(f"Failed to start SSH tunnel: {e}")
            return False

    def stop(self):
        """Stop the SSH tunnel"""
        self.running = False
        
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning("SSH process did not terminate, killing it")
                self.process.kill()
                self.process.wait()
            except Exception as e:
                logger.error(f"Error stopping SSH tunnel: {e}")
            
            logger.info("SSH tunnel closed")


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
        
        print("\n" + "="*70)
        print("  SCAN THIS QR CODE TO ACCESS FILES")
        print("="*70)
        qr.print_ascii(invert=True)
        print("="*70)
        print(f"\n  🌐 URL: {url}")
        print("\n" + "="*70 + "\n")
        
    except ImportError:
        print("\n" + "="*70)
        print("  ⚠️  QR Code library not installed")
        print("  Install with: pip install qrcode[pil]")
        print("="*70)
        print(f"\n  🌐 URL: {url}")
        print("\n" + "="*70 + "\n")
    except Exception as e:
        logger.warning(f"Failed to generate QR code: {e}")
        print("\n" + "="*70)
        print(f"  🌐 URL: {url}")
        print("="*70 + "\n")


def check_dependencies():
    """Check if required dependencies are available"""
    # Check if SSH is available
    try:
        result = subprocess.run(
            ['ssh', '-V'],
            capture_output=True,
            timeout=5
        )
        logger.info("✓ SSH is available")
        return True
    except FileNotFoundError:
        logger.error("✗ SSH is not installed or not in PATH")
        logger.error("  Please install OpenSSH:")
        logger.error("  - Windows: Install OpenSSH via Settings > Apps > Optional Features")
        logger.error("  - macOS: SSH is pre-installed")
        logger.error("  - Linux: sudo apt-get install openssh-client (Debian/Ubuntu)")
        return False
    except subprocess.TimeoutExpired:
        logger.error("✗ SSH command timed out")
        return False
    except Exception as e:
        logger.error(f"✗ Error checking SSH: {e}")
        return False


def format_size(size_bytes):
    """Format bytes to human-readable size"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="shareqr: Simple file sharing via QR code with SSH tunneling.",
        usage="shareqr <file_path1> [<file_path2> ...]"
    )
    parser.add_argument('file_paths', nargs='+', help='One or more file paths to share')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    file_paths = args.file_paths
    
    # Validate files
    validated_files = []
    total_size = 0
    
    for file_path in file_paths:
        path = Path(file_path)
        
        if not path.exists():
            logger.error(f"✗ File not found: {file_path}")
            sys.exit(1)
        
        if not path.is_file():
            logger.error(f"✗ Not a file: {file_path}")
            sys.exit(1)
        
        validated_files.append(str(path.absolute()))
        total_size += path.stat().st_size
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Display banner
    print("\n" + "="*70)
    print("  shareqr - Simple File Sharing via QR Code")
    print("="*70)
    print("\n  Files to share:")
    for file_path in validated_files:
        size = os.path.getsize(file_path)
        print(f"    📄 {os.path.basename(file_path)} ({format_size(size)})")
    print(f"\n  Total size: {format_size(total_size)}")
    print("="*70 + "\n")
    
    # Find free port
    Config.LOCAL_PORT = find_free_port()
    logger.info(f"Using local port: {Config.LOCAL_PORT}")
    
    # Set up handler with file paths
    FileShareHandler.file_paths = validated_files
    
    # Start HTTP server in a separate thread
    try:
        server = HTTPServer(('localhost', Config.LOCAL_PORT), FileShareHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        logger.info(f"✓ HTTP server started on localhost:{Config.LOCAL_PORT}")
    except Exception as e:
        logger.error(f"✗ Failed to start HTTP server: {e}")
        sys.exit(1)
    
    # Start SSH tunnel
    tunnel = SSHTunnel(Config.LOCAL_PORT)
    
    if not tunnel.start():
        logger.error("✗ Failed to establish SSH tunnel")
        server.shutdown()
        sys.exit(1)
    
    # Generate and display QR code
    generate_qr_code(tunnel.public_url)
    
    print("  📱 Scan the QR code or visit the URL above")
    print("  ⌨️  Press 'q' to quit, or Ctrl+C to stop")
    print("="*70 + "\n")
    
    # Set up signal handler for clean shutdown
    def signal_handler(sig, frame):
        print("\n\n[*] Shutting down...")
        tunnel.stop()
        server.shutdown()
        print("[*] Goodbye!")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Keep the main thread alive
        while True:
            char = getch()
            if char and char.lower() == 'q':
                print("\n\n[*] 'q' pressed. Shutting down...")
                break
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted. Shutting down...")
    finally:
        tunnel.stop()
        server.shutdown()
        print("[*] Server stopped. Goodbye!")


if __name__ == '__main__':
    main()
