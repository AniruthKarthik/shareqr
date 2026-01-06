import sys
sys.path.append('/home/ani/qrtunnel')
from qr import HotspotHelper, Config
import json
import os
import shutil

# Clean up before
if Config.CONFIG_DIR.exists():
    shutil.rmtree(Config.CONFIG_DIR)

# Mock input
# SSID: MyNet
# Security: 1 (WPA)
# Password: secret123
input_values = ["MyNet", "1", "secret123"]
input_iterator = iter(input_values)

def mock_input(prompt=""):
    try:
        val = next(input_iterator)
        print(f"{prompt}{val}")
        return val
    except StopIteration:
        return ""

# Patch input in the module
import builtins
builtins.input = mock_input

try:
    h = HotspotHelper()
    h.setup_interactive()
    
    if h.config_file.exists():
        with open(h.config_file, 'r') as f:
            print("Config content:")
            print(f.read())
            
        # Verify QR string generation
        qr, ssid, pwd = h.get_qr_data()
        print(f"QR String: {qr}")
        print(f"SSID: {ssid}")
        print(f"PWD: {pwd}")
    else:
        print("Config file not found!")
except Exception as e:
    print(f"Error: {e}")
finally:
    # Cleanup
    if Config.CONFIG_DIR.exists():
        shutil.rmtree(Config.CONFIG_DIR)
