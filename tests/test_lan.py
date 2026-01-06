import ipaddress
import platform
from qr import is_same_lan

def test_is_same_lan():
    # Same /24 subnet
    assert is_same_lan("192.168.1.5", "192.168.1.20") == True
    
    # Different /24 subnet (heuristic failure or different LAN)
    assert is_same_lan("192.168.1.5", "192.168.2.20") == False
    
    # Public IP
    assert is_same_lan("8.8.8.8", "192.168.1.20") == False
    
    # Loopback
    assert is_same_lan("127.0.0.1", "192.168.1.20") == False
    
    # Same IP
    assert is_same_lan("192.168.1.20", "192.168.1.20") == True

    print("✅ is_same_lan tests passed!")

if __name__ == "__main__":
    test_is_same_lan()
