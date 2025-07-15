import socket 
from typing import Optional 
from core.network_utils import is_filtered
from core.config import DEFAULT_TIMEOUT, logger

def test_ip_connection(ip: str, address_family: int) -> Optional[int]:
    """Tries to connect and returns the result code (from connect_ex)."""
    try:
        with socket.socket(address_family, socket.SOCK_STREAM) as sock:
            sock.settimeout(DEFAULT_TIMEOUT)
            if address_family == socket.AF_INET6:
                connect_args = (ip, 80, 0, 0)
            else:
                connect_args = (ip, 80)
            return sock.connect_ex(connect_args)

    except Exception as e:
        logger.error(f"Error testing connection to {ip} ({'IPv6' if address_family == socket.AF_INET6 else 'IPv4'}): {e}")
        return None

def interpret_connection_result(result: Optional[int]) -> bool:
    """Returns True if the connection was successful or the port is filtered; otherwise, returns False."""
    if result is None:
        return False
    if result == 0:
        return True
    if is_filtered(result):
        return True
    return False

def is_host_reachable(ip: str, address_family: int) -> bool:
    """Checks whether the target host responds to ICMP ping requests (i.e., is reachable)."""
    try: 
        result = test_ip_connection(ip, address_family)
        return interpret_connection_result(result)
    except (socket.gaierror, socket.timeout, OSError) as e:
        ip_version = 'IPv6' if address_family == socket.AF_INET6 else 'IPv4'
        logger.error(f"Connection test failed on IP {ip} ({ip_version}): {e}")
        return False

def check_network_available() -> bool:
    """Verifies general network availability on the host machine."""
    try: 
        result = test_ip_connection('8.8.8.8', socket.AF_INET)
        return interpret_connection_result(result)
    except OSError as e:
        logger.exception("Network unavailable while testing connection to 8.8.8.8 (IPv4): %s", e)
        return False
                               