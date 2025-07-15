import argparse # Parses command-line arguments from the user
from core.network_utils import resolve_ip_or_domain

def valid_port(p: str) -> int:
    """
    Validates the given port and port range (0–65535).
    """
    port = int(p)
    if port < 0 or port > 65535:
        raise argparse.ArgumentTypeError("[ERROR] Port must be between 0 and 65535.")
    return port

def get_args():
    """
    Parses command-line arguments provided by the user.
    """
    parser = argparse.ArgumentParser(
        description="Command-line port scanner for TCP/UDP over IPv4 and IPv6, with detection of open and filtered ports."
    )
    parser.add_argument("--protocol", choices=["tcp", "udp", "both"], default="both", help="Protocol to scan")
    parser.add_argument("--ip", type=resolve_ip_or_domain, required=True, help="IP address or domain to scan")
    parser.add_argument("--start_port", type=valid_port, required=True, help="Start port (0–65535)")
    parser.add_argument("--end_port", type=valid_port, required=True, help="End port (0–65535)")
    return parser.parse_args()