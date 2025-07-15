from core.network_utils import resolve_ip_or_domain
from argparse import Namespace

def validate_args(args: Namespace):
    """Performs basic validation on user input arguments such as IP format and port range."""
    args.ip = resolve_ip_or_domain(args.ip)

    if not check_port_range(args.start_port, args.end_port):
        raise ValueError("[ERROR] Start port must be less than or equal to end port.")

def check_port_range(start_port: int, end_port: int) -> bool:
    """Ensure the start port is less than or equal to the end port."""
    return start_port <= end_port    