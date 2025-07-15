import socket #for network operations
import ipaddress #for IP address manipulations
from typing import Any, Optional # Type hinting for better code clarity

"""Main coordination module for executing the port scan and handling the pipeline logic."""
from common.models import ScanResults
from core.config import logger
from output.saver import save_results
from scanner.scanner import (
    scan_tcp_ports_parallel, 
    scan_udp_ports_parallel, 
    perform_protocol_scan
)
from scanner.diagnostics import is_host_reachable, check_network_available

def get_local_ip() -> str:
    """Retrieves the host machine’s local IP address."""
    return str(ipaddress.ip_address(socket.gethostbyname(socket.gethostname())))

 
def execute_full_scan (args: Any, user_ip: str) -> Optional[ScanResults]:
    """Executes full TCP and UDP port scans based on user-provided arguments."""
    try:
        tcp4_open_ports, tcp4_uncertain_ports, tcp4_closed_ports, _ = perform_protocol_scan(args, scan_tcp_ports_parallel, socket.AF_INET, "tcp4")
        udp4_open_ports, udp4_uncertain_ports, udp4_closed_ports, _ = perform_protocol_scan(args, scan_udp_ports_parallel, socket.AF_INET, "udp4")
        tcp6_open_ports, tcp6_uncertain_ports, tcp6_closed_ports, _ = perform_protocol_scan(args, scan_tcp_ports_parallel, socket.AF_INET6, "tcp6")
        udp6_open_ports, udp6_uncertain_ports, udp6_closed_ports, _ = perform_protocol_scan(args, scan_udp_ports_parallel, socket.AF_INET6, "udp6")

        scan_results = ScanResults(
                        args,
                        user_ip,
                        args.ip,
                        args.start_port,
                        args.end_port,
                        tcp4_open_ports,
                        tcp4_uncertain_ports,
                        tcp4_closed_ports,
                        udp4_open_ports,
                        udp4_uncertain_ports,
                        udp4_closed_ports,
                        tcp6_open_ports,
                        tcp6_uncertain_ports,
                        tcp6_closed_ports,
                        udp6_open_ports,
                        udp6_uncertain_ports,
                        udp6_closed_ports
                    )
    except Exception as e:
        logger.error(f"Unexpected error during scan: {e}")
        logger.debug("Full stack trace:", exc_info=True)
        return None
    return scan_results

def verify_environment(ip: str, address_family: int) -> bool:
    network_ok = check_network_available()
    host_ok = is_host_reachable(ip, address_family)
    return network_ok and host_ok

def process_results(scan_results: ScanResults) -> None:
    """Processes and saves the scan results."""
    save_results(
        scan_results,
    )
