import socket  
from concurrent.futures import ThreadPoolExecutor, Future 
from scapy.all import sr1
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from common.models import PortScanResult 
from core.network_utils import is_filtered, is_ipv6 
from core.config import DEFAULT_TIMEOUT, logger
from typing import Callable, Tuple, List, Any
from scanner.exceptions import PortScanError 



def perform_protocol_scan(
                args: Any,
                scan_fn: Callable[[str, int, int, int, str], Tuple[List[int],List[int] ,List[int], List[str]]],
                address_family: int,
                label: str
            ) -> Tuple[List[int], List[int], List[int], List[str]]:
    """
    Performs a protocol-specific scan, skipping incompatible address families.
    """
    if address_family == socket.AF_INET and is_ipv6(args.ip):
        logger.warning(f"[{label.upper()}] Skipping IPv4 scan for IPv6 address: {args.ip}")
        return [], [], [], []

    if address_family == socket.AF_INET6 and not is_ipv6(args.ip):
        logger.warning(f"[{label.upper()}] Skipping IPv6 scan for IPv4 address: {args.ip}")
        return [], [], [], []

    try:
        return scan_fn(
            args.ip,
            args.start_port,
            args.end_port,
            address_family,
            label
        )
    except Exception as e:
        logger.error(f"[{label.upper()}] Scan failed: {e}", exc_info=True)
        return [], [], [], []


def scan_single_port_tcp(ip: str, port: int, address_family: int, protocol_label: str):
    """Scan a single TCP port using IPv4 or IPv6 socket."""
    try:
        with socket.socket(address_family, socket.SOCK_STREAM) as s:
            s.settimeout(DEFAULT_TIMEOUT)
            if address_family == socket.AF_INET6:
                result = s.connect_ex((ip, port, 0, 0))
            else:
                result = s.connect_ex((ip, port))

            if result == 0:
                return PortScanResult(ip=ip, label=f"{protocol_label}_open", port=port)
            elif is_filtered(result):
                return PortScanResult(ip=ip, label=f"{protocol_label}_uncertain", port=port)
            else:
                return PortScanResult(ip=ip, label=f"{protocol_label}_closed", port=port)
            

    except socket.error as e:
        logger.error(f"[TCP] Socket error while scanning {ip}:{port} ({'IPv6' if address_family == socket.AF_INET6 else 'IPv4'}): {e}")
        raise PortScanError(f"Socket failure: {e}")


def scan_tcp_ports_parallel(ip: str, start_port: int, end_port: int, address_family: int, protocol_label: str) -> Tuple[List[int], List[int], List[int], List[str]]:
    """Scan multiple TCP ports concurrently."""
    tcp_futures: List[Future[Any]] = []
    tcp_open_ports: List[int] = []
    tcp_uncertain_ports: List[int] = []
    tcp_closed_ports: List[int] = []
    errors: List[str] = []

    with ThreadPoolExecutor(max_workers=30) as executor:
        for port in range(start_port, end_port + 1):
            tcp_futures.append(executor.submit(scan_single_port_tcp, ip, port, address_family, protocol_label))

    for future in tcp_futures:
        try:
            result = future.result()
            if result:
                if result.label == f"{protocol_label}_open":
                    tcp_open_ports.append(result.port)
                elif result.label == f"{protocol_label}_uncertain":
                    tcp_uncertain_ports.append(result.port)
                elif result.label == f"{protocol_label}_closed":
                    tcp_closed_ports.append(result.port)
                logger.debug(f"[{protocol_label.upper()}] Port {result.port}: {result.label.upper()}")
        except PortScanError as e:
            errors.append(str(e))

    return tcp_open_ports, tcp_uncertain_ports, tcp_closed_ports ,errors


def scan_single_port_udp(ip: str, port: int, address_family: int, protocol_label: str):
    """Scan a single UDP port using Scapy for more accurate state detection."""

    try:
        if address_family == socket.AF_INET6:
            pkt = IPv6(dst=ip) / UDP(dport=port)
        else:
            pkt = IP(dst=ip) / UDP(dport=port)
    except Exception as e:
        logger.error(f"[UDP/SCAPY] Packet build failed for {ip}:{port} - {e}")
        raise PortScanError(f"Packet build failed: {e}")

    
    try:
        resp = sr1(pkt, timeout=DEFAULT_TIMEOUT, verbose=0)
    except Exception as e:
        logger.error(f"[UDP/SCAPY] Packet send failed for {ip}:{port} - {e}")
        raise PortScanError(f"Packet send failed: {e}")

    
    if resp is None:
        return PortScanResult(ip=ip, label=f"{protocol_label}_uncertain", port=port)
    
    try:
        icmp_layer = resp.getlayer(ICMP)
        if resp.haslayer(ICMP) and icmp_layer is not None:
            if icmp_layer.type == 3 and icmp_layer.code == 3:
                return PortScanResult(ip=ip, label=f"{protocol_label}_closed", port=port)
            else:
                return PortScanResult(ip=ip, label=f"{protocol_label}_uncertain", port=port)
        else:
            return PortScanResult(ip=ip, label=f"{protocol_label}_open", port=port)

    except Exception as e:
        logger.error(f"[UDP/SCAPY] Error interpreting response from {ip}:{port} - {e}")
        raise PortScanError(f"Response parsing failed: {e}")


def scan_udp_ports_parallel(ip: str, start_port: int, end_port: int, address_family: int, protocol_label: str) -> Tuple[List[int], List[int], List[int], List[str]]:

    """Scan multiple UDP ports concurrently."""

    udp_futures: List[Future[Any]] = []
    udp_open_ports: List[int] = []
    udp_uncertain_ports: List[int] = []
    udp_closed_ports: List[int] = []
    errors: List[str] = []
    
    with ThreadPoolExecutor(max_workers=30) as executor:
        for port in range(start_port, end_port + 1):
            udp_futures.append(executor.submit(scan_single_port_udp, ip, port, address_family, protocol_label))

    for future in udp_futures:
        try:
            result = future.result()
            if result:
                if result.label == f"{protocol_label}_open":
                    udp_open_ports.append(result.port)
                elif result.label == f"{protocol_label}_uncertain":
                    udp_uncertain_ports.append(result.port)
                elif result.label == f"{protocol_label}_closed":
                    udp_closed_ports.append(result.port)
                logger.debug(f"[{protocol_label.upper()}] Port {result.port}: {result.label.upper()}")
        except PortScanError as e:
            logger.warning(f"[{protocol_label.upper()}] A port scan failed due to error: {e}")
            errors.append(str(e))

    return udp_open_ports, udp_uncertain_ports, udp_closed_ports, errors
