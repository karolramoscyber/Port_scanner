import socket        # Provides socket interface for TCP/UDP connections
import ipaddress     # Allows manipulation of IPv4 and IPv6 addresses

def is_valid_ip(ip: str) -> bool:
    """
    Checks if the provided IP address is a valid IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(ip) 
        return True
    except ValueError:
        return False
    

def is_ipv6(ip: str) -> bool:
    """"
    Checks if the provided IP address is IPv6.
    """
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
    except ValueError:
        return False
    
def is_filtered(result: int) -> bool:
    """Checks if the result indicates a filtered port."""
    return result not in [0, 111, 10061, 13]
    
def resolve_ip_or_domain(ip: str) -> str:
    """
    Resolves a valid IPv4/IPv6 address or domain name to an IP address.
    """
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        try:
            info = socket.getaddrinfo(ip, None)
            return str(info[0][4][0])  
        except socket.gaierror:
            raise ValueError("[ERROR] Invalid IP address or domain.")
