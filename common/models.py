from dataclasses import dataclass 
from typing import List, Any 

@dataclass
class PortScanResult:
    """Scan result: IP, port, and status."""
    ip: str
    port: int
    label: str

    def __repr__(self):
        return f"{self.ip} - {self.label} -> {self.port}"
        
        
@dataclass
class ScanResults:
    """Holds full port scan results."""
    args: Any
    user_ip: str
    target_ip: str
    start_port: int
    end_port: int
    #IPv4 port results
    
    tcp4_open_ports: List[int]
    tcp4_uncertain_ports: List[int]
    tcp4_closed_ports: List[int]
    udp4_open_ports: List[int]
    udp4_uncertain_ports: List[int]
    udp4_closed_ports: List[int]
    #IPv6 port results

    tcp6_open_ports: List[int]
    tcp6_uncertain_ports: List[int]
    tcp6_closed_ports: List[int]
    udp6_open_ports: List[int]
    udp6_uncertain_ports: List[int]
    udp6_closed_ports: List[int]
    def to_dict (self)-> dict[str,Any]:
        """Convert to dict."""
        return {
            'args': vars(self.args) if self.args else None,
            'user_ip': self.user_ip,
            'target_ip': self.target_ip,
            'start_port': self.start_port,
            'end_port': self.end_port,
            'tcp4_open_ports': self.tcp4_open_ports,
            'tcp4_uncertain_ports': self.tcp4_uncertain_ports,
            'tcp4_closed_ports': self.tcp4_closed_ports,
            'udp4_open_ports':self.udp4_open_ports,
            'udp4_uncertain_ports': self.udp4_uncertain_ports,
            'udp4_closed_ports': self.udp4_closed_ports,
            'tcp6_open_ports':self.tcp6_open_ports,
            'tcp6_uncertain_ports': self.tcp6_uncertain_ports,
            'tcp6_closed_ports': self.tcp6_closed_ports,
            'udp6_open_ports': self.udp6_open_ports,
            'udp6_uncertain_ports':self.udp6_uncertain_ports,
            'udp6_closed_ports': self.udp6_closed_ports
        }
