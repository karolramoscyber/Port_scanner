import datetime
from dataclasses import asdict 
from typing import Any 
from common.models import PortScanResult, ScanResults 

def format_scan_result(scan_data: ScanResults) -> dict[str, Any]:
    """Format the scan results into a structured dictionary for JSON serialization."""
    port_data = [('tcp4_open_ports', 'TCP4 open', scan_data.tcp4_open_ports),
                    ('tcp4_uncertain_ports', 'TCP4 uncertain', scan_data.tcp4_uncertain_ports),
                    ('udp4_open_ports', 'UDP4 open', scan_data.udp4_open_ports),
                    ('udp4_uncertain_ports', 'UDP4 uncertain', scan_data.udp4_uncertain_ports),
                    ('tcp6_open_ports', 'TCP6 open', scan_data.tcp6_open_ports),
                    ('tcp6_uncertain_ports', 'TCP6 uncertain', scan_data.tcp6_uncertain_ports),
                    ('udp6_open_ports', 'UDP6 open', scan_data.udp6_open_ports),
                    ('udp6_uncertain_ports', 'UDP6 uncertain', scan_data.udp6_uncertain_ports)
                    ]
    result: dict[str, Any] = {
                'scanner_ip': scan_data.user_ip,
                'target_ip': scan_data.target_ip,
                'start_port': scan_data.start_port,
                'end_port': scan_data.end_port
            }
    
    def format_ports(label_prefix: str, ports: list[int]):
        """Format a list of ports into a list of PortScanResult dataclasses."""  
        return [asdict(PortScanResult(ip=scan_data.target_ip, label=label_prefix, port=port)) for port in ports]
    for key, label, ports in port_data:
        result[key] = format_ports(label, ports)
    return result

def save_results_to_json(scan_results: ScanResults) -> dict[str, Any]:
    """Formats ScanResults into a structured dictionary compatible with JSON serialization."""
    return {
        "scan_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "scanner_ip": scan_results.user_ip,
        "target_ip": scan_results.target_ip,
        "port_range": {
            "start": scan_results.start_port,
            "end": scan_results.end_port,
            "total_scanned": scan_results.end_port - scan_results.start_port + 1
        },
        "results": {
            "tcp4": {
                "open": scan_results.tcp4_open_ports,
                "uncertain": scan_results.tcp4_uncertain_ports,
                "closed": scan_results.tcp4_closed_ports
            },
            "udp4": {
                "open": scan_results.udp4_open_ports,
                "uncertain": scan_results.udp4_uncertain_ports,
                "closed": scan_results.udp4_closed_ports
            },
            "tcp6": {
                "open": scan_results.tcp6_open_ports,
                "uncertain": scan_results.tcp6_uncertain_ports,
                "closed": scan_results.tcp6_closed_ports
            },
            "udp6": {
                "open": scan_results.udp6_open_ports,
                "uncertain": scan_results.udp6_uncertain_ports,
                "closed": scan_results.udp6_closed_ports
            }
        }
    }

