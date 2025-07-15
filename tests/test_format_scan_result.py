import unittest
from common.models import ScanResults
from core.formatting import format_scan_result

class TestFormatScanResult(unittest.TestCase):
    def test_returns_correct_structure_when_given_valid_scan_results(self):
        """Test that format_scan_result returns the correct structure when given valid ScanResults."""
        # Arrange
        mock_args = type("Args", (), {"ip": "8.8.8.8", "start_port": 20, "end_port": 25})()
        scan_results = ScanResults(
            args = mock_args,
            user_ip="192.168.1.100",
            target_ip='8.8.8.8',
            start_port=20,
            end_port=25,
            tcp4_open_ports=[22],
            tcp4_uncertain_ports=[23],
            tcp4_closed_ports=[21],
            udp4_open_ports=[],
            udp4_uncertain_ports=[],
            udp4_closed_ports=[24, 25],
            tcp6_open_ports=[],
            tcp6_uncertain_ports=[],
            tcp6_closed_ports=[],
            udp6_open_ports=[],
            udp6_uncertain_ports=[],
            udp6_closed_ports=[],      
        )
        # Act
        result = format_scan_result(scan_results)

        # Assert
        self.assertEqual(result["scanner_ip"], "192.168.1.100")
        self.assertEqual(result["target_ip"], "8.8.8.8")
        self.assertEqual(result["start_port"], 20)
        self.assertEqual(result["tcp4_open_ports"][0]['port'], 22)
        self.assertEqual(result["tcp4_uncertain_ports"][0]['label'], "TCP4 uncertain")
        self.assertEqual(result["udp6_open_ports"], [])

if __name__ == "__main__":
    unittest.main()
