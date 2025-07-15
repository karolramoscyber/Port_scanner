import unittest
from unittest.mock import patch, MagicMock
from output.reporter import report_results

class TestReportResults(unittest.TestCase):
    """Unit tests for the report_results function in the reporter module."""
    def test_report_prints_expected_output(self):
        """Test that report_results prints the expected output."""
        # Arrange
        mock_print = MagicMock()
        protocol_label: str = "tcp4"
        open_ports: list[int] = [22, 80, 443]
        uncertain_ports: list[int] = [21, 25]
        with patch('builtins.print', mock_print):
        
            # Act
            report_results(protocol_label, open_ports, uncertain_ports)

            # Assert
            mock_print.assert_any_call(f"[{protocol_label.upper()}] Open ports: {open_ports}")
            mock_print.assert_any_call(f"[{protocol_label.upper()}] Possible filtered ports: {uncertain_ports}")

    def test_report_prints_no_open_or_uncertain_ports(self):
        """Test that report_results prints the expected output when no open or uncertain ports are found."""
        # Arrange
        mock_print = MagicMock()
        protocol_label: str = "udp6"
        open_ports: list[int] = []
        uncertain_ports: list[int] = []
        with patch('builtins.print', mock_print):
        
            # Act
            report_results(protocol_label, open_ports, uncertain_ports)

            # Assert
            mock_print.assert_any_call(f"[{protocol_label.upper()}] No open ports found.")   

if __name__ == "__main__":
    unittest.main()