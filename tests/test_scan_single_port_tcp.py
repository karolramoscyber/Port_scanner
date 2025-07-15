import unittest
import socket
from unittest.mock import patch, MagicMock

from scanner.scanner import scan_single_port_tcp
from common.models import PortScanResult


class TestScanSinglePortTCP(unittest.TestCase):
    def test_scan_single_port_tcp_open(self):
        """Test that an open TCP port is correctly identified."""
        #Arrange
        with patch('socket.socket') as mock_socket_class:
            mock_socket_instance = mock_socket_class.return_value.__enter__.return_value
            mock_socket_instance.connect_ex.return_value = 0

            result = scan_single_port_tcp('8.8.8.8', 80, socket.AF_INET, 'tcp')

        # Assert
        self.assertIsNotNone(result, "scan_single_port_tcp returned None")
        self.assertIsInstance(result, PortScanResult)
        self.assertEqual(result.label, 'tcp_open')

    @patch('core.network_utils.is_filtered', return_value=True)
    def test_scan_single_port_tcp_filtered(self, mock_is_filtered: MagicMock):
        """Test that a filtered TCP port is correctly identified."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket_instance = mock_socket_class.return_value.__enter__.return_value
            mock_socket_instance.connect_ex.return_value = 10013 

            result = scan_single_port_tcp('8.8.8.8', 80, socket.AF_INET, 'tcp')

        # Assert
        self.assertIsNotNone(result, "scan_single_port_tcp returned None")
        self.assertIsInstance(result, PortScanResult)
        self.assertEqual(result.label, 'tcp_uncertain')

    @patch('core.network_utils.is_filtered', return_value=False)
    def test_scan_single_port_tcp_closed(self, mock_is_filtered: MagicMock):
        """Test that a closed TCP port is correctly identified."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket_instance = mock_socket_class.return_value.__enter__.return_value
            mock_socket_instance.connect_ex.return_value = 10061  
            result = scan_single_port_tcp('8.8.8.8', 80, socket.AF_INET, 'tcp')
            

        self.assertIsNotNone(result)
        self.assertIsInstance(result, PortScanResult)
        self.assertEqual(result.label, 'tcp_closed')

if __name__ == "__main__":
    unittest.main()
        