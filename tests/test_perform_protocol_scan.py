import unittest
import socket
from unittest.mock import Mock
from scanner.scanner import perform_protocol_scan

class DummyArgs:
    """A dummy class to simulate command line arguments for testing purposes."""
    def __init__(self, ip: str, start_port: int, end_port: int):
        self.ip = ip
        self.start_port = start_port
        self.end_port = end_port

class TestPerformProtocolScan(unittest.TestCase):
    def test_perform_protocol_scan_open(self):
        """Test perform_protocol_scan correctly interprets a mock result with port 80 open."""
        # Arrange
        mock_scan_fn = Mock(return_value=([80], [], []))
        args = DummyArgs('8.8.8.8', 80, 80)

        result = perform_protocol_scan(args=args,
                                           scan_fn=mock_scan_fn,
                                           address_family=socket.AF_INET,
                                           label='tcp')
            
        # Assert
        self.assertTrue(mock_scan_fn.called, "Expected scan_fn to be called")
        self.assertEqual(len(result[0]), 1, "Expected one open port")
        self.assertEqual(result[0][0], 80, "Expected port 80 to be open")

if __name__ == "__main__":
    unittest.main()
