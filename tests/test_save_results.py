import unittest
from unittest import TestCase
from common.models import ScanResults
from unittest.mock import Mock, patch, mock_open
from output.saver import save_results
from datetime import datetime

class TestSaveResults(TestCase):
    
    def setUp(self):
        self.scan_data = ScanResults(
            args=Mock(ip='8.8.8.8', start_port=20, end_port=29),
            user_ip='192.168.1.100',
            target_ip='8.8.8.8',
            start_port=20,
            end_port=29,
            tcp4_open_ports=[21],
            tcp4_uncertain_ports=[22],
            tcp4_closed_ports=[23, 24],
            udp4_open_ports=[25],
            udp4_uncertain_ports=[26],
            udp4_closed_ports=[27,28,29],
            tcp6_open_ports=[],
            tcp6_uncertain_ports=[],
            tcp6_closed_ports=[],
            udp6_open_ports=[],
            udp6_uncertain_ports=[],
            udp6_closed_ports=[]
        )     
        self.output_dir = 'output'
        self.output_file = f"{self.output_dir}/scan_result.json"

    @patch("os.makedirs")
    @patch('builtins.open', new_callable=mock_open)
    @patch("output.saver.save_results_to_json")  
    @patch("json.dump")
    def test_save_results(self,
                        mock_json_dump: Mock,
                        mock_save_results_to_json: Mock,
                        mock_open_fn: Mock,
                        mock_makedirs: Mock):
        fake_now = datetime(2025, 6, 27, 15, 48)
        mock_save_results_to_json.return_value = {
            'scan_date': fake_now.strftime('%Y-%m-%d %H:%M'),
            'scanner_ip': '192.168.1.100',
            'target_ip': '8.8.8.8',
            'port_range': {
                'start': 20,
                'end': 29,
                'total_scanned': 10
            },
            'results': {
                'tcp4': {'open': [21], 'uncertain': [22], 'closed': [23, 24]},
                'udp4': {'open': [25], 'uncertain': [26], 'closed': [27, 28, 29]},
                'tcp6': {'open': [], 'uncertain': [], 'closed': []},
                'udp6': {'open': [], 'uncertain': [], 'closed': []}
            }
        }

        # Act
        save_results(self.scan_data, self.output_file)

        # Assert
        mock_open_fn.assert_called_once_with(self.output_file, "w")
        call_args = mock_json_dump.call_args
        args, kwargs = call_args
        self.assertEqual(kwargs["indent"], 4)
        self.assertEqual(kwargs["sort_keys"], True)
        self.assertEqual(args[1], mock_open_fn.return_value.__enter__.return_value)
        self.assertEqual(args[0], mock_save_results_to_json.return_value)
        mock_makedirs.assert_called_once_with(self.output_dir, exist_ok=True)
        mock_save_results_to_json.assert_called_once_with(self.scan_data)

    @patch('builtins.open', side_effect = PermissionError('Access denied'))
    def test_save_results_permission_error(self, mock_open_fn: Mock):
        with self.assertLogs('scanner', level='ERROR') as log:
            save_results(self.scan_data, self.output_file)
            mock_open_fn.assert_called_once_with(self.output_file, 'w')
            self.assertTrue(any("save results" in msg.lower() for msg in log.output))

if __name__ == "__main__":
    unittest.main()