import unittest
import tempfile
import json
from common.models import ScanResults
from output.saver import save_results_to_json

#create a temporary file to save the results

class TestSaveResultsToJson(unittest.TestCase):
    """Test case for saving scan results to JSON format and writing to a temporary file."""
    def test_should_return_correct_json_structure_and_write_to_temp_file(self):
        # Arrange
        scan_results = ScanResults(
            args=None,
            user_ip = '192.168.1.218',
            target_ip = '8.8.8.8',
            start_port = 20,
            end_port = 25,
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
        result = save_results_to_json(scan_results)
        self.assertEqual(result["port_range"]["start"], 20)
        self.assertEqual(result["port_range"]["end"], 25)
        self.assertEqual(result["results"]["tcp4"]["open"], [22])
        self.assertEqual(result["results"]["tcp4"]["uncertain"], [23])
        self.assertEqual(result["results"]["tcp4"]["closed"], [21])
        self.assertEqual(result["results"]["udp4"]["closed"], [24, 25])
        

        # Assert
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', encoding='utf-8') as temp_file:
            json.dump(result, temp_file, indent=4)
            temp_file.seek(0)
            reloaded_data = json.load(temp_file)
            self.assertEqual(reloaded_data, result)
    
            
if __name__ == "__main__":
    unittest.main()
    