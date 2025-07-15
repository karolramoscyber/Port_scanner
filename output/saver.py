import json   # Handles output formatting: console reporting and saving results as JSON
import os    # For creating directories if they do not exist
from core.formatting import save_results_to_json
from common.models import ScanResults
from core.config import logger


def save_results(scan_data: ScanResults, output_file: str = "output/scan_result.json") -> None:
    """
    Saves the scan results to a JSON file.
    """
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    try:
        result_dict = save_results_to_json (scan_data) 
        with open(output_file, "w") as file:
            json.dump(result_dict, file, indent=4, sort_keys=True)
            logger.info(f"Results for {scan_data.args.ip} ({scan_data.args.start_port}–{scan_data.args.end_port}) saved to {output_file}")
    except (OSError, PermissionError) as e:
        logger.error(f"Could not save results to {output_file}: {e}")
        logger.debug("Full stack trace:", exc_info=True)
