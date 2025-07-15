from core.config import logger
from common.models import ScanResults
from pipeline.pipeline import execute_full_scan, process_results, get_local_ip
from cli import get_args
from typing import Any
from core.preconditions import validate_args
from typing import Optional

def safe_execute_scan (args:Any) -> Optional[ScanResults]:
    try:
        user_ip = get_local_ip()
        return execute_full_scan(args, user_ip)
    except PermissionError:
        logger.error("Permission denied. Try running with elevated privileges.")
    except Exception as e:
        logger.critical(f"Unexpected error during scanning: {e}", exc_info=True)
        return None

def main():
    """Main entry point for the port scanner application."""
    logger.info("Starting scan...")

    try:
        args = get_args()
        validate_args(args)
    except ValueError as e:
        logger.error(f"Invalid input: {e}")
        return
    except Exception as e:
        logger.critical(f"Unexpected error during argument parsing: {e}", exc_info=True)
        return

    scan_results = safe_execute_scan(args)
    
    if not scan_results:
        logger.warning("No results to process. Scan may have failed.")
        return

    logger.info("Scan completed successfully. Results will be saved or displayed.")

    try:
        process_results(scan_results)
    except Exception as e:
        logger.error(f"Failed to process or save results: {e}", exc_info=True)

if __name__ == "__main__":
    main()
