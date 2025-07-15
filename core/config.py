import os
import logging

# Ensure 'logs' directory exists
os.makedirs("logs", exist_ok=True)

DEFAULT_TIMEOUT = 5.0

# Create logger
logger = logging.getLogger('scanner')
logger.setLevel(logging.DEBUG)

# File handler
scanner_log = logging.FileHandler("logs/scanner.log", mode="w")
scanner_log.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

# Stream handler
ch = logging.StreamHandler()
ch.setLevel(logging.ERROR)
ch.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

#Before adding handlers, check if they’re already present

if not logger.handlers:
    logger.addHandler(scanner_log)
    logger.addHandler(ch)

