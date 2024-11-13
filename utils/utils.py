import logging

logging.basicConfig(
    filename='firewall.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_action(action, details):
    logging.info(f"{action}: {details}")
