import os, sys
import logging
from dotenv import load_dotenv
#
import src.utils as utils
from src.custom_exceptions import *

load_dotenv(dotenv_path=utils.get_absolute_dotenv_filepath(), override=True)

# Static variables
MIN_PORT_SCANNER_TIMEOUT_SEC:int = 5
AVAILABLE_NMAP_TIMING_TEMPLATES:list[str] = [f"T{i}" for i in range(0,6)]
DEFAULT_NMAP_TIMING_TEMPLATE:str = AVAILABLE_NMAP_TIMING_TEMPLATES[4]

# Load variables
HOSTS_CONFIG_FILEPATH:str|None = os.getenv('HOSTS_CONFIG_FILEPATH', None)
if not HOSTS_CONFIG_FILEPATH:
    raise MissingConfiguration("Missing hosts-config-filepath!")

try:
    requests_timeout_sec_:int = int(os.getenv('REQUESTS_TIMEOUT_SEC', 10))
except (ValueError, TypeError) as _e:
    raise InvalidConfiguration(f"Given requests-timeout value is not a valid INTEGER! '{_e}'")
REQUESTS_TIMEOUT_SEC:int = requests_timeout_sec_

NTFY_INSTANCE_TOPIC_URL:str|None = os.getenv('NTFY_INSTANCE_TOPIC_URL', None)
if not NTFY_INSTANCE_TOPIC_URL:
    raise MissingConfiguration("Missing NTFY topic URL!")

NTFY_INSTANCE_AUTH_TOKEN:str|None = os.getenv('NTFY_INSTANCE_AUTH_TOKEN', None)
if not NTFY_INSTANCE_AUTH_TOKEN:
    raise MissingConfiguration("Missing NTFY topic authentication token!")

NTFY_ALERT_INSTANCE_NAME:str = os.getenv('NTFY_ALERT_INSTANCE_NAME', 'PortWatcher<TestEnv>')

IGNORE_UNSAFE_SSL:bool = utils.get_bool_str(string=os.getenv('IGNORE_UNSAFE_SSL'), default=False)

LOG_LEVEL:str = os.getenv('LOG_LEVEL', 'DEBUG')

try:
    port_scanner_max_workers_:int = int(os.getenv('PORT_SCANNER_MAX_WORKERS', 2))
except (ValueError, TypeError) as _e:
    raise InvalidConfiguration(f"Given port-scanner-max-workers value is not a valid INTEGER! '{_e}'")
PORT_SCANNER_MAX_WORKERS:int = port_scanner_max_workers_

try:
    port_scanner_timeout_sec_:int = int(os.getenv('PORT_SCANNER_TIMEOUT_SEC', 120))
except (ValueError, TypeError) as _e:
    raise InvalidConfiguration(f"Given port-scanner timeout value is not a valid INTEGER! '{_e}'")
if port_scanner_timeout_sec_ < MIN_PORT_SCANNER_TIMEOUT_SEC:
    raise InvalidConfiguration(f"Given port-scanner timeout value is smaller than the allowed minimum of {MIN_PORT_SCANNER_TIMEOUT_SEC} seconds!")
PORT_SCANNER_TIMEOUT_SEC:int = port_scanner_timeout_sec_

PORT_SCANNER_NMAP_TIMING_TEMPLATE:str = os.getenv('PORT_SCANNER_NMAP_TIMING_TEMPLATE', DEFAULT_NMAP_TIMING_TEMPLATE)
if PORT_SCANNER_NMAP_TIMING_TEMPLATE.upper() not in AVAILABLE_NMAP_TIMING_TEMPLATES:
    raise InvalidConfiguration(f"Given port-scanner nmap-timing-template '{PORT_SCANNER_NMAP_TIMING_TEMPLATE}' does not exist!")

# Functions

def configure_logger() -> None:
    """
    Simple configuration of the `logging`-module for this project.
    """
    # Prevent adding multiple handlers if this function is called multiple times
    if logging.getLogger().handlers:
        return
    
    handlers:list[logging.StreamHandler] = [logging.StreamHandler(sys.stdout)]  # stdout

    #
    # ToDo: Validate `LOG_LEVEL` beforehand or raise an exception.
    #
    logging.basicConfig(
        level=LOG_LEVEL.upper(),
        format="(%(asctime)s) [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers
    )