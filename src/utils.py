import logging
from pathlib import Path

logger = logging.getLogger(__name__)

def get_absolute_dotenv_filepath() -> Path:
    """
    Get absolute filepath of the dotenv-file.
    """
    
    return Path(__file__).resolve().parent.parent / ".env"

def get_absolute_hosts_config_filepath(hosts_config_filepath:str) -> Path:
    """
    Get absolute filepath of the JSON-hosts-file.
    """
    
    return Path(__file__).resolve().parent.parent / hosts_config_filepath