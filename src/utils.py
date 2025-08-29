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

def get_bool_str(string:str|None, default:bool=False) -> bool:
    """
    Get boolean from string.
    - Interprets '1', 'true', 'on' as `True` (case-insensitive)
    
    - Interprets '0', 'false', 'off' as `False` (case-insensitive)
    
    - Returns `default` if not set or invalid.
    """
    
    if not string:
        return default
    
    val:str = string.lower().strip()
    
    if val in ['1', 'true', 'on']:
        return True
    
    if val in ['0', 'false', 'off']:
        return False
    
    return default
    