import json
import logging
from pathlib import Path
#
import src.utils as utils
from src.config import HOSTS_CONFIG_FILEPATH
from src.custom_exceptions import InvalidHostsConfigFile

logger = logging.getLogger(__name__)

def get_hosts_config() -> dict:
    """
    Get all hosts from the JSON-hosts-configuration-file.
    """
    
    data:dict = {}
    absolute_hosts_config_filepath:Path = utils.get_absolute_hosts_config_filepath(hosts_config_filepath=HOSTS_CONFIG_FILEPATH)
    
    try:
        with absolute_hosts_config_filepath.open('r', encoding="utf-8") as json_file:
            data = json.load(json_file)
    except FileNotFoundError as _e:
        logger.exception(f"Filepath '{absolute_hosts_config_filepath}' does not exist")
        raise InvalidHostsConfigFile(f"Filepath '{absolute_hosts_config_filepath}' does not exist: {_e}")
    
    except json.JSONDecodeError as _e:
        logger.exception(f"Invalid JSON in '{absolute_hosts_config_filepath}'")
        raise InvalidHostsConfigFile(f"Invalid JSON in '{absolute_hosts_config_filepath}': {_e}")
    
    except Exception as _e:
        logger.exception(f"An unexpected error occured while reading '{absolute_hosts_config_filepath}'")
        raise InvalidHostsConfigFile(f"An unexpected error occured while reading '{absolute_hosts_config_filepath}': {_e}")
    
    if not isinstance(data, dict):
        raise InvalidHostsConfigFile(f"Hosts configuration in '{absolute_hosts_config_filepath}' must be a JSON object, got '{type(data).__name__}'")
    
    logger.debug(f"Got hosts configuration from '{absolute_hosts_config_filepath}'")
    
    return data