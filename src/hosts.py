import json
import logging
from pathlib import Path
#
import src.utils as utils
from src.config import HOSTS_CONFIG_FILEPATH
from src.custom_exceptions import (InvalidHostsConfigFile, MissingHostsConfigurationKey)

logger = logging.getLogger(__name__)

def get_hosts_config() -> dict:
    """
    Get all hosts from the JSON-hosts-configuration-file.
    And check if the data-syntax is valid.
    """
    required_host_keys:dict = {
        'name': str,
        'host': str,
        'open-ports': list
    }
    
    data:dict = {}
    absolute_hosts_config_filepath:Path = utils.get_absolute_hosts_config_filepath(hosts_config_filepath=HOSTS_CONFIG_FILEPATH)
    
    # Load JSON
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
        logger.exception(f"An unexpected error occurred while reading '{absolute_hosts_config_filepath}'")
        raise InvalidHostsConfigFile(f"An unexpected error occurred while reading '{absolute_hosts_config_filepath}': {_e}")
    
    if not isinstance(data, dict):
        raise InvalidHostsConfigFile(f"Hosts configuration in '{absolute_hosts_config_filepath}' must be a JSON object, got '{type(data).__name__}'")
    
    if not isinstance(data, dict):
        raise InvalidHostsConfigFile(f"Hosts config must be a JSON object. Got {type(data).__name__}")
    
    logger.debug(f"Got hosts configuration from '{absolute_hosts_config_filepath}'")
    
    keys:list = list(required_host_keys.keys())
    
    # Validate data-syntax
    try:
        for host, host_data in data.items():
            if not isinstance(host, str):
                raise TypeError(f"'{host}' should be a {type(str).__name__}. Got '{type(host).__name__}'")
            
            if not isinstance(host_data, dict):
                raise TypeError(f"'{host_data}' should be a {type(dict).__name__}. Got '{type(host_data).__name__}'")

            # Check if any key is missing
            if not all([key in host_data for key in keys]):
                raise MissingHostsConfigurationKey(f"A required dict-key is missing in the host configuration of '{host}'")
            
            for key, expected_type in required_host_keys.items():
                # Check if data-types are correct
                if not isinstance(host_data[key], expected_type):
                    raise TypeError(f"'{host_data[key]}' should be a {expected_type.__name__}. Got '{type(host_data[key]).__name__}'")
                #
                # `isinstance(..., list[int])` is (probably) not valid in Python <3.12
                #
                if key == keys[2] and not all(isinstance(port, int) for port in host_data[key]):
                    raise TypeError("The host-ports should be an Integer.")
            
    except (TypeError, MissingHostsConfigurationKey) as _e:
        raise InvalidHostsConfigFile(f"Invalid Hosts configuration-syntax in '{absolute_hosts_config_filepath}': {_e}")
    
    return data