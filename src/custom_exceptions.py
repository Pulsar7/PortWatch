class ConfigError(Exception):
    """Base class for configuration-related exceptions."""
    pass

class MissingConfiguration(ConfigError):
    """Raised when a required configuration is missing."""
    pass

class InvalidConfiguration(ConfigError):
    """Raise when a configuration-value is invalid."""
    pass

class InvalidHostsConfigFile(Exception):
    """Raise when the hosts-data couldn't be read from the JSON-file."""
    pass