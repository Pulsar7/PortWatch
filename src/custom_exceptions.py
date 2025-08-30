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
    """Raise when the hosts-data couldn't be read or invalid JSON-Syntax is being used."""
    pass

class MissingHostsConfigurationKey(InvalidHostsConfigFile):
    """Raise when a JSON-configuration-key is missing."""
    pass

class MissingNmapScanReport(Exception):
    """Raise when nmap doesn't return any scan-reports."""
    pass