import logging
import requests
#
from src.config import (NTFY_INSTANCE_TOPIC_URL,
                        NTFY_INSTANCE_AUTH_TOKEN,
                        NTFY_ALERT_INSTANCE_NAME,
                        REQUESTS_TIMEOUT_SEC,
                        IGNORE_UNSAFE_SSL)

class AlertHandler:
    """
    Parent class to handle alerts.
    """
    def __init__(self):
        pass
    

class NTFYAlertHandler(AlertHandler):
    """
    Handles specifically NTFY alerts.
    """
    def __init__(self):
        super().__init__()
        #
        self._ntfy_instance_topic_url:str  = NTFY_INSTANCE_TOPIC_URL
        self._ntfy_instance_auth_token:str = NTFY_INSTANCE_AUTH_TOKEN
        self._ntfy_alert_instance_name:str = NTFY_ALERT_INSTANCE_NAME
        self._requests_timeout:int         = REQUESTS_TIMEOUT_SEC
        self._ignore_unsafe_ssl:bool       = IGNORE_UNSAFE_SSL
        #
        self.logger = logging.getLogger(__class__.__name__)
    
    @property
    def ntfy_instance_topic_url(self) -> str:
        """URL to the NTFY topic."""
        return self._ntfy_instance_topic_url
    
    @property
    def ntfy_instance_auth_token(self) -> str:
        """Authentication Token for the NTFY topic."""
        return self._ntfy_instance_auth_token
    
    @property
    def ntfy_alert_instance_name(self) -> str:
        """Title of this alert-manager."""
        return self._ntfy_alert_instance_name

    @property
    def requests_timeout(self) -> int:
        """Timeout in seconds for HTTP-requests."""
        return self._requests_timeout
    
    @property
    def ntfy_headers(self) -> dict[str, str]:
        """Build NTFY HTTP-headers."""
        return {'Authorization': f"Bearer {self._ntfy_instance_auth_token}"}
    
    @property
    def ignore_unsafe_ssl(self) -> bool:
        """If SSL-certificate-verification gets ignored by requests or not."""
        return self._ignore_unsafe_ssl
    
    def test_ntfy(self) -> bool:
        """
        Test given NTFY configuration by sending a HTTP-GET request.
        """
        self.logger.debug("Testing NTFY configuration")
        
        if self._ignore_unsafe_ssl:
            self.logger.warning("Accepting unsafe SSL-certificates!")
        
        try:
            response = requests.get(url=self._ntfy_instance_topic_url,
                                    headers=self.ntfy_headers,
                                    timeout=self._requests_timeout,
                                    verify=not self._ignore_unsafe_ssl)
        except requests.exceptions.RequestException:
            self.logger.exception(f"Failed to connect to NTFY topic '{self._ntfy_instance_topic_url}'")
            return False
        
        if not (200 <= response.status_code < 300):
            self.logger.error(f"Got invalid HTTP-status-code from '{self._ntfy_instance_topic_url}': {response.status_code}")
            return False
        
        self.logger.debug("Finished testing the NTFY configuration")
        return True
    
    def send_out_alert(self, title:str, text:str, priority:str, tags:str) -> bool:
        """Send alert via HTTP-Post request to the given NTFY-instance."""
        
        if self._ignore_unsafe_ssl:
            self.logger.warning("Accepting unsafe SSL-certificates!")
        
        headers:dict = self.ntfy_headers
        headers['Title'] = title
        headers['Priority'] = priority
        headers['Tags'] = tags
        
        try:
            response = requests.post(url=self._ntfy_instance_topic_url,
                                    headers=headers,
                                    timeout=self._requests_timeout,
                                    data=text,
                                    verify=self._ignore_unsafe_ssl)
        except requests.exceptions.RequestException:
            self.logger.exception(f"Failed to connect to NTFY topic '{self._ntfy_instance_topic_url}'")
            return False
        
        if not (200 <= response.status_code < 300):
            self.logger.error(f"Got invalid HTTP-status-code from '{self._ntfy_instance_topic_url}': {response.status_code}")
            return False
        
        self.logger.info(f"Sent out alert to '{self._ntfy_instance_topic_url}' with title '{title}'")
        return True
        