"""

    PortWatch
    
    # Description: A simple port-scanner that's scanning for unusual open-ports on certain services
                   and sends out an alert to a given NTFY-instance.
    
    # Python-Version: 3.10.12
    # Author: Pulsar
    # v1

"""
import sys
import time
import logging
import traceback
#
import src.utils as utils
from src.alert_handler import NTFYAlertHandler
import src.custom_exceptions as custom_exceptions

def main() -> None:
    _start:float = time.time()
    
    config.configure_logger()
    logger = logging.getLogger(__name__)
    
    logger.debug(f"Started at {_start}")
    
    alert_handler = NTFYAlertHandler()
    if not alert_handler.test_ntfy():
        logger.critical("Cannot proceed without an alert manager!")
        sys.exit(1)
    
    
   
    logger.info(f"Closed. (Runtime={time.time()-_start})")


if __name__ == '__main__':
    try:
        import src.config as config
    except custom_exceptions.MissingConfiguration as _e:
        logging.basicConfig(
            level=logging.ERROR,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )
        logging.error(f"Configuration error: {_e} | Using '{utils.get_absolute_dotenv_filepath()}'")
        logging.error(f"{traceback.format_exc()}")
        sys.exit(1) # Exit immediately if configuration is invalid
    main()