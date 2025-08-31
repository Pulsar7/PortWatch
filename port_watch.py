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
import src.hosts as hosts
from src.port_scanner import PortScanner
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
    
    try:
        hosts_data:dict = hosts.get_hosts_config()
    except custom_exceptions.InvalidHostsConfigFile:
        logger.exception("Couldn't get hosts")
        logger.critical("Cannot proceed without the hosts configurations!")
        sys.exit(1)

    if not utils.check_nmap_in_path():
        logger.critical("It looks like `nmap` is not installed at the PATH. Cannot operate without `nmap`")
        sys.exit(1)
    
    # Start port-scan
    port_scanner = PortScanner(hosts=hosts_data)
    port_scanner.start_scan()
    
    # Send out alerts (if any)
    if port_scanner.alert_queue.empty():
        logger.info("Nothing to report. Alert queue is empty.")
        sys.exit(0)
    
    alert_msg:str = ""
    
    while not port_scanner.alert_queue.empty():
        alert_msg += port_scanner.alert_queue.get()+"\n"
    
    alert_msg += f"\n<{config.NTFY_ALERT_INSTANCE_NAME}/{utils.get_current_timestamp()}>"
    
    if not alert_handler.send_out_alert(title="Port-Scan Report", text=alert_msg,
                                priority="urgent", tags="warning"):
        logger.critical("Couldn't send out alert!")
   
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