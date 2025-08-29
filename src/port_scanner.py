import time
import nmap
import queue
import logging
from concurrent.futures import ThreadPoolExecutor
#
from src.config import (PORT_SCANNER_MAX_WORKERS, PORT_SCANNER_TIMEOUT_SEC)

class PortScanner:
    """
    Handles the port-scanning.
    TCP & UDP.
    """
    def __init__(self, hosts:dict) -> None:
        self._hosts:dict = hosts
        self._max_workers:int = PORT_SCANNER_MAX_WORKERS
        self._timeout:int = PORT_SCANNER_TIMEOUT_SEC
        self.logger = logging.getLogger(__class__.__name__)
        self.alert_queue = queue.Queue()
        self._threads:list = []
        
    def scan_host(self, host_key:str, host_data:dict) -> None:
        """
        1. Scan all ports except for the given open-ports.
        2. Check if the list of given open-ports are actually open.
        """
        open_ports:list[int] = host_data['open-ports']
        host:str = host_data['host']
        self.logger.debug(f"Starting scan of host '{host_key}' ({host}). Open ports: {open_ports}")
        
        nm = nmap.PortScanner()
        required_open_ports:set[int] = set(host_data["open-ports"])
        all_ports:set[int] = set(range(1, 65536))
        ports_str:str = "1-65535"
        ports_to_scan:list[int] = sorted(all_ports)
        
        # Scan unknown ports
        self.logger.debug(f"Scanning for {len(ports_to_scan)} ports at '{host}'")
        
        try:
            scan_result = nm.scan(
                hosts=host,
                ports=ports_str,
                arguments=f"-sT -Pn -T4 --host-timeout {self._timeout}s"
            )
            self.logger.debug("Executed command '%s'", scan_result["nmap"]["command_line"])
            for port in ports_to_scan:
                try:
                    state = scan_result["scan"][host]["tcp"][port]["state"]
                    if state == "open" and port not in required_open_ports:
                        alert_msg = f"Unexpected open port {port} on {host} ({host_data['name']})"
                        self.alert_queue.put(alert_msg)
                        self.logger.debug(f"Alert queued '{alert_msg}'")
                    elif state != "open" and port in required_open_ports:
                        alert_msg = f"Unexpected closed port {port} on {host} ({host_data['name']}). Expected an open port."
                        self.alert_queue.put(alert_msg)
                        self.logger.debug(f"Alert queued '{alert_msg}'")
                except KeyError:
                    pass # port not reported by nmap
        except nmap.PortScannerError:
            self.logger.exception(f"A port-scanning-error occured while scanning '{host}'")
        except Exception:
            self.logger.exception(f"An unexpected error occured while scanning '{host}'")
        
        self.logger.debug(f"Scanned all ports at '{host}'")
        
    def start_scan(self) -> None:
        """
        Scan all hosts.
        """
        _start:float = time.time()
        self.logger.debug(f"Starting scan of {len(self._hosts.keys())} hosts")
        
        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            # Submit tasks for all hosts
            futures:list = [
                executor.submit(self.scan_host, host_key, host_data)
                for host_key, host_data in self._hosts.items()
            ]

            # Optional: handle exceptions in worker threads
            for future in futures:
                try:
                    future.result()  # raises exception if worker failed
                except Exception:
                    self.logger.exception("Scanning task failed")
        
        self.logger.info(f"Stopped scan (Runtime={time.time()-_start} seconds).")