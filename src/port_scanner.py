import time
import nmap
import queue
import logging
from concurrent.futures import ThreadPoolExecutor
#
from src.custom_exceptions import NmapScanError, MissingNmapScanReport
from src.scan_modes import PortScanMode
from src.config import (PORT_SCANNER_MAX_WORKERS, PORT_SCANNER_TIMEOUT_SEC,
                        PORT_SCANNER_NMAP_TIMING_TEMPLATE,
                        AVAILABLE_NMAP_TIMING_TEMPLATES,
                        PORT_SCAN_CHUNK_THRESHOLD,
                        PORT_SCAN_MODE)

class PortScanner:
    """
    Handles the port-scanning.
    TCP `Connect()` (TCP Connect Scan)
    """
    def __init__(self, hosts:dict) -> None:
        self._hosts:dict = hosts
        self._max_workers:int                       = PORT_SCANNER_MAX_WORKERS
        self._timeout:int                           = PORT_SCANNER_TIMEOUT_SEC
        self._port_scanner_nmap_timing_template:str = PORT_SCANNER_NMAP_TIMING_TEMPLATE
        self._port_scan_mode:PortScanMode           = PORT_SCAN_MODE
        self.logger = logging.getLogger(__class__.__name__)
        self.alert_queue = queue.Queue()
        self._threads:list = []
    
    def get_scan_results(self, host:str, ports_str:str):
        """
        Get scan results from nmap.
        
        Raises:
            NmapScanError: When an error occured while port-scanning.
        """
        nm = nmap.PortScanner()
        try:
            scan_result = nm.scan(
                hosts=host,
                ports=ports_str,
                arguments=f"-sT -Pn -{self._port_scanner_nmap_timing_template} --host-timeout {self._timeout}s"
            )
            
            #
            # Too noisy
            #
            #self.logger.debug("Executed command '%s'", scan_result["nmap"]["command_line"])
        
        except nmap.PortScannerError as _e:
            raise NmapScanError("A port-scanning-error occured while scanning") from _e
        
        except Exception as _e:
            raise NmapScanError("An unexpected error occured") from _e
        
        return scan_result
            
    
    def scan_host(self, host_key:str, host_data:dict) -> None:
        """
        Scan all ports except for the given open-ports.
        Check if the list of given open-ports are actually open.
        
        Raises:
            MissingNmapScanReport: When nmap didn't return any scan-report.
        """
        open_ports:list[int] = host_data['open-ports']
        host:str = host_data['host']
        self.logger.debug(f"Starting scan of host '{host_key}' ({host}). Open ports: {open_ports}")
        
        # Get list of required-open-ports
        required_open_ports:set[int] = set(host_data["open-ports"])
        # Get all ports that shall be scanned by the scan-mode
        all_ports:set[int] = set(self._port_scan_mode.ports_list)
        # Merge sets to include all ports + required ports, no duplicates
        ports_to_scan:list[int] = sorted(all_ports | required_open_ports)
        amount_of_ports_to_scan:int = len(ports_to_scan)
        
        # Perform scans
        self.logger.debug(f"Scanning for {amount_of_ports_to_scan} ports at '{host}'")
        
        scan_results:list = []
        
        if amount_of_ports_to_scan > PORT_SCAN_CHUNK_THRESHOLD:
            self.logger.warning(f"Scanning ports in chunks, because the amount of ports that need to be scanned exceeds the threshold of {PORT_SCAN_CHUNK_THRESHOLD} ports")
            chunk_size:int = PORT_SCAN_CHUNK_THRESHOLD
            chunk_number:int = 0
            for i in range(0, amount_of_ports_to_scan, chunk_size):
                chunk = ports_to_scan[i:(i+chunk_size)]
                chunk_number += 1
                ports_str = ",".join(map(str, chunk))
                
                #
                # Too noisy
                #
                #self.logger.debug(f"[host={host}] [chunk-number={chunk_number}] current chunk-size (ports to scan)={len(chunk)}")
                
                try:
                    scan_result = self.get_scan_results(host=host, ports_str=ports_str)
                    # Check if any TCP scan-results are in the dictionary
                    #
                    # This can happen, when the `--host-timeout` is too low 
                    # or the given host is not reachable at all.
                    #
                    # !!! Current thoughts about this: When scanning the last 100 ports of ~3000 for example,
                    # all scan-reports will be thrown away, because the exception gets raised.
                    # ToDo: Fix that? Or shouldn't it continue when scan-reports are missing?
                    #
                    #
                    if not scan_result["scan"].get(host, None):
                        # No nmap-scan-report available!
                        raise MissingNmapScanReport(f"nmap didn't return any scan-results for host!")
                    
                except NmapScanError as _e:
                    raise MissingNmapScanReport(f"[chunk-number={chunk_number}] A nmap-scan error occured while scanning '{host}'") from _e
                
                scan_results.append(scan_result)
        
        else:
            try:
                scan_result = self.get_scan_results(host=host, ports_str=ports_str)
            except NmapScanError as _e:
                self.logger.exception(f"A nmap-scan error occured while scanning '{host}'")
                raise MissingNmapScanReport("Scan failed. No scan-results from nmap available!") from _e

            # Check if any TCP scan-results are in the dictionary
            #
            # This can happen, when the `--host-timeout` is too low 
            # or the given host is not reachable at all.
            #
            if not scan_result["scan"].get(host, None):
                # No nmap-scan-report available!
                raise MissingNmapScanReport(f"nmap didn't return any scan-results for host!")

            scan_results.append(scan_result)
        
        # Add alerts to queue (if any unexpected port-state has been found)
        reported_ports:list[int] = []
        for scan_result in scan_results:
            for port in ports_to_scan:
                try:
                    state = scan_result["scan"][host]["tcp"][port]["state"]

                    if state == "open" and port not in required_open_ports and port not in reported_ports:
                        alert_msg = f"Unexpected open port {port} on {host} ({host_data['name']})"
                        self.alert_queue.put(alert_msg)
                        self.logger.debug(f"Alert queued '{alert_msg}'")
                        reported_ports.append(port)
                        
                except KeyError:
                    # port not reported by nmap
                    if port in required_open_ports and port not in reported_ports:
                        alert_msg = f"Unexpected closed port {port} on {host} ({host_data['name']}). Expected an open port."
                        self.alert_queue.put(alert_msg)
                        self.logger.debug(f"Alert queued '{alert_msg}'")
                        reported_ports.append(port)
        
        self.logger.debug(f"Scanned all ports at '{host}'")
        
    def start_scan(self) -> None:
        """
        Scan all hosts.
        """
        _start:float = time.time()
        self.logger.debug(f"Starting scan of {len(self._hosts.keys())} hosts.")
        
        if self._port_scanner_nmap_timing_template == AVAILABLE_NMAP_TIMING_TEMPLATES[0]:
            self.logger.warning("Using a very cautious but slow nmap-timing-template!")
        
        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            # Submit tasks for all hosts
            futures:list = [
                executor.submit(self.scan_host, host_key, host_data)
                for host_key, host_data in self._hosts.items()
            ]

            # Handle exceptions in worker threads
            for future in futures:
                try:
                    future.result()  # raises exception if worker failed
                except MissingNmapScanReport:
                    self.logger.exception("Scan task failed")
                except Exception:
                    self.logger.exception("An unexpected error occured while scanning")
        
        self.logger.info(f"Stopped all scans (Runtime={time.time()-_start} seconds).")