import time
import queue
import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor
#
from src.custom_exceptions import (NmapScanError, MissingNmapScanReport,
                                   NmapScanReportXMLParsingError)
from src.scan_constants import (PortScanMode, ScanModeEnum,
                                PortState, PortScanData, ScanResult)
from src.config import (PORT_SCANNER_MAX_WORKERS, PORT_SCANNER_TIMEOUT_SEC,
                        PORT_SCANNER_NMAP_TIMING_TEMPLATE,
                        AVAILABLE_NMAP_TIMING_TEMPLATES,
                        PORT_SCAN_CHUNK_THRESHOLD,
                        PORT_SCAN_MODE)
from src.utils import parse_nmap_xml

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
    
    def run_nmap(self, host:str, ports:str, arguments:str) -> bytes:
        """
        Run nmap CLI tool via subprocess.
        
        Raises:
            NmapScanError: If anything went wrong while scanning
        
        Returns:
            bytes: STDOUT of nmap-scan.
        """
        #
        # Parameters `-oX` and `-` to get XML output from nmap
        #
        command:list[str] = ["nmap", "-oX", "-", "-p", ports]
        # Add scanning-parameters (e.g. scan-mode, timing-template, etc.)
        command.extend(arguments.strip().split())
        # Add host
        command.extend([host])
        
        try:
            # TODO: Add timeout?
            result = subprocess.run(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                check=False
            )
            stdout, stderr = result.stdout, result.stderr
            
            if stderr:
                self.logger.warning(f"[host={host}] Nmap stderr: {stderr.decode('utf-8')}")
        
        except subprocess.SubprocessError as _e:
            raise NmapScanError("SubprocessError occured") from _e
        
        except subprocess.TimeoutExpired as _e:
            raise NmapScanError("Timeout expired while waiting for a child process.") from _e
        
        except Exception as _e:
            raise NmapScanError("Unexpected error occured while executing nmap-scan-command") from _e
        
        return stdout
    
    def get_scan_results(self, host:str, ports_str:str) -> ScanResult:
        """
        Get scan results from nmap.
        
        Raises:
            NmapScanError: When an error occured while port-scanning.
            NmapScanReportXMLParsingError: When parsing the stdout of nmap couldn't be parsed.
            
        Returns:
            PortScanResult: A dataclass-object containing the scanning-results
        """
        try:
            stdout:bytes = self.run_nmap(
                host=host,
                ports=ports_str,
                arguments=f"-sT -Pn -{self._port_scanner_nmap_timing_template} --host-timeout {self._timeout}s"
            )
        except NmapScanError as _e:
            raise NmapScanError("A port-scanning-error occured while scanning") from _e
        
        except Exception as _e:
            raise NmapScanError("An unexpected error occured") from _e
        
        # Get scan-result-object
        try:
            stdout_str:str = stdout.decode("utf-8")
        except UnicodeDecodeError as _e:
            raise NmapScanReportXMLParsingError("Failed to decode nmap output") from _e
        
        try:
            scan_result:ScanResult = parse_nmap_xml(xml_data=stdout_str)
        except NmapScanReportXMLParsingError as _e:
            raise NmapScanReportXMLParsingError("Couldn't get scan-result-object!") from _e
        
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
                    scan_result:ScanResult = self.get_scan_results(host=host, ports_str=ports_str)
                except (NmapScanError, NmapScanReportXMLParsingError) as _e:
                    raise MissingNmapScanReport(f"[chunk-number={chunk_number}] A nmap-scan error occured while scanning '{host}'") from _e
                
                scan_results.append(scan_result)
        
        else:
            if self._port_scan_mode.name == ScanModeEnum.TOP_100:
                ports_str:str = ",".join(map(str, ports_to_scan))
                
            elif self._port_scan_mode.name == ScanModeEnum.ALL:
                # ALL (using `range` for nmap)
                ports_str:str = f"1-{self._port_scan_mode.ports_amount}"
            try:
                scan_result:ScanResult = self.get_scan_results(host=host, ports_str=ports_str)
            except (NmapScanError, NmapScanReportXMLParsingError) as _e:
                self.logger.exception(f"A nmap-scan error occured while scanning '{host}'")
                raise MissingNmapScanReport("Scan failed. No scan-results from nmap available!") from _e

            scan_results.append(scan_result)
        
        # Add alerts to queue (if any unexpected port-state has been found)
        
        port_map:dict[int, PortScanData] = {}
        
        # Fill port-map with ports with report
        for scan_result in scan_results:
            for _p in scan_result.ports:
                port_map[_p.port] = _p
        
        missing_ports = [p for p in ports_to_scan if p not in port_map]
        if missing_ports:
            self.logger.debug(f"[{host}] {len(missing_ports)} ports not in Nmap XML")
        
        # Iterate all ports
        for port in ports_to_scan:
            if port not in port_map:
                # Assuming port is closed/unknown, because nmap didn't report port
                state = PortState.CLOSED
                service = "unknown"
            else:
                state = port_map[port].state
                service = port_map[port].service_name
            
            # Check if port is open
            if state == PortState.OPEN:
                # Found open port
                # Check if it should be open
                if port not in required_open_ports:
                    # Unexpected open port found
                    self.logger.warning(f"[{host}] Found unexpected open port {port}")
                    self.alert_queue.put(f"Unexpected open port {port} on {host} ({host_data['name']}). service-name={service}")
                    continue
            
            # Check if port is closed/filtered
            # or use just `else` ^^
            elif state != PortState.OPEN:
                # Found port that seems to be closed for filtered
                # Check if it should be open
                if port in required_open_ports:
                    # Unexpected closed/filtered port found
                    self.logger.warning(f"[{host}] Found unexpected {state.value} port {port}. Expected port to be open!")
                    self.alert_queue.put(f"Unexpected {state.value} port {port} on {host} ({host_data['name']}). Expected port to be open. port-state={state.value}")
                    continue
        
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