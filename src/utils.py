import pytz
import shutil
import logging
from pathlib import Path
from datetime import datetime
import xml.etree.ElementTree as ET
#
from src.scan_constants import PortState, PortScanData, ScanResult
from src.custom_exceptions import NmapScanReportXMLParsingError

logger = logging.getLogger(__name__)

def get_absolute_dotenv_filepath() -> Path:
    """
    Get absolute filepath of the dotenv-file.
    """
    
    return Path(__file__).resolve().parent.parent / ".env"

def get_absolute_hosts_config_filepath(hosts_config_filepath:str) -> Path:
    """
    Get absolute filepath of the JSON-hosts-file.
    """
    
    return Path(__file__).resolve().parent.parent / hosts_config_filepath

def get_bool_str(string:str|None, default:bool=False) -> bool:
    """
    Get boolean from string.
    - Interprets '1', 'true', 'on' as `True` (case-insensitive)
    
    - Interprets '0', 'false', 'off' as `False` (case-insensitive)
    
    - Returns `default` if not set or invalid.
    """
    
    if not string:
        return default
    
    val:str = string.lower().strip()
    
    if val in ['1', 'true', 'on']:
        return True
    
    if val in ['0', 'false', 'off']:
        return False
    
    return default
    
def check_nmap_in_path() -> bool:
    """
    Check if `nmap` is installed in PATH.
    """
    return shutil.which("nmap") is not None

def parse_nmap_xml(xml_data:str) -> ScanResult:
    """
    Parse nmap XML output into a `ScanResult`-object.
    
    Raises:
        NmapScanReportXMLParsingError: If parsing the XML-output of nmap failed.
        
    Returns:
        ScanResult: The scan-results of all ports at a given host.
    """
    root = ET.fromstring(xml_data)

    # Get host
    hosts:list = root.findall("host")
    if not len(hosts):
        raise NmapScanReportXMLParsingError("No data available!")

    host = hosts[0]
    if not host:
        raise NmapScanReportXMLParsingError("Couldn't find host in XML-Data!")
    
    host_addr:str = host.find("address").attrib.get("addr")
    if not host_addr:
        logger.warning(f"Got host-data: '{hosts}'")
        raise NmapScanReportXMLParsingError("Couldn't find host-address in XML-data!")
    
    #
    # Get '<port>' and '<extraports>' elements
    #
    ports:list = host.findall(".//port")
    extraports:list = host.findall(".//extraports")
    ports_data:list[PortScanData] = []
    if ports:
        # Parse ports-data
        try:
            for port in ports:
                try:
                    portid = int(port.attrib["portid"])
                except TypeError as _e:
                    raise NmapScanReportXMLParsingError("Parsed port-id is invalid!") from _e
                
                except ValueError as _e:
                    raise NmapScanReportXMLParsingError("Couldn't parse port-id from XML-data!") from _e
                
                state_elem = port.find("state")
                state_str = state_elem.attrib.get("state") if state_elem != None else None
                
                if not state_str:
                    logger.warning(f"[host={host_addr}] No state found for port '{portid}'")
                    state:PortState = PortState.UNKNOWN
                else:
                    try:
                        state:PortState = PortState(state_str)
                    except ValueError:
                        logger.warning(f"[host={host_addr}] Parsed unknown port-state '{state_str}' for port '{portid}'")
                        state:PortState = PortState.UNKNOWN
                
                service_elem = port.find("service")
                service = service_elem.attrib.get("name", "unknown") if service_elem != None else "unknown"
                
                ports_data.append(
                    PortScanData(service_name=service, state=state, port=portid)
                )
        except KeyError as _e:
            raise NmapScanReportXMLParsingError("Got invalid XML-data from nmap!") from _e
        
        except NmapScanReportXMLParsingError:
            raise
        
        except Exception as _e:
            raise NmapScanReportXMLParsingError("Unexpected error occured") from _e
    else:
        # Not worth a warning, right?
        logger.debug("Didn't find any '<ports>'-element in XML-data.")
    
    if extraports:
        #
        # Check for extra-ports.
        #
        #
        # Get ports that have been scanned
        #
        scaninfo_element = root.find("scaninfo")
        if scaninfo_element is None:
            raise NmapScanReportXMLParsingError("Couldn't find scan-info in XML-data!")
        scaninfo_services = scaninfo_element.attrib.get("services")
        if not scaninfo_services:
            raise NmapScanReportXMLParsingError("Couldn't find scan-info-services in XML-data!")
        
        scanned_ports:list[int] = []
        for port_str in scaninfo_services.split(","):
            port_str = port_str.strip()
            if "-" in port_str:
                args:list[str] = port_str.split("-")
                try:
                    port_begin:int = int(args[0])
                    port_end:int = int(args[1])
                except (ValueError, TypeError) as _e:
                    # TODO: Improve log description here
                    raise NmapScanReportXMLParsingError("Invalid scan-info-services ports list in XML-data!") from _e
                
                scanned_ports.extend(range(port_begin, port_end + 1))
            else:
                try:
                    port:int = int(port_str)
                except (ValueError, TypeError) as _e:
                    # TODO: Improve log description here
                    raise NmapScanReportXMLParsingError("Invalid scan-info-services ports list in XML-data!") from _e
                
                scanned_ports.append(port)
        
        for extraport in extraports:
            if extraport is not None: # Shouldn't be false in any case, right?
                state_str = extraport.attrib.get("state")
                if state_str is None:
                    # TODO: Log required?
                    #logger.warning(f"[host={host_addr}] No state found")
                    port_state:PortState = PortState.UNKNOWN
                else:
                    try:
                        port_state:PortState = PortState(state_str)
                    except ValueError:
                        # TODO: Log required?
                        #logger.warning(f"[host={host_addr}] Parsed unknown port-state '{state_str}'")
                        port_state:PortState = PortState.UNKNOWN
                #reason_elem = extraport.find("extrareasons")
                #reason = reason_elem.attrib.get("reason") if reason_elem is not None else "unknown"
                count = int(extraport.attrib.get("count", "0"))

                if count == len(scanned_ports):
                    # All ports have the same port-state
                    logger.debug(f"All {count} ports have the port-state '{state_str}'")

                if port_state == PortState.CLOSED:
                    #
                    # Closed ports are just ignored/empty
                    #
                    continue
            
                for port in scanned_ports:
                    ports_data.append(
                        PortScanData(service_name="unknown", 
                                     state=port_state, 
                                     port=port)
                        )
    else:
        # Not worth a warning, right?
        logger.debug("Didn't find any '<extraports>'-element in XML-data.")
        if not ports:
            logger.warning("Neither found any '<ports>' element, nor any '<extraports>' element!")
            raise NmapScanReportXMLParsingError("Couldn't find ports in XML-data!")
    
    
    return ScanResult(host=host_addr, ports=ports_data)

def get_current_timestamp(timezone:str="UTC") -> str:
    """
    Get current timestamp in ISO8601 format.
    
    If an invalid timezone is given, the fallback timezone `UTC` is being used.
    """
    try:
        timestamp:str = datetime.now(pytz.timezone(timezone)).isoformat()
    except pytz.UnknownTimeZoneError:
        logger.exception(f"Given timezone '{timezone}' is invalid!")
        logger.warning("Using fallback timezone UTC")
        timestamp:str = datetime.now(pytz.timezone("UTC")).isoformat()
    
    return timestamp