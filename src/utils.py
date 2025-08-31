import shutil
import logging
from pathlib import Path
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
    
    # Get ports
    ports:list = host.findall(".//port")
    if not ports:
        logger.warning(f"Got host-data: '{hosts}'")
        raise NmapScanReportXMLParsingError("Couldn't find ports in XML-data!")
    
    # Parse ports-data
    ports_data:list[PortScanData] = []

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
                print(ET.tostring(state_elem, encoding="unicode"))
                print(ET.tostring(port, encoding="unicode"))
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
    
    return ScanResult(host=host_addr, ports=ports_data)