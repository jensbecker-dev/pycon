# Port scanning and service enumeration tool
import socket
import threading
import argparse
from queue import Queue, Empty
from termcolor import cprint, colored
import os
import sys
from typing import List, Dict, Any, Optional, Set, Union
import tqdm
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.progress import Progress

# Global constants
DEFAULT_TIMEOUT = 1.0
COMMON_SERVICES = {
    # System Services
    1: "TCPMUX",
    7: "ECHO",
    9: "DISCARD",
    11: "SYSTAT",
    13: "DAYTIME",
    17: "QOTD",
    19: "CHARGEN",
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    37: "TIME",
    43: "WHOIS",
    49: "TACACS",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    70: "Gopher",
    79: "Finger",
    80: "HTTP",
    81: "TorPark",
    82: "TorPark",
    88: "Kerberos",
    101: "HOSTNAME",
    102: "ISO-TSAP",
    105: "CCSO",
    107: "RTelnet",
    109: "POP2",
    110: "POP3",
    111: "RPCbind",
    113: "IDENT",
    115: "SFTP",
    117: "UUCP-PATH",
    119: "NNTP",
    123: "NTP",
    135: "MS-RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    152: "BFTP",
    153: "SGMP",
    156: "SQL-Service",
    158: "DMSP",
    161: "SNMP",
    162: "SNMP-Trap",
    170: "Print-Server",
    179: "BGP",
    194: "IRC",
    201: "AppleTalk",
    209: "QMTP",
    210: "ANSI-Z39.50",
    389: "LDAP",
    396: "Netware-IP",
    443: "HTTPS",
    444: "SNPP",
    445: "SMB",
    464: "Kerberos-Change",
    465: "SMTPS",
    500: "ISAKMP/IKE",
    512: "Rexec",
    513: "Rlogin",
    514: "Syslog/Rsh",
    515: "LPD/LPR",
    520: "RIP",
    521: "RIPng",
    540: "UUCP",
    543: "Klogin",
    544: "Kshell",
    546: "DHCPv6-Client",
    547: "DHCPv6-Server",
    554: "RTSP",
    563: "NNTPS",
    587: "SMTP-Submission",
    593: "HTTP-RPC-EPMAP",
    631: "IPP",
    636: "LDAPS",
    639: "MSDP",
    646: "LDP",
    691: "MS-Exchange",
    860: "iSCSI",
    873: "rsync",
    902: "VMware-Server",
    989: "FTPS-Data",
    990: "FTPS",
    992: "Telnet-SSL",
    993: "IMAPS",
    995: "POP3S",
    
    # Registered ports
    1025: "NFS-or-IIS",
    1080: "SOCKS",
    1194: "OpenVPN",
    1241: "Nessus",
    1311: "Dell-OpenManage",
    1433: "Microsoft-SQL",
    1434: "Microsoft-SQL-Monitor",
    1521: "Oracle-DB",
    1604: "Citrix-ICA",
    1720: "H.323",
    1723: "PPTP",
    1755: "MMS",
    1812: "RADIUS",
    1813: "RADIUS-Accounting",
    1883: "MQTT",
    1900: "SSDP",
    2000: "Cisco-SCCP",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel-SSL",
    2086: "WHM",
    2087: "WHM-SSL",
    2096: "Webmail",
    2181: "Zookeeper",
    2222: "DirectAdmin",
    2375: "Docker",
    2376: "Docker-SSL",
    2483: "Oracle-DB-SSL",
    3000: "Ruby/NodeJS",
    3001: "Ruby/NodeJS",
    3128: "Squid-Proxy",
    3260: "iSCSI-Target",
    3306: "MySQL",
    3389: "RDP",
    3690: "SVN",
    4000: "Elasticsearch",
    4040: "Spark-UI",
    4369: "Erlang-Port-Mapper",
    4443: "Privia",
    4444: "Metasploit",
    5000: "Docker/Flask",
    5001: "Flask-SSL",
    5060: "SIP",
    5061: "SIP-TLS",
    5222: "XMPP",
    5269: "XMPP-Server",
    5432: "PostgreSQL",
    5500: "VNC",
    5601: "Kibana",
    5671: "AMQP-SSL",
    5672: "AMQP",
    5800: "VNC-HTTP",
    5900: "VNC",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    6000: "X11",
    6379: "Redis",
    6443: "Kubernetes-API",
    6660: "IRC",
    6661: "IRC",
    6662: "IRC",
    6663: "IRC",
    6664: "IRC",
    6665: "IRC",
    6666: "IRC",
    6667: "IRC",
    6668: "IRC",
    6669: "IRC",
    6697: "IRC-SSL",
    7000: "Cassandra",
    7001: "Weblogic",
    7077: "Spark-Job",
    7474: "Neo4j",
    7547: "CPE-WAN",
    8000: "HTTP-Alt",
    8008: "HTTP-Alt",
    8009: "AJP",
    8080: "HTTP-Proxy",
    8081: "HTTP-Alt",
    8087: "Parallels-Plesk",
    8089: "Splunk",
    8090: "HTTP-Alt",
    8098: "Riak",
    8161: "ActiveMQ",
    8291: "MikroTik-Winbox",
    8333: "Bitcoin",
    8443: "HTTPS-Alt",
    8500: "Consul",
    8529: "ArangoDB",
    8686: "JBoss-CLI",
    8834: "Nessus-Web",
    8880: "CDDBP-Alt",
    8888: "HTTP-Alt",
    9000: "SonarQube",
    9042: "Cassandra-CQL",
    9090: "WebSphere",
    9092: "Kafka",
    9200: "Elasticsearch",
    9418: "Git",
    9443: "WebSphere-Admin",
    9990: "JBoss-Admin",
    9999: "Java-Debug",
    10000: "Webmin",
    10050: "Zabbix-Agent",
    10051: "Zabbix-Server",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB-Shard",
    27019: "MongoDB-Config",
    28017: "MongoDB-Web",
    49152: "Windows-RPC",
    50000: "SAP"
}

# TCP connection cache to avoid redundant connections
_connection_cache = {}
_cache_lock = threading.Lock()

# Rich console for better output formatting
console = Console()

def port_scan(target: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """
    Optimized port scan function with better error handling and timeout management.
    """
    # Check cache first
    cache_key = f"{target}:{port}"
    with _cache_lock:
        if cache_key in _connection_cache:
            return _connection_cache[cache_key]
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port)) == 0
            
            # Cache the result
            with _cache_lock:
                _connection_cache[cache_key] = result
                
            return result
    except (socket.gaierror, socket.error, ConnectionRefusedError, OSError) as e:
        # More specific error handling
        if isinstance(e, socket.gaierror):
            # DNS resolution error
            return False
        elif isinstance(e, socket.timeout):
            # Connection timeout
            return False
        else:
            return False
    except Exception as e:
        # Fallback error handling with proper logging
        return False

def identify_service(target: str, port: int) -> Optional[str]:
    """
    Attempt to identify the service running on an open port.
    """
    if port in COMMON_SERVICES:
        service = COMMON_SERVICES[port]
        try:
            # For some common ports, attempt to get banner
            if port in [22, 21, 25, 110, 143]:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.5)
                    s.connect((target, port))
                    # Receive banner (if available)
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        return f"{service} ({banner})"
            return service
        except Exception:
            return service
    return None

def scan_all_ports(target: str, ports: List[int], timeout: float = DEFAULT_TIMEOUT) -> Dict[int, bool]:
    """
    Scan all ports in the provided list for the target.
    Simple sequential scan, optimized with proper timeout handling.
    """
    open_ports = {}
    for port in tqdm.tqdm(ports, desc=colored(f"[*] Scanning ports on {target}", 'cyan'), 
                       unit="port"):
        if port_scan(target, port, timeout):
            open_ports[port] = True
            service = identify_service(target, port)
            service_info = f" ({service})" if service else ""
            cprint(f"[+] Port {port}{service_info} is open on {target}", 'green')
    return open_ports

def threaded_port_scan(target: str, ports: List[int], num_threads: int = 10, 
                       timeout: float = DEFAULT_TIMEOUT) -> Dict[int, Any]:
    """
    Perform port scanning using multiple threads.
    Optimized version with better resource management and cancellation support.
    """
    open_ports = {}
    open_ports_lock = threading.Lock()
    queue = Queue()
    stop_event = threading.Event()
    threads = []

    # Fill the queue with the ports
    for port in ports:
        queue.put(port)

    # Use Rich's Progress for proper terminal formatting instead of tqdm
    with console.status(f"[bold cyan]Scanning ports on {target}...", spinner="dots") as status:
        def worker():
            while not stop_event.is_set():
                try:
                    # Use timeout to allow checking stop_event periodically
                    port = queue.get(block=True, timeout=0.1)
                except Empty:
                    continue  # Queue empty or timeout, check stop_event again
                
                if stop_event.is_set():
                    queue.task_done()
                    break

                # Use optimized port_scan function
                if port_scan(target, port, timeout):
                    with open_ports_lock:
                        # Identify service and store it in open_ports
                        service = identify_service(target, port)
                        open_ports[port] = service
                        service_info = f" ({service})" if service else ""
                        console.print(f"[green][+] Port {port}{service_info} is open on {target}[/green]")
                
                queue.task_done()
        
        try:
            # Create and start threads in batches to avoid system resource exhaustion
            batch_size = min(num_threads, 50)  # Cap at 50 threads maximum
            
            for _ in range(batch_size):
                thread = threading.Thread(target=worker)
                thread.daemon = True
                thread.start()
                threads.append(thread)

            # Wait for queue to be processed or for interrupt
            queue.join()
            
        except KeyboardInterrupt:
            console.print("[yellow]\n[*] Port scanning interrupted by user. Cleaning up...[/yellow]")
            stop_event.set()
            raise

        finally:
            # Clean up resources
            stop_event.set()
            # Give threads time to exit cleanly
            for thread in threads:
                thread.join(timeout=0.5)

    return open_ports

async def async_port_scan(target: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> Optional[int]:
    """
    Asynchronous port scanner function.
    """
    # Check cache first for performance
    cache_key = f"{target}:{port}"
    with _cache_lock:
        if cache_key in _connection_cache:
            return port if _connection_cache[cache_key] else None
    
    loop = asyncio.get_event_loop()
    fut = loop.create_future()
    
    def _scan():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port)) == 0
                
                # Cache the result
                with _cache_lock:
                    _connection_cache[cache_key] = result
                    
                return port if result else None
        except Exception:
            return None
    
    # Run the blocking socket operation in a thread pool
    result = await loop.run_in_executor(None, _scan)
    return result

async def async_port_scan_batch(target: str, ports: List[int], 
                             concurrent_limit: int = 100, timeout: float = DEFAULT_TIMEOUT) -> Dict[int, bool]:
    """
    Scan ports in batches using asyncio for better performance.
    """
    open_ports = {}
    semaphore = asyncio.Semaphore(concurrent_limit)
    
    async def _scan_with_semaphore(port):
        async with semaphore:
            return await async_port_scan(target, port, timeout)
    
    # Break ports into manageable batches to avoid overwhelming resources
    all_results = []
    batch_size = 500
    
    for i in range(0, len(ports), batch_size):
        batch = ports[i:i+batch_size]
        tasks = [_scan_with_semaphore(port) for port in batch]
        
        # Display a spinner for the current batch
        with console.status(f"[bold cyan]Scanning ports {i+1}-{min(i+batch_size, len(ports))} of {len(ports)}...", spinner="dots"):
            batch_results = await asyncio.gather(*tasks)
        
        # Filter out None results and add to all_results
        all_results.extend([r for r in batch_results if r is not None])
    
    # Convert results to dictionary
    for port in all_results:
        if port is not None:
            open_ports[port] = True
            service = identify_service(target, port)
            service_info = f" ({service})" if service else ""
            cprint(f"[+] Port {port}{service_info} is open on {target}", 'green')
    
    return open_ports

def main():
    parser = argparse.ArgumentParser(description="Port scanning and service enumeration tool.")
    parser.add_argument('--target', type=str, required=True, help="The target domain or IP address (e.g., example.com)")
    parser.add_argument('--ports', type=str, default="1-1024,3389,8080,8443", help="Comma-separated list of ports or range (e.g., 1-1024, 80, 443)")
    parser.add_argument('--threads', type=int, default=20, help="Number of threads for port scanning (default: 20)")
    parser.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument('--async', action='store_true', help="Use asynchronous scanning mode (faster but may be less reliable)")
    args = parser.parse_args()
    
    target = args.target.strip()
    ports_input = args.ports.strip()
    num_threads = args.threads
    timeout = args.timeout
    use_async = getattr(args, 'async', False)
    
    if not target:
        cprint("[-] Target domain or IP address is required. Exiting.", 'red', attrs=['bold'])
        sys.exit(1)
    
    if not ports_input:
        cprint("[-] Ports are required. Exiting.", 'red', attrs=['bold'])
        sys.exit(1)
    
    # Parse ports input
    ports = []
    for part in ports_input.split(','):
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    
    ports = list(set(ports))  # Remove duplicates
    ports.sort()  # Sort for consistent output
    
    cprint(f"\n[*] Starting port scan for {target} on {len(ports)} ports", 'yellow', attrs=['bold'])
    
    try:
        if use_async:
            cprint("[*] Using asynchronous scanning mode", 'cyan')
            # Run async scan
            open_ports_status = asyncio.run(async_port_scan_batch(target, ports, concurrent_limit=num_threads, timeout=timeout))
        else:
            # Run threaded scan
            open_ports_status = threaded_port_scan(target, ports, num_threads, timeout=timeout)
        
        if open_ports_status:
            cprint(f"\n[*] Summary of open ports for {target}:", 'green', attrs=['bold'])
            for port in sorted(list(open_ports_status.keys())):
                service = identify_service(target, port)
                service_info = f" ({service})" if service else ""
                cprint(f"[+] Port {port}{service_info} is open", 'green')
        else:
            cprint(f"\n[-] No open ports found for {target}.", 'red')
    except KeyboardInterrupt:
        cprint("\n[-] Port scanning interrupted by user. Exiting gracefully.", 'red', attrs=['bold'])
        sys.exit(0)
    except Exception as e:
        cprint(f"\n[-] An unexpected error occurred: {e}", 'red', attrs=['bold'])
        sys.exit(1)

if __name__ == "__main__":
    main()
