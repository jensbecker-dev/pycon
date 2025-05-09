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
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
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
