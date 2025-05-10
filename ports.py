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
    631: "CUPS",  # Common Unix Printing System
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    3390: "RDP-Alt",  # Alternative RDP port
    5432: "PostgreSQL",
    8000: "HTTP-Alt",  # Alternate HTTP port
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

def identify_service(target: str, port: int, detailed: bool = True) -> Optional[str]:
    """
    Attempt to identify the service running on an open port with detailed version detection.
    
    Args:
        target: Target host
        port: Port number to identify
        detailed: If True, attempt to get detailed version information
        
    Returns:
        String containing service name and version information if available
    """
    service_name = COMMON_SERVICES.get(port, "Unknown")
    
    if not detailed:
        return service_name
    
    # Common protocol-specific probes for better version detection
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.5)  # Slightly longer timeout for service enumeration
            s.connect((target, port))
            
            # Handle specific protocols differently
            if port == 22:  # SSH
                # SSH typically sends banner immediately on connect
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    # Clean up the banner - remove extra whitespace
                    banner = ' '.join(banner.split())
                    return f"SSH ({banner})"
                return "SSH"
                
            elif port == 21:  # FTP
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    return f"FTP ({banner})"
                return "FTP"
                
            elif port in [25, 587]:  # SMTP
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    # Try EHLO to get more server info
                    try:
                        s.send(b"EHLO example.com\r\n")
                        ehlo_response = s.recv(1024).decode('utf-8', errors='ignore').strip()
                        if "250" in ehlo_response:
                            # Extract the server name from ehlo response if possible
                            server_info = banner.split(' ')[0] if ' ' in banner else banner
                            return f"SMTP ({server_info})"
                    except:
                        pass
                    return f"SMTP ({banner.split()[0]})"
                return "SMTP"
                
            elif port in [80, 8000]:  # HTTP and alternate HTTP ports
                try:
                    s.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\nConnection: close\r\n\r\n")
                    response = s.recv(4096).decode('utf-8', errors='ignore')
                    
                    # Try to extract server header
                    server_header = None
                    for line in response.splitlines():
                        if line.lower().startswith('server:'):
                            server_header = line[7:].strip()
                            break
                    
                    if "HTTP/" in response:
                        if server_header:
                            return f"HTTP ({server_header})"
                        else:
                            # Get HTTP version if available
                            if response.startswith("HTTP/"):
                                http_version = response.split('\r\n')[0]
                                return f"HTTP ({http_version})"
                            return "HTTP (Web Server)"
                except:
                    pass
                return "HTTP"
                
            elif port == 443:  # HTTPS - requires SSL/TLS handling
                try:
                    import ssl
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((target, port), timeout=2.0) as sock:
                        with context.wrap_socket(sock, server_hostname=target) as ssock:
                            # Try to get certificate information
                            try:
                                cert_dict = ssock.getpeercert()
                                if cert_dict and 'subject' in cert_dict:
                                    for subject in cert_dict['subject']:
                                        for key, value in subject:
                                            if key == 'commonName':
                                                return f"HTTPS (SSL/TLS, CN={value})"
                            except:
                                pass
                            
                            # Fall back to basic SSL info
                            ssl_version = ssock.version()
                            if ssl_version:
                                return f"HTTPS ({ssl_version})"
                            return "HTTPS (SSL/TLS enabled)"
                except:
                    pass
                return "HTTPS"
                
            elif port in [3389, 3390]:  # RDP and alternate RDP port
                # RDP requires specific protocol handling
                try:
                    # Send RDP connection request (CredSSP/TLS)
                    rdp_probe = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
                    s.send(rdp_probe)
                    response = s.recv(1024)
                    
                    if len(response) > 0:
                        # Check if we can identify Windows version in the response
                        if b"Windows" in response:
                            windows_ver = response.decode('utf-8', errors='ignore')
                            return f"RDP (Microsoft {windows_ver})"
                        # Check for TPKT header (RDP uses this)
                        elif response.startswith(b'\x03\x00'):
                            return "RDP (Microsoft Terminal Services)"
                except:
                    pass
                return "RDP"
                
            elif port == 631:  # CUPS - Internet Printing Protocol
                try:
                    # Send HTTP request to the CUPS server
                    s.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\nConnection: close\r\n\r\n")
                    response = s.recv(4096).decode('utf-8', errors='ignore')
                    
                    # Look for CUPS-specific strings in response
                    if "CUPS" in response or "Internet Printing Protocol" in response:
                        # Try to extract version
                        if "CUPS/" in response:
                            version_start = response.find("CUPS/")
                            version_end = response.find(" ", version_start)
                            if version_end > version_start:
                                cups_version = response[version_start:version_end].strip()
                                return f"CUPS ({cups_version})"
                        return "CUPS (Printing System)"
                except:
                    pass
                return "CUPS"
                
            elif port in [3306, 5432]:  # Database ports
                banner = s.recv(1024)
                if banner:
                    # Just check if we get any response
                    protocol = "MySQL" if port == 3306 else "PostgreSQL"
                    return f"{protocol} (Active)"
                return service_name
                
            # For other ports just try to get banner data
            else:
                try:
                    # Send a generic newline and see if we get anything back
                    s.send(b"\r\n")
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        # Truncate very long banners
                        if len(banner) > 50:
                            banner = banner[:50] + "..."
                        return f"{service_name} ({banner})"
                except:
                    pass
                
    except (socket.timeout, socket.error, ConnectionRefusedError):
        pass
    except Exception as e:
        # Fallback for any other errors
        pass
        
    return service_name

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
    Optimized version with better resource management, cancellation support, and visual feedback.
    
    Args:
        target: Target host to scan
        ports: List of port numbers to scan
        num_threads: Number of concurrent threads to use
        timeout: Socket connection timeout in seconds
    
    Returns:
        Dictionary of open ports with service information
    """
    open_ports = {}
    open_ports_lock = threading.Lock()
    queue = Queue()
    stop_event = threading.Event()
    threads = []
    scanned_count = 0
    scanned_lock = threading.Lock()
    total_ports = len(ports)

    # Fill the queue with the ports
    for port in ports:
        queue.put(port)
    
    # Create shared progress stats
    with console.status("") as status:
        # Update status initially
        status.update(f"[bold cyan]Initializing port scan on {target}...[/bold cyan]", spinner="dots")
        
        def worker():
            nonlocal scanned_count
            while not stop_event.is_set():
                try:
                    # Use timeout to allow checking stop_event periodically
                    port = queue.get(block=True, timeout=0.1)
                except Empty:
                    continue  # Queue empty or timeout, check stop_event again
                
                if stop_event.is_set():
                    queue.task_done()
                    break
                
                # Update scan count for progress display
                with scanned_lock:
                    scanned_count += 1
                    # Update status every 10 ports or so to avoid too much UI refresh
                    if scanned_count % 10 == 0 or scanned_count == total_ports:
                        percent = int((scanned_count / total_ports) * 100)
                        status.update(
                            f"[bold cyan]Scanning ports on {target}... [green]{scanned_count}/{total_ports}[/green] ([green]{percent}%[/green])[/bold cyan]",
                            spinner="dots"
                        )

                # Use optimized port_scan function
                if port_scan(target, port, timeout):
                    with open_ports_lock:
                        # Detailed service identification
                        service = identify_service(target, port, detailed=True)
                        open_ports[port] = service
                        
                        # Format the output with color-coded information
                        if isinstance(service, str) and "(" in service:
                            service_name, version_info = service.split("(", 1)
                            version_info = "(" + version_info  # Add the opening parenthesis back
                            console.print(f"[green][+] Port [bold]{port}[/bold]: [cyan]{service_name}[/cyan] [yellow]{version_info}[/yellow] on [blue]{target}[/blue][/green]")
                        else:
                            console.print(f"[green][+] Port [bold]{port}[/bold]: [cyan]{service}[/cyan] on [blue]{target}[/blue][/green]")
                
                queue.task_done()
        
        try:
            # Determine optimal thread count based on port count
            optimal_threads = min(num_threads, len(ports), 100)  # Cap at 100 max threads
            status.update(f"[bold cyan]Starting scan with {optimal_threads} threads...[/bold cyan]", spinner="dots")
            
            # Create and start threads
            for _ in range(optimal_threads):
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
            
    # Display summary 
    if open_ports:
        console.print(f"\n[green bold]Scan complete: Found {len(open_ports)} open ports on {target}[/green bold]")
    else:
        console.print(f"\n[yellow bold]Scan complete: No open ports found on {target}[/yellow bold]")
            
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
                             concurrent_limit: int = 100, timeout: float = DEFAULT_TIMEOUT) -> Dict[int, Any]:
    """
    Scan ports in batches using asyncio for better performance.
    
    Args:
        target: Target host to scan
        ports: List of port numbers to scan
        concurrent_limit: Maximum number of concurrent scan operations
        timeout: Socket connection timeout in seconds
    
    Returns:
        Dictionary of open ports with service information
    """
    open_ports = {}
    semaphore = asyncio.Semaphore(concurrent_limit)
    total_ports = len(ports)
    scanned_count = 0
    
    async def _scan_with_semaphore(port):
        async with semaphore:
            return await async_port_scan(target, port, timeout)
    
    # Break ports into manageable batches to avoid overwhelming resources
    all_results = []
    batch_size = min(500, len(ports))  # Adaptive batch size
    
    for i in range(0, len(ports), batch_size):
        batch = ports[i:i+batch_size]
        batch_start = i + 1
        batch_end = min(i+batch_size, len(ports))
        batch_percent = int((batch_end / total_ports) * 100)
        
        # Create tasks for this batch
        tasks = [_scan_with_semaphore(port) for port in batch]
        
        # Display progress for the current batch
        with console.status(f"[bold cyan]Scanning ports {batch_start}-{batch_end} of {total_ports} ([green]{batch_percent}%[/green])...[/bold cyan]", spinner="dots"):
            batch_results = await asyncio.gather(*tasks)
        
        # Process results and update progress
        open_ports_in_batch = [r for r in batch_results if r is not None]
        all_results.extend(open_ports_in_batch)
        
        if open_ports_in_batch:
            console.print(f"[green]Found {len(open_ports_in_batch)} open ports in batch {batch_start}-{batch_end}[/green]")
    
    # Process all discovered ports and get detailed service information
    console.print(f"\n[bold cyan]Identifying services on {len(all_results)} open ports...[/bold cyan]")
    
    # Process results - use ThreadPoolExecutor for efficient service scanning
    with ThreadPoolExecutor(max_workers=min(10, len(all_results) or 1)) as executor:
        # Use a thread pool for the potentially blocking service detection operations
        loop = asyncio.get_event_loop()
        
        async def process_port(port):
            # Run identify_service in a thread to prevent blocking the event loop
            service = await loop.run_in_executor(
                executor,
                identify_service,
                target,
                port,
                True  # detailed mode
            )
            
            # Store the result
            open_ports[port] = service
            
            # Format the output with color-coded information
            if isinstance(service, str) and "(" in service:
                service_name, version_info = service.split("(", 1)
                version_info = "(" + version_info  # Add the opening parenthesis back
                console.print(f"[green][+] Port [bold]{port}[/bold]: [cyan]{service_name}[/cyan] [yellow]{version_info}[/yellow] on [blue]{target}[/blue][/green]")
            else:
                console.print(f"[green][+] Port [bold]{port}[/bold]: [cyan]{service}[/cyan] on [blue]{target}[/blue][/green]")
        
        # Process all ports in parallel
        await asyncio.gather(*[process_port(port) for port in all_results])
    
    # Display summary
    if open_ports:
        console.print(f"\n[green bold]Async scan complete: Found {len(open_ports)} open ports on {target}[/green bold]")
    else:
        console.print(f"\n[yellow bold]Async scan complete: No open ports found on {target}[/yellow bold]")
    
    return open_ports

def main():
    parser = argparse.ArgumentParser(description="Port scanning and service enumeration tool.")
    parser.add_argument('--target', type=str, required=True, help="The target domain or IP address (e.g., example.com)")
    parser.add_argument('--ports', type=str, default="1-1024,3389,8080,8443", help="Comma-separated list of ports or range (e.g., 1-1024, 80, 443)")
    parser.add_argument('--threads', type=int, default=20, help="Number of threads for port scanning (default: 20)")
    parser.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument('--async', action='store_true', help="Use asynchronous scanning mode (faster but may be less reliable)")
    parser.add_argument('--deep', action='store_true', help="Perform deep service version detection (slower but more detailed)")
    args = parser.parse_args()
    
    target = args.target.strip()
    ports_input = args.ports.strip()
    num_threads = args.threads
    timeout = args.timeout
    use_async = getattr(args, 'async', False)
    deep_scan = args.deep
    
    if not target:
        console.print("[bold red][-] Target domain or IP address is required. Exiting.[/bold red]")
        sys.exit(1)
    
    if not ports_input:
        console.print("[bold red][-] Ports are required. Exiting.[/bold red]")
        sys.exit(1)
    
    # Parse ports input
    ports = []
    for part in ports_input.split(','):
        if '-' in part:
            try:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            except ValueError:
                console.print(f"[yellow]Warning: Invalid port range '{part}' ignored.[/yellow]")
        else:
            try:
                ports.append(int(part))
            except ValueError:
                console.print(f"[yellow]Warning: Invalid port number '{part}' ignored.[/yellow]")
    
    ports = list(set(ports))  # Remove duplicates
    ports.sort()  # Sort for consistent output
    
    # Print banner with more information
    from rich.panel import Panel
    
    console.print(Panel(
        f"[cyan bold]PORT SCANNER AND SERVICE ANALYZER[/cyan bold]\n"
        f"[green]Target:[/green] [white]{target}[/white]\n"
        f"[green]Ports:[/green] [white]{len(ports)} ports selected[/white]\n"
        f"[green]Mode:[/green] [white]{'Asynchronous' if use_async else 'Threaded'} ({num_threads} concurrent operations)[/white]\n"
        f"[green]Service Detection:[/green] [white]{'Deep' if deep_scan else 'Standard'}[/white]",
        border_style="blue",
        title="SCAN CONFIGURATION"
    ))
    
    try:
        start_time = time.time()
        
        if use_async:
            console.print("[cyan][*] Using asynchronous scanning mode[/cyan]")
            # Run async scan
            open_ports_status = asyncio.run(async_port_scan_batch(target, ports, concurrent_limit=num_threads, timeout=timeout))
        else:
            # Run threaded scan
            open_ports_status = threaded_port_scan(target, ports, num_threads, timeout=timeout)
        
        end_time = time.time()
        duration = round(end_time - start_time, 2)
        
        # Create a nice table for results
        from rich.table import Table
        
        if open_ports_status:
            console.print(f"\n[green bold]SCAN COMPLETED IN {duration} SECONDS[/green bold]")
            
            # Create a nice looking table
            table = Table(title=f"[bold cyan]Open Ports on {target}[/bold cyan]", show_header=True, header_style="bold magenta")
            table.add_column("Port", style="cyan", justify="right")
            table.add_column("Service", style="green")
            table.add_column("Details", style="yellow")
            
            for port in sorted(list(open_ports_status.keys())):
                service_info = open_ports_status[port]
                
                if isinstance(service_info, str) and "(" in service_info:
                    service_name, details = service_info.split("(", 1)
                    details = f"({details}"  # Add back opening parenthesis
                    table.add_row(str(port), service_name.strip(), details)
                else:
                    table.add_row(str(port), str(service_info), "")
            
            console.print(table)
            
            # Print result summary
            console.print(f"\n[green bold]Total: {len(open_ports_status)} open ports found on {target}[/green bold]")
        else:
            console.print(f"\n[yellow bold]No open ports found on {target}. Scan completed in {duration} seconds.[/yellow bold]")
        
        # Save results to file option
        save_filename = f"portscan_{target.replace('.', '_')}_{int(time.time())}.txt"
        with open(save_filename, "w") as f:
            f.write(f"PORT SCAN RESULTS FOR {target}\n")
            f.write(f"Scan completed on {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scanned {len(ports)} ports in {duration} seconds\n\n")
            f.write("PORT     SERVICE             DETAILS\n")
            f.write("------------------------------------------\n")
            
            if open_ports_status:
                for port in sorted(list(open_ports_status.keys())):
                    service_info = open_ports_status[port]
                    if isinstance(service_info, str) and "(" in service_info:
                        service_name, details = service_info.split("(", 1)
                        details = f"({details}"  # Add back opening parenthesis
                        f.write(f"{port:<8} {service_name.strip():<20} {details}\n")
                    else:
                        f.write(f"{port:<8} {str(service_info):<20}\n")
            else:
                f.write("No open ports found.\n")
        
        console.print(f"[cyan]Results saved to: [bold]{save_filename}[/bold][/cyan]")
        
    except KeyboardInterrupt:
        console.print("\n[bold red]Port scanning interrupted by user. Exiting gracefully.[/bold red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred: {e}[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
