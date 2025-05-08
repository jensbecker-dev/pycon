# Port scanning and service enumeration tool
import socket
import threading
import argparse
from queue import Queue, Empty
from termcolor import cprint, colored
import os
import sys
from typing import List, Dict, Any
import tqdm

def port_scan(target: str, port: int) -> bool:
    """
    Simple port scan function to check if a port is open on the target.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            return result == 0
    except Exception as e:
        cprint(f"[-] Error scanning {target}:{port} - {e}", 'red')
        return False
    
def scan_all_ports(target: str, ports: List[int]) -> Dict[int, bool]:
    """
    Scan all ports in the provided list for the target.
    """
    open_ports = {}
    for port in ports:
        if port_scan(target, port):
            open_ports[port] = True
            cprint(f"[+] Port {port} is open on {target}", 'green')
        else:
            pass
    return open_ports

def threaded_port_scan(target: str, ports: List[int], num_threads: int = 10) -> Dict[int, bool]:
    """
    Perform port scanning using multiple threads.
    """
    open_ports = {}
    queue = Queue()
    threads = []
    stop_event = threading.Event()

    # Fill the queue with the ports
    for port in ports:
        queue.put(port)

    # Initialize tqdm progress bar
    pbar = tqdm.tqdm(total=len(ports), desc=colored(f"[*] Scanning ports on {target}", 'cyan'), unit="port", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}{postfix}]")

    def worker():
        while not stop_event.is_set():
            try:
                port = queue.get(block=True, timeout=0.1)
            except Empty:
                continue # Queue empty or timeout, loop back to check stop_event
            
            if stop_event.is_set():
                queue.task_done()
                break

            if port_scan(target, port):
                open_ports[port] = True
            queue.task_done()
            if pbar:
                try:
                    pbar.update(1)
                except Exception:
                    pass # Ignore errors during pbar update on shutdown
    
    try:
        # Create and start threads
        for _ in range(num_threads):
            thread = threading.Thread(target=worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)

        # Wait for all tasks in queue to be processed or for interrupt
        try:
            queue.join()
        except KeyboardInterrupt:
            cprint(colored("\n[*] Port scanning interrupted by user. Signaling threads to stop...", 'yellow', attrs=['bold']))
            stop_event.set()

    finally:
        if pbar:
            pbar.close()
        
        # Ensure all daemon threads are given a moment to exit cleanly
        for thread in threads:
            thread.join(timeout=0.5)

    return open_ports

def main():

    parser = argparse.ArgumentParser(description="Port scanning and service enumeration tool.")
    parser.add_argument('--target', type=str, required=True, help="The target domain or IP address (e.g., example.com)")
    parser.add_argument('--ports', type=str, default="1-10000", help="Comma-separated list of ports or range (e.g., 1-1024, 80, 443)")
    parser.add_argument('--threads', type=int, default=10, help="Number of threads for port scanning (default: 10)")
    args = parser.parse_args()
    target = args.target.strip()
    ports_input = args.ports.strip()
    num_threads = args.threads
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
    cprint(f"\n[*] Starting port scan for {target} on ports: {ports}", 'yellow', attrs=['bold'])
    open_ports_status = threaded_port_scan(target, ports, num_threads) # Renamed to avoid conflict

    if open_ports_status: # Check if there are any open ports
        cprint(f"\n[*] Open ports for {target}:", 'green', attrs=['bold'])
        for port in sorted(list(open_ports_status.keys())): # Iterate through open ports
            if open_ports_status[port]: # Check if port is truly open
                cprint(f"[+] Port {port} is open", 'green')
    else:
        cprint(f"\n[-] No open ports found for {target}.", 'red')

if __name__ == "__main__":

    main()
