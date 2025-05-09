# Directory Enumeration
import os, sys, requests, json, argparse
import threading
import asyncio
import aiohttp
from queue import Queue, Empty  
from typing import List, Dict, Any, Set, Optional
import tqdm
from termcolor import cprint, colored
from concurrent.futures import ThreadPoolExecutor
import time

def import_wordlist(file_path: str) -> List[str]:
    """
    Import a wordlist from a file.
    Filter out comment lines (starting with #) and empty lines.
    Uses optimized file reading approach.
    """
    try:
        with open(file_path, 'r') as file:
            # Filter out comment lines and empty lines - optimized for memory efficiency
            wordlist = [line.strip() for line in file if line.strip() and not line.strip().startswith('#')]
        return wordlist
    except FileNotFoundError:
        cprint(f"[-] File not found: {file_path}", 'red')  # Colored output
        return []
    except Exception as e:
        cprint(f"[-] Error reading file {file_path}: {e}", 'red')  # Colored output
        return []
    
def get_directory_enumeration(domain: str, wordlist: List[str]) -> List[str]:
    """
    Get directories for a given domain using a wordlist.
    Optimized version that uses connection pooling.
    """
    found_directories = set()
    session = requests.Session()
    # Use connection pooling for better performance
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=10,
        pool_maxsize=100,
        max_retries=0
    )
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    
    for sub in wordlist:
        url = f"http://{domain}/{sub}"
        try:
            response = session.get(url, timeout=3, allow_redirects=False)
            # Consider 200, 302, 303 status codes as "found"
            if response.status_code in [200, 302, 303]:
                found_directories.add(url)
        except requests.RequestException:
            pass
    return list(found_directories)

async def async_directory_check(session: aiohttp.ClientSession, url: str, semaphore: asyncio.Semaphore) -> Optional[tuple]:
    """
    Asynchronously check if a directory exists using aiohttp.
    Returns a tuple of (url, status_info) if the directory is found.
    Uses semaphore to limit concurrent connections.
    """
    async with semaphore:
        try:
            # Set shorter timeouts for better performance
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), 
                                  allow_redirects=True) as response:
                # Consider a wider range of status codes as "interesting"
                content_length = response.headers.get('Content-Length', '0')
                status_code = response.status
                
                # Always consider 2xx responses as valid
                if 200 <= status_code < 300:
                    status_info = f"[Status: {status_code}, Size: {content_length}]"
                    return (url, status_info)
                
                # Also consider certain 3xx, 4xx status codes in specific cases
                elif status_code in [301, 302, 307, 308]:  # Redirects
                    location = response.headers.get('Location', '')
                    status_info = f"[Status: {status_code}, Redirect: {location}]"
                    return (url, status_info)
                    
                # Check for "soft 404s" - pages that return 200 but are actually error pages
                # This is more sophisticated detection of false positives
                elif status_code == 404 and int(content_length) > 500:
                    # Some servers return custom 404 pages with substantial content
                    # We're not interested in these
                    return None
                    
        except (aiohttp.ClientError, asyncio.TimeoutError):
            # Handle connection errors gracefully
            pass
        except Exception as e:
            # Log other errors for debugging but continue scanning
            print(f"Error scanning {url}: {str(e)}")
            pass
    
    return None

async def async_directory_enumeration(domain: str, wordlist: List[str], 
                                     max_concurrent: int = 40) -> Dict[str, str]:
    """
    Perform directory enumeration asynchronously using aiohttp.
    Returns a dictionary of {url: status_info} for found directories.
    """
    found_directories = {}
    semaphore = asyncio.Semaphore(max_concurrent)
    connector = aiohttp.TCPConnector(limit=max_concurrent, ttl_dns_cache=300)
    
    # Use custom headers to appear more like a browser
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
    }
    
    # Try both http and https for more comprehensive scanning
    protocols = ["http", "https"]
    total_urls = len(protocols) * len(wordlist)
    
    # Import rich console if not already available
    try:
        from rich.console import Console
        console = Console()
    except ImportError:
        console = None  # Fallback if rich is not available

    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        tasks = []
        
        # Create tasks for both HTTP and HTTPS
        for protocol in protocols:
            for sub in wordlist:
                url = f"{protocol}://{domain}/{sub.strip('/')}"
                task = asyncio.create_task(async_directory_check(session, url, semaphore))
                tasks.append(task)
        
        # Create a status display using Rich
        if console:
            with console.status(f"[cyan]Processing {total_urls} directory paths...", spinner="dots") as status:
                for coro in asyncio.as_completed(tasks):
                    result = await coro
                    if result:
                        url, status_info = result
                        found_directories[url] = status_info
                        console.print(f"[green][+] Found: {url} {status_info}[/green]")
        else:
            # Fallback to simpler output if Rich is not available
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result:
                    url, status_info = result
                    found_directories[url] = status_info
                    cprint(f"[+] Found: {url} {status_info}", 'green')
    
    return found_directories

def threaded_directory_enumeration(domain: str, wordlist: List[str], num_threads: int = 10) -> List[str]:
    """
    Perform directory enumeration using multiple threads.
    Optimized with connection pooling and better resource management.
    """
    found_directories = set()
    queue = Queue()
    stop_event = threading.Event()
    
    # Fill the queue with the wordlist
    for sub in wordlist:
        queue.put(sub)

    # Initialize tqdm progress bar with colored description
    pbar = tqdm.tqdm(total=len(wordlist), desc=colored("[*] Processing directories", 'cyan'), 
                    unit="dir", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}{postfix}]")
    threads = []
    
    # Create a session for each thread with connection pooling
    def create_session():
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=1,
            pool_maxsize=10,
            max_retries=0
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session

    def worker():
        # Create a session per thread for better connection management
        thread_session = create_session()
        
        while not stop_event.is_set():
            try:
                # Use timeout to allow checking stop_event periodically
                sub = queue.get(block=True, timeout=0.1)
            except Empty:
                # Queue empty or timeout, loop back to check stop_event
                continue
            
            if stop_event.is_set():
                queue.task_done()  # Mark item as done if retrieved before stop signal
                break

            url = f"http://{domain}/{sub}"
            try:
                # Using the thread's session for connection pooling
                response = thread_session.get(url, timeout=3, allow_redirects=False)
                # Consider 200, 302, 303 status codes as "found"
                if response.status_code in [200, 302, 303]:
                    found_directories.add(url)
            except requests.RequestException:
                # Ignore connection errors
                pass
            except Exception:
                # Ignore other exceptions within the thread
                pass
            finally:
                queue.task_done()
                if pbar and not getattr(pbar, 'disable', False) and pbar.total is not None and pbar.n < pbar.total:
                    try:
                        pbar.update(1)  # Update progress bar for each processed item
                    except Exception:
                        pass  # Ignore errors during pbar update on shutdown

    try:
        # Start threads
        for _ in range(num_threads):
            thread = threading.Thread(target=worker)
            thread.daemon = True  # Set thread as daemon
            thread.start()
            threads.append(thread)

        # Wait for all tasks in queue to be processed
        try:
            queue.join()
        except KeyboardInterrupt:
            cprint("\n[*] Interrupt in dir_en worker. Signaling threads to stop...", 'yellow', attrs=['bold'])
            stop_event.set()  # Signal worker threads to stop
            raise  # Re-raise KeyboardInterrupt for the caller to handle

    finally:
        if pbar:
            pbar.close()  # Close the progress bar when done or interrupted

        # Wait for daemon threads to finish their current task
        for thread in threads:
            thread.join(timeout=0.5)  # Slightly increased timeout for cleaner exit

    return list(found_directories)

def main():
    parser = argparse.ArgumentParser(description="Directory Enumeration Tool")
    parser.add_argument('--target', type=str, help="The target domain (e.g., example.com)", required=True)
    parser.add_argument('--threads', type=int, default=10, help="Number of threads to use (default: 10)")
    parser.add_argument('--async', action='store_true', help="Use async mode for better performance")
    args = parser.parse_args()
    target_domain = args.target.strip()
    num_threads = args.threads
    use_async = getattr(args, 'async', False)  # Use async mode if specified
    
    if not target_domain:
        cprint("[-] Target domain is required.", 'red', attrs=['bold'])
        sys.exit(1)

    try:
        wordlist_paths = ["wordlists/directories.txt", "wordlists/directories_med.txt"]
        all_found_directories = {}

        for wordlist_path in wordlist_paths:
            if not os.path.isfile(wordlist_path):
                cprint(f"[-] Wordlist file not found: {wordlist_path}", 'red', attrs=['bold'])
                continue

            wordlist = import_wordlist(wordlist_path)
            if not wordlist:
                cprint(f"[-] Wordlist {wordlist_path} is empty or could not be loaded.", 'red', attrs=['bold'])
                continue
        
            if use_async:
                cprint(f"[*] Starting async directory enumeration for {target_domain} with {wordlist_path}...", 'yellow')
                found_directories = asyncio.run(async_directory_enumeration(target_domain, wordlist, max_concurrent=num_threads))
            else:
                cprint(f"[*] Starting threaded directory enumeration for {target_domain} with {wordlist_path} using {num_threads} threads...", 'yellow')
                found_directories = threaded_directory_enumeration(target_domain, wordlist, num_threads)
                
            all_found_directories.update(found_directories)
        
        if all_found_directories:
            cprint(f"\n[*] Found directories for {target_domain}:", 'green', attrs=['bold'])
            for directory, status_info in sorted(all_found_directories.items()):
                cprint(f"[+] {directory} {status_info}", 'green')
        else:
            cprint(f"\n[-] No directories found for {target_domain}.", 'red')
    except KeyboardInterrupt:
        cprint("\n[-] User interrupted the directory enumeration process. Exiting gracefully.", 'red', attrs=['bold'])
        sys.exit(0)
    except Exception as e:
        cprint(f"\n[-] An unexpected error occurred during directory enumeration: {e}", 'red', attrs=['bold'])
        sys.exit(1)

if __name__ == "__main__":
    main()