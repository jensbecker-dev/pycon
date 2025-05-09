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
    try:
        async with semaphore:  # If cancelled while waiting for semaphore
            try:
                # Set slightly longer and more granular timeouts
                timeout = aiohttp.ClientTimeout(total=15, connect=7, sock_read=10)
                async with session.get(url, timeout=timeout, allow_redirects=True) as response:  # If cancelled during HTTP GET
                    content_length = response.headers.get('Content-Length', '0')
                    status_code = response.status
                    
                    if 200 <= status_code < 300:
                        status_info = f"[Status: {status_code}, Size: {content_length}]"
                        return (url, status_info)
                    elif status_code in [301, 302, 307, 308]:  # Redirects
                        location = response.headers.get('Location', '')
                        status_info = f"[Status: {status_code}, Redirect: {location}]"
                        return (url, status_info)
                        
            except asyncio.TimeoutError:
                # Explicitly handle timeout without traceback
                pass
            except aiohttp.ClientConnectorError:
                # Network connection errors
                pass
            except aiohttp.ClientError as e:
                if "Session is closed" in str(e):
                    # Session already closed (happens during shutdown)
                    pass
                pass
            except asyncio.CancelledError:
                # Re-raise CancelledError to allow proper task cancellation
                raise
            except Exception as e:
                # For any other exceptions, only log if they're not common network errors
                if "Connect call failed" not in str(e) and "Connection refused" not in str(e):
                    pass
                pass
    
    except asyncio.CancelledError:
        # Important: re-raise CancelledError to propagate cancellation properly
        raise
    
    return None

async def async_directory_enumeration(domain: str, wordlist: List[str], 
                                     max_concurrent: int = 40) -> Dict[str, str]:
    """
    Perform directory enumeration asynchronously using aiohttp.
    Returns a dictionary of {url: status_info} for found directories.
    """
    found_directories = {}
    semaphore = asyncio.Semaphore(max_concurrent)
    connector = aiohttp.TCPConnector(
        limit_per_host=max_concurrent, 
        ttl_dns_cache=300, 
        enable_cleanup_closed=True
    )
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
    }
    
    protocols = ["http", "https"]
    total_urls = len(protocols) * len(wordlist)
    
    try:
        from rich.console import Console
        console = Console()
    except ImportError:
        console = None

    tasks = []
    task_cancellation_requested = False
    
    # Define a helper function to handle proper task cleanup
    async def cancel_all_tasks(task_list):
        """Cancel all tasks and wait for them to complete with proper exception handling"""
        if not task_list:
            return
            
        # First cancel all tasks
        for t in task_list:
            if not t.done():
                t.cancel()
                
        # Then await their cancellation with exception handling
        await asyncio.gather(*task_list, return_exceptions=True)
        
        # Explicitly clear the list to help garbage collection
        task_list.clear()
    
    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        try:
            # Create all tasks but process them in batches to avoid excessive memory usage
            batch_size = min(5000, len(wordlist))  # Process in reasonable batches
            
            for batch_start in range(0, len(wordlist), batch_size):
                batch_end = min(batch_start + batch_size, len(wordlist))
                batch = wordlist[batch_start:batch_end]
                
                # Clear previous batch tasks if any
                if tasks:
                    await cancel_all_tasks(tasks)
                    tasks = []
                
                # Create tasks for this batch
                for protocol in protocols:
                    for sub in batch:
                        url = f"{protocol}://{domain}/{sub.strip('/')}"
                        task = asyncio.create_task(async_directory_check(session, url, semaphore))
                        tasks.append(task)
                
                if console:
                    with console.status(f"[cyan]Processing {len(tasks)} directory paths (batch {batch_start}-{batch_end}) for {domain}...", spinner="dots") as status:
                        for coro in asyncio.as_completed(tasks):
                            try:
                                result = await coro
                                if result:
                                    url, status_info = result
                                    found_directories[url] = status_info
                            except asyncio.CancelledError:
                                # Task was cancelled, just move on
                                pass
                            except Exception as e:
                                if not task_cancellation_requested:
                                    console.print(f"[red]Error processing a directory check: {e}[/red]")
                else:
                    # Without rich console
                    for coro in asyncio.as_completed(tasks):
                        try:
                            result = await coro
                            if result:
                                url, status_info = result
                                found_directories[url] = status_info
                        except asyncio.CancelledError:
                            # Task was cancelled, just move on
                            pass
                        except Exception as e:
                            if not task_cancellation_requested:
                                cprint(f"Error processing a directory check: {e}", 'red')
                
        except asyncio.CancelledError:
            # Main task was cancelled (e.g., by Ctrl+C)
            task_cancellation_requested = True
            if console:
                console.print("[yellow]Task cancellation requested. Cleaning up...[/yellow]")
            else:
                cprint("Task cancellation requested. Cleaning up...", 'yellow')
            raise  # Re-raise to propagate cancellation
        except Exception as e:
            task_cancellation_requested = True
            if console:
                console.print(f"[red]Error during directory enumeration: {e}[/red]")
            else:
                cprint(f"Error during directory enumeration: {e}", 'red')
            raise
        finally:
            # Ensure proper cleanup of all remaining tasks
            if tasks:
                if console:
                    console.print("[cyan]Cleaning up remaining tasks...[/cyan]")
                await cancel_all_tasks(tasks)
    
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
                found_directories_dict = asyncio.run(async_directory_enumeration(target_domain, wordlist, max_concurrent=num_threads))
                all_found_directories.update(found_directories_dict)  # Ensure update from dict
            else:
                cprint(f"[*] Starting threaded directory enumeration for {target_domain} with {wordlist_path} using {num_threads} threads...", 'yellow')
                found_dirs_list = threaded_directory_enumeration(target_domain, wordlist, num_threads)
                for fd_url in found_dirs_list:
                    all_found_directories[fd_url] = "[Status: (threaded)]"  # Placeholder status
                
        if all_found_directories:
            cprint(f"\n[*] Found directories for {target_domain}:", 'green', attrs=['bold'])
            for directory, status_info in sorted(all_found_directories.items()):
                cprint(f"[+] {directory} {status_info}", 'green')
        else:
            cprint(f"\n[-] No directories found for {target_domain}.", 'red')
    except KeyboardInterrupt:
        cprint("\n[-] User interrupted the directory enumeration process. Exiting gracefully.", 'red', attrs=['bold'])
        # Removed sys.exit(0) to allow asyncio.run() to clean up if it's handling KeyboardInterrupt.
    except Exception as e:
        cprint(f"\n[-] An unexpected error occurred during directory enumeration: {e}", 'red', attrs=['bold'])
        sys.exit(1)

if __name__ == "__main__":
    main()