# Directory Enumeration
import os, sys, requests, json, argparse
import threading
from queue import Queue, Empty  # MODIFIED: Added Empty
from typing import List, Dict, Any
import tqdm
from termcolor import cprint, colored  # Add termcolor import

def import_wordlist(file_path: str) -> List[str]:
    """
    Import a wordlist from a file.
    """
    try:
        with open(file_path, 'r') as file:
            wordlist = [line.strip() for line in file if line.strip()]
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
    """
    found_directories = set()
    for sub in wordlist:
        url = f"http://{domain}/{sub}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                found_directories.add(url)
        except requests.RequestException as e:
            # Ignore connection errors
            pass
    return list(found_directories)

def threaded_directory_enumeration(domain: str, wordlist: List[str], num_threads: int = 10) -> List[str]:
    """
    Perform directory enumeration using multiple threads.
    """
    found_directories = set()
    queue = Queue()
    stop_event = threading.Event()  # ADDED: Event to signal threads to stop

    # Fill the queue with the wordlist
    for sub in wordlist:
        queue.put(sub)

    # Initialize tqdm progress bar with colored description
    pbar = tqdm.tqdm(total=len(wordlist), desc=colored("[*] Processing directories", 'cyan'), unit="dir", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}{postfix}]")
    threads = []

    def worker():
        while not stop_event.is_set():  # MODIFIED: Check stop_event
            try:
                # MODIFIED: Use timeout to allow checking stop_event periodically
                sub = queue.get(block=True, timeout=0.1)
            except Empty:
                # Queue empty or timeout, loop back to check stop_event
                continue
            
            if stop_event.is_set():  # ADDED: Check event after getting item
                queue.task_done()  # Mark item as done if retrieved before stop signal
                break  # Exit worker loop

            url = f"http://{domain}/{sub}"
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
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

        # MODIFIED: Wrap queue.join() to handle KeyboardInterrupt
        try:
            # Wait for all tasks in queue to be processed
            queue.join()
        except KeyboardInterrupt:
            cprint("\n[*] Interrupt in dir_en worker. Signaling threads to stop...", 'yellow', attrs=['bold'])
            stop_event.set()  # Signal worker threads to stop
            raise  # Re-raise KeyboardInterrupt for the caller to handle

    finally:
        if pbar:
            pbar.close()  # Close the progress bar when done or interrupted

        # Wait for daemon threads to finish their current task or be terminated by main thread exit
        for thread in threads:
            thread.join(timeout=0.5)  # MODIFIED: Slightly increased timeout for cleaner exit

    return list(found_directories)

def main():

    parser = argparse.ArgumentParser(description="Directory Enumeration Tool")
    parser.add_argument('--target', type=str, help="The target domain (e.g., example.com)", required=True)
    parser.add_argument('--threads', type=int, default=10, help="Number of threads to use (default: 10)")
    args = parser.parse_args()
    target_domain = args.target.strip()
    num_threads = args.threads
    if not target_domain:
        cprint("[-] Target domain is required.", 'red', attrs=['bold'])  # Colored output
        sys.exit(1)

    try:
        wordlist_paths = ["wordlists/directories.txt", "wordlists/directories_med.txt"]
        all_found_directories = set()

        for wordlist_path in wordlist_paths:
            if not os.path.isfile(wordlist_path):
                cprint(f"[-] Wordlist file not found: {wordlist_path}", 'red', attrs=['bold'])
                continue

            wordlist = import_wordlist(wordlist_path)
            if not wordlist:
                cprint(f"[-] Wordlist {wordlist_path} is empty or could not be loaded.", 'red', attrs=['bold'])
                continue
        
            cprint(f"[*] Starting directory enumeration for {target_domain} with {wordlist_path} using {num_threads} threads...", 'yellow')  # Colored output
            found_directories = threaded_directory_enumeration(target_domain, wordlist, num_threads)
            all_found_directories.update(found_directories)
        
        if all_found_directories:
            cprint(f"\n[*] Found directories for {target_domain}:", 'green', attrs=['bold'])  # Colored output and newline
            for directory in sorted(list(all_found_directories)):  # Sort for consistent output
                cprint(f"[+] {directory}", 'green')  # Colored output
        else:
            cprint(f"\n[-] No directories found for {target_domain}.", 'red')  # Colored output and newline
    except KeyboardInterrupt:
        cprint("\n[-] User interrupted the directory enumeration process. Exiting gracefully.", 'red', attrs=['bold'])
        sys.exit(0)
    except Exception as e:
        cprint(f"\n[-] An unexpected error occurred during directory enumeration: {e}", 'red', attrs=['bold'])
        sys.exit(1)

if __name__ == "__main__":
    main()