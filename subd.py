# subdomain enumeration module
import requests
import json
import threading
from queue import Queue, Empty
import dns.resolver
import dns.exception
import dns.query
import dns.rdatatype
import tqdm
import argparse
from termcolor import cprint, colored
import sys
import time
import functools
from typing import List, Set, Dict, Any, Optional
import asyncio

# DNS cache for performance optimization
_dns_cache = {}
_dns_cache_lock = threading.Lock()

def dns_cache(func):
    """Decorator to cache DNS lookups for performance"""
    @functools.wraps(func)
    def wrapper(domain_to_check, *args, **kwargs):
        cache_key = f"{domain_to_check}-{args}-{kwargs.get('record_type', 'A')}"
        with _dns_cache_lock:
            if cache_key in _dns_cache:
                return _dns_cache[cache_key]
        
        result = func(domain_to_check, *args, **kwargs)
        
        with _dns_cache_lock:
            _dns_cache[cache_key] = result
        return result
    return wrapper

def import_wordlist(file_path):
    """
    Import a wordlist from a file.
    Filter out comment lines (starting with #) and empty lines.
    """
    try:
        with open(file_path, 'r') as file:
            # Filter out comment lines and empty lines for better efficiency
            wordlist = [line.strip() for line in file 
                       if line.strip() and not line.strip().startswith('#')]
        return wordlist
    except FileNotFoundError:
        cprint(f"[-] File not found: {file_path}", 'red')
        return []
    except Exception as e:
        cprint(f"[-] Error reading file {file_path}: {e}", 'red')
        return []

@dns_cache
def resolve_domain(domain_to_check, record_type='A'):
    """
    Resolve a domain with caching for performance optimization.
    Returns True if domain exists, False otherwise.
    """
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
    resolver.timeout = 2.0  # Faster timeout for better performance
    resolver.lifetime = 4.0  # Total lookup time
    
    try:
        resolver.resolve(domain_to_check, record_type)
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return False
    except Exception:
        return False

def get_subdomains_w_pub_dns(domain, max_workers=20):
    """
    Get subdomains for a given domain using a public DNS server.
    Optimized with worker pool and better error handling.
    """
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [
        '8.8.8.8',  # Google Public DNS
        '8.8.4.4',  # Google Public DNS
        '1.1.1.1'   # Cloudflare DNS (added for redundancy)
    ]
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT']
    found_subdomains = set()
    results_queue = Queue()
    threads = []
    pbar = None
    stop_event = threading.Event()

    common_subs = import_wordlist('wordlists/subdomains.txt')
    if not common_subs:
        cprint("[-] No common subdomains found in the wordlist. Subdomain scan might be ineffective.", 'yellow')
        return []

    try:
        # Verify the base domain first before proceeding
        base_domain_valid = False
        for rtype in ['A', 'NS']:
            try:
                answers = resolver.resolve(domain, rtype)
                if answers:
                    base_domain_valid = True
                    break
            except Exception:
                continue
        
        if not base_domain_valid:
            cprint(f"[-] Warning: Base domain {domain} could not be resolved. Results may be unreliable.", 'yellow')

        # Initialize progress bar with proper error handling
        try:
            pbar = tqdm.tqdm(total=len(common_subs), desc=colored("[*] Processing subdomains", 'cyan'), 
                          unit="subdomain", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}{postfix}]")
        except Exception as e:
            cprint(f"[-] Warning: Could not initialize progress bar: {e}", 'yellow')
            pbar = None

        def check_subdomain(sub, domain_to_check, queue_instance):
            if stop_event.is_set():
                return

            subdomain_to_check_fqdn = f"{sub}.{domain_to_check}"
            try:
                # Use cached resolver function
                if resolve_domain(subdomain_to_check_fqdn):
                    queue_instance.put(subdomain_to_check_fqdn)
            except Exception:
                pass  # Suppress errors within the thread
            finally:
                if pbar and not stop_event.is_set():
                    try:
                        pbar.update(1)
                    except Exception:
                        pass
        
        # Use a thread pool with improved error handling
        batch_size = min(100, len(common_subs))  # Process in batches for better memory management
        for i in range(0, len(common_subs), batch_size):
            if stop_event.is_set():
                break
                
            batch = common_subs[i:i+batch_size]
            active_threads = []
            
            for sub_item in batch:
                if stop_event.is_set():
                    break
                    
                # Limit concurrent threads to avoid resource exhaustion
                while len(active_threads) >= max_workers:
                    active_threads = [t for t in active_threads if t.is_alive()]
                    if len(active_threads) >= max_workers:
                        time.sleep(0.1)
                
                thread = threading.Thread(target=check_subdomain, args=(sub_item, domain, results_queue))
                thread.daemon = True
                active_threads.append(thread)
                threads.append(thread)
                thread.start()
            
            # Join all threads from this batch
            for thread in active_threads:
                while thread.is_alive() and not stop_event.is_set():
                    thread.join(timeout=0.1)
                if stop_event.is_set():
                    break
        
        # Collect results from queue
        while not results_queue.empty():
            try:
                item = results_queue.get(block=False)
                found_subdomains.add(item)
            except Empty:
                break

        # Attempt zone transfer (AXFR) with improved error handling
        try:
            ns_answer = resolver.resolve(domain, 'NS')
            for ns_record in ns_answer:
                if stop_event.is_set():
                    break
                    
                nameserver = str(ns_record.target)
                try:
                    q = dns.query.xfr(nameserver, domain, relativize=False, timeout=5)
                    for msg in q:
                        if stop_event.is_set():
                            break
                        for rrset in msg.answer:
                            for item in rrset.items:
                                if item.rdtype in (dns.rdatatype.A, dns.rdatatype.CNAME):
                                    name_str = str(rrset.name)
                                    if name_str.endswith(f".{domain}") and name_str != f"{domain}.":
                                        found_subdomains.add(name_str[:-1])  # Remove trailing dot
                except Exception:
                    continue
        except Exception:
            pass  # Continue with partial results on error

        return list(found_subdomains)

    except KeyboardInterrupt:
        stop_event.set()
        cprint("\n[-] Subdomain enumeration interrupted by user.", 'red', attrs=['bold'])
        return list(found_subdomains)  # Return partial results
    except Exception as e:
        stop_event.set()
        cprint(f"[-] An error occurred during subdomain enumeration: {e}", 'red', attrs=['bold'])
        return list(found_subdomains)  # Return partial results
    finally:
        # Always clean up progress bar
        if pbar:
            try:
                pbar.close()
            except Exception:
                pass
        
        # Signal all threads to stop
        stop_event.set()
        
        # Brief wait to allow threads to notice stop_event
        time.sleep(0.1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Subdomain enumeration tool.")
    parser.add_argument('--target', type=str, help="The target domain (e.g., example.com)", required=True)
    parser.add_argument('--workers', type=int, default=20, help="Maximum number of concurrent workers (default: 20)")
    args = parser.parse_args()

    target_domain = args.target.strip()
    max_workers = args.workers

    if not target_domain:
        cprint("[-] No domain provided. Exiting.", 'red', attrs=['bold'])
        exit(1)
    
    try:
        cprint(f"[*] Attempting to find subdomains for: {target_domain} using public DNS", 'yellow')
        subdomains = get_subdomains_w_pub_dns(target_domain, max_workers)
        if subdomains:
            cprint("\n[*] Found subdomains:", 'green', attrs=['bold'])
            for sub in sorted(list(subdomains)):
                cprint(f"[+] {sub}", 'green')
        else:
            cprint("\n[-] No subdomains found.", 'red')
    except KeyboardInterrupt:
        cprint("\n[-] User interrupted the subdomain enumeration process. Exiting gracefully.", 'red', attrs=['bold'])
        sys.exit(0)
    except Exception as e:
        cprint(f"\n[-] An unexpected error occurred during subdomain enumeration: {e}", 'red', attrs=['bold'])
        sys.exit(1)