# subdomain enumeration module
import requests
import json
import threading
from queue import Queue
import dns.resolver
import dns.exception
import dns.query
import dns.rdatatype
import tqdm
import argparse
from termcolor import cprint, colored  # Add termcolor import
import sys

def import_wordlist(file_path):
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
    except Exception as e:  # Catch generic exception for other file errors
        cprint(f"[-] Error reading file {file_path}: {e}", 'red')  # Colored output
        return []

def get_subdomains_w_pub_dns(domain):
    """
    Get subdomains for a given domain using a public DNS server.
    """
    resolver = dns.resolver.Resolver(configure=False)  # Prevent reading /etc/resolv.conf
    resolver.nameservers = [
        '8.8.8.8',  # Google Public DNS
        '8.8.4.4'   # Google Public DNS
    ]
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT']
    found_subdomains = set()
    results_queue = Queue()
    threads = []
    pbar = None  # Initialize pbar to None

    common_subs = import_wordlist('wordlists/subdomains.txt')
    if not common_subs:
        cprint("[-] No common subdomains found in the wordlist. Subdomain scan might be ineffective.", 'yellow')

    try:
        # Check the domain itself
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                continue  # Ignore if no record of this type or domain doesn't exist

        if common_subs:
            # Corrected pbar initialization for manual updates
            pbar = tqdm.tqdm(total=len(common_subs), desc=colored("[*] Processing subdomains", 'cyan'), unit="subdomain", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}{postfix}]")

            def check_subdomain(sub, domain_to_check, queue_instance):
                thread_resolver = dns.resolver.Resolver(configure=False)
                thread_resolver.nameservers = ['8.8.8.8', '8.8.4.4']
                subdomain_to_check_fqdn = f"{sub}.{domain_to_check}"
                try:
                    thread_resolver.resolve(subdomain_to_check_fqdn, 'A')
                    queue_instance.put(subdomain_to_check_fqdn)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                    pass
                except Exception: # Catch all other exceptions within the thread
                    pass # Suppress errors within the thread
                finally:
                    if pbar:  # Check if pbar exists before updating
                        try:
                            pbar.update(1) # Manual update
                        except Exception:
                            pass # Ignore errors during pbar update on shutdown
            
            for sub_item in common_subs:  # Iterate over the actual list
                thread = threading.Thread(target=check_subdomain, args=(sub_item, domain, results_queue))
                thread.daemon = True # Set thread as daemon
                threads.append(thread)
                thread.start()

            for thread in threads:
                while thread.is_alive(): # Loop to ensure join, respects timeout
                    thread.join(timeout=0.1) 
        
        while not results_queue.empty():
            found_subdomains.add(results_queue.get())

        # Attempt AXFR
        try:
            ns_answer = resolver.resolve(domain, 'NS')
            for ns_record in ns_answer:
                nameserver = str(ns_record.target)
                try:
                    q = dns.query.xfr(nameserver, domain, relativize=False, timeout=5)
                    for msg in q:
                        for rrset in msg.answer:
                            for item in rrset.items:
                                if item.rdtype == dns.rdatatype.A or item.rdtype == dns.rdatatype.CNAME:
                                    name_str = str(rrset.name)
                                    if name_str.endswith(f".{domain}") and name_str != domain:
                                        found_subdomains.add(name_str)
                except Exception as e: # Catch errors during AXFR for a single nameserver
                    continue
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass # No NS records found or other DNS issue for AXFR setup

        return list(found_subdomains)

    except KeyboardInterrupt:
        cprint("\n[-] Subdomain enumeration interrupted by user.", 'red', attrs=['bold'])
        return list(found_subdomains) # Return partial results
    except Exception as e:
        cprint(f"[-] An error occurred during subdomain enumeration: {e}", 'red', attrs=['bold'])
        return list(found_subdomains) # Return partial results
    finally:
        if pbar:
            pbar.close()
        # Daemonic threads will be cleaned up automatically when the main thread exits.
        # The join loop above attempts to wait for them briefly.

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Subdomain enumeration tool.")
    parser.add_argument('--target', type=str, help="The target domain (e.g., example.com)", required=True)
    args = parser.parse_args()

    target_domain = args.target.strip()

    if not target_domain:
        cprint("[-] No domain provided. Exiting.", 'red', attrs=['bold'])  # Colored output
        exit(1)
    
    try:
        cprint(f"[*] Attempting to find subdomains for: {target_domain} using public DNS", 'yellow')  # Colored output
        subdomains = get_subdomains_w_pub_dns(target_domain)
        if subdomains:
            cprint("\n[*] Found subdomains:", 'green', attrs=['bold'])  # Colored output and newline
            for sub in sorted(list(subdomains)):  # Sort for consistent output
                cprint(f"[+] {sub}", 'green')  # Colored output
        else:
            cprint("\n[-] No subdomains found.", 'red')  # Colored output and newline
    except KeyboardInterrupt:
        cprint("\n[-] User interrupted the subdomain enumeration process. Exiting gracefully.", 'red', attrs=['bold'])
        sys.exit(0)
    except Exception as e:
        cprint(f"\n[-] An unexpected error occurred during subdomain enumeration: {e}", 'red', attrs=['bold'])
        sys.exit(1)