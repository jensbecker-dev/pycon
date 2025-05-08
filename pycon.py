import dir_en
import subd
import ports
import os
import sys
import argparse
from dir_en import import_wordlist # Import utility from dir_en
from pyfiglet import figlet_format
from termcolor import cprint, colored
import tqdm # <--- Add tqdm import

def banner():
    print("\n")
    tool_name = "   PYC0N   " # <--- Ersetze dies durch den Namen deines Tools!

    # Wähle eine Schriftart für den Banner.
    # Einige große oder eindrucksvolle Schriftarten sind:
    # 'big', 'banner', 'standard', 'slant', 'roman', 'shadow', 'epic'
    # Probiere verschiedene aus, um zu sehen, welche dir am besten gefällt.
    font_name = "slant" # <--- Hier die Schriftart auswählen
    banner_text = figlet_format(tool_name, font=font_name)
    # Füge die Bannerfarbe hinzu
    colored_banner = colored(banner_text, 'cyan', attrs=['bold'])
    # Füge den Banner in die Konsole ein
    print(colored_banner)

def main():

    banner()

    parser = argparse.ArgumentParser(description="Main tool to run subdomain and directory enumeration.")
    parser.add_argument('--target', type=str, required=True, help="The target domain (e.g., example.com)")
    parser.add_argument('--wordlist-dir', type=str, default="wordlists/directories.txt", help="Path to the primary wordlist file for directory enumeration (default: wordlists/directories.txt)")
    parser.add_argument('--threads', type=int, default=10, help="Number of threads for directory enumeration (default: 10)")

    args = parser.parse_args()

    target_domain = args.target.strip()
    wordlist_path_dir_primary = args.wordlist_dir.strip()
    wordlist_path_dir_secondary = "wordlists/directories_med.txt" # Hardcoded second wordlist
    num_threads_dir = args.threads

    if not target_domain:
        cprint("[-] Target domain is required. Exiting.", 'red', attrs=['bold'])
        sys.exit(1)

    # Starting port scan
    cprint(f"\n[*] Starting port scan for target: {target_domain}", 'yellow', attrs=['bold'])
    ports_input = "1-10524"  # Default port range
    num_threads_ports = 10  # Default number of threads for port scanning
    ports_list = []
    for part in ports_input.split(','):
        if '-' in part:
            start, end = part.split('-')
            ports_list.extend(range(int(start), int(end) + 1))
        else:
            ports_list.append(int(part))
    ports_list = list(set(ports_list))  # Remove duplicates
    ports_list.sort()  # Sort for consistent output

    ports_found = ports.threaded_port_scan(target_domain, ports_list, num_threads_ports)

    if ports_found:
        cprint(f"\n[*] Open ports for {target_domain}:", 'green', attrs=['bold'])
        for port in sorted(list(ports_found.keys())):  # Sort for consistent output
            cprint(f"[+] Port {port} is open", 'green')
    else:
        cprint(f"\n[-] No open ports found for {target_domain}.", 'red')

    try:
        cprint(f"\n[*] Starting enumeration for target: {target_domain}", 'yellow', attrs=['bold'])

        # Subdomain enumeration
        cprint(f"\n[*] Performing subdomain enumeration for {target_domain}...", 'yellow')
        found_subdomains = subd.get_subdomains_w_pub_dns(target_domain)
        # Print subdomain results immediately
        if found_subdomains:
            cprint("\n[*] Found Subdomains:", 'green', attrs=['bold'])
            for subdomain in sorted(list(found_subdomains)): # Sort for consistent output
                cprint(f"[+] {subdomain}", 'green')
        else:
            cprint(f"\n[-] No subdomains found for {target_domain}.", 'red')

        all_found_directories = set() # Use a set to store all found directories to avoid duplicates

        # Directory enumeration - Primary wordlist
        cprint(f"\n[*] Performing directory enumeration for {target_domain} using primary wordlist: {wordlist_path_dir_primary} with {num_threads_dir} threads...", 'yellow')
        
        dir_wordlist_items_primary = import_wordlist(wordlist_path_dir_primary)
        if not dir_wordlist_items_primary:
            cprint(f"[-] Wordlist for primary directory enumeration ('{wordlist_path_dir_primary}') is empty or could not be loaded. Skipping this scan.", 'red')
        else:
            found_directories_primary = dir_en.threaded_directory_enumeration(target_domain, dir_wordlist_items_primary, num_threads_dir)
            if found_directories_primary:
                cprint(f"\n[*] Found Directories (from {os.path.basename(wordlist_path_dir_primary)}):", 'green', attrs=['bold'])
                for directory in sorted(list(found_directories_primary)):
                    cprint(f"[+] {directory}", 'green')
                all_found_directories.update(found_directories_primary)
            else:
                cprint(f"\n[-] No directories found for {target_domain} using {os.path.basename(wordlist_path_dir_primary)}.", 'red')

        # Directory enumeration - Secondary wordlist (directories_med.txt)
        cprint(f"\n[*] Performing directory enumeration for {target_domain} using secondary wordlist: {wordlist_path_dir_secondary} with {num_threads_dir} threads...", 'yellow')
        
        dir_wordlist_items_secondary = import_wordlist(wordlist_path_dir_secondary)
        if not dir_wordlist_items_secondary:
            cprint(f"[-] Wordlist for secondary directory enumeration ('{wordlist_path_dir_secondary}') is empty or could not be loaded. Skipping this scan.", 'red')
        else:
            found_directories_secondary = dir_en.threaded_directory_enumeration(target_domain, dir_wordlist_items_secondary, num_threads_dir)
            if found_directories_secondary:
                cprint(f"\n[*] Found Directories (from {os.path.basename(wordlist_path_dir_secondary)}):", 'green', attrs=['bold'])
                for directory in sorted(list(found_directories_secondary)):
                    cprint(f"[+] {directory}", 'green')
                all_found_directories.update(found_directories_secondary)
            else:
                cprint(f"\n[-] No directories found for {target_domain} using {os.path.basename(wordlist_path_dir_secondary)}.", 'red')

        # Print the combined directory results if any were found from any directory scan
        if all_found_directories:
            cprint("\n[*] Found Directories (Combined Results from all directory scans):", 'green', attrs=['bold'])
            for directory in sorted(list(all_found_directories)): # Sort for consistent output
                cprint(f"[+] {directory}", 'green')
        else:
            # This message is shown if no directories were added to all_found_directories.
            # Individual messages for skipped scans or scans that found nothing would have already appeared.
            cprint(f"\n[-] No directories found for {target_domain} from any directory scan.", 'red')

        # Subdomain results were already printed earlier.
            
    except KeyboardInterrupt:
        cprint("\n[-] User interrupted the process. Exiting gracefully.", 'red', attrs=['bold'])
        sys.exit(0)
    except Exception as e:
        cprint(f"\n[-] An unexpected error occurred: {e}", 'red', attrs=['bold'])
        sys.exit(1)

if __name__ == "__main__":
    main()