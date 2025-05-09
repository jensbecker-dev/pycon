import dir_en
import subd
import ports
import os
import sys
import argparse
import asyncio
from dir_en import import_wordlist
from pyfiglet import figlet_format
from termcolor import cprint, colored
import tqdm
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import time

# Initialize rich console
console = Console()

def banner():
    print("\n")
    tool_name = " PYC0N "
    font_name = "slant"
    banner_text = figlet_format(tool_name, font=font_name)
    colored_banner = colored(banner_text, 'cyan', attrs=['bold'])
    print(colored_banner)
    
    # Add timestamp and version info with rich
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    console.print(Panel(f"[cyan]Python-based recon toolset v1.1.0[/cyan]\n[yellow]Started at: {now}[/yellow]", 
                       border_style="blue", expand=False))

async def run_port_scan(target_domain, ports_list, num_threads_ports):
    console.print("[yellow]Starting port scan...[/yellow]")
    
    # Use a thread pool for the blocking port scan operation
    with console.status("[bold green]Scanning ports...") as status:
        with ThreadPoolExecutor(max_workers=1) as executor:
            # Run the port scan in the executor to prevent blocking the event loop
            ports_found = await asyncio.get_event_loop().run_in_executor(
                executor, 
                ports.threaded_port_scan, 
                target_domain, 
                ports_list, 
                num_threads_ports
            )
    
    return ports_found

async def run_subdomain_scan(target_domain):
    console.print("[yellow]Starting subdomain enumeration...[/yellow]")
    
    # Use a thread pool for the blocking DNS operations
    with console.status("[bold green]Scanning subdomains...") as status:
        with ThreadPoolExecutor(max_workers=1) as executor:
            found_subdomains = await asyncio.get_event_loop().run_in_executor(
                executor,
                subd.get_subdomains_w_pub_dns,
                target_domain
            )
    
    return found_subdomains

async def run_directory_scan(target_domain, wordlist_path, num_threads_dir):
    console.print(f"[yellow]Starting directory scan with wordlist: {wordlist_path}[/yellow]")
    
    dir_wordlist_items = import_wordlist(wordlist_path)
    if not dir_wordlist_items:
        console.print(f"[red]Wordlist '{wordlist_path}' is empty or could not be loaded. Skipping this scan.[/red]")
        return {}
    
    # Use async directory enumeration for better performance and status information
    with console.status(f"[bold green]Scanning directories with {os.path.basename(wordlist_path)}...") as status:
        try:
            # Run the enhanced async directory scan with status information
            found_directories = await dir_en.async_directory_enumeration(target_domain, dir_wordlist_items, max_concurrent=num_threads_dir)
            return found_directories
        except Exception as e:
            console.print(f"[red]Error during directory scan: {str(e)}[/red]")
            return {}

def display_results(target_domain, ports_found, found_subdomains, all_found_directories):
    # Create a nice table for the results
    table = Table(title=f"[bold cyan]Scan Results for {target_domain}[/bold cyan]", show_header=True, header_style="bold magenta", width=100)
    
    # Add columns with better styling
    table.add_column("Category", style="cyan", no_wrap=True)
    table.add_column("Results", style="green")
    
    # Add port scan results with more details
    if ports_found:
        port_details = []
        for port in sorted(list(ports_found.keys())):
            service = ports_found[port] if isinstance(ports_found[port], str) else "Unknown"
            port_details.append(f"[bold]{port}[/bold]: {service}")
        ports_str = "\n".join(port_details)
        table.add_row("Open Ports", ports_str)
    else:
        table.add_row("Open Ports", "[red]None found[/red]")
    
    # Add subdomain results
    if found_subdomains:
        subdomains_str = "\n".join([f"[bold]{subdomain}[/bold]" for subdomain in sorted(found_subdomains)])
        table.add_row("Subdomains", subdomains_str)
    else:
        table.add_row("Subdomains", "[red]None found[/red]")
    
    # Add directory results with more details
    if all_found_directories:
        dirs_details = []
        if isinstance(all_found_directories, dict):
            # If all_found_directories is a dictionary with status info
            for url, status_info in sorted(all_found_directories.items()):
                dirs_details.append(f"[bold]{url}[/bold] {status_info}")
        else:
            # If all_found_directories is a list or set
            for directory in sorted(list(all_found_directories)):
                dirs_details.append(f"[bold]{directory}[/bold]")
        dirs_str = "\n".join(dirs_details)
        table.add_row("Directories", dirs_str)
    else:
        table.add_row("Directories", "[red]None found[/red]")
    
    console.print("\n")
    console.print(table)
    
    # Save results to file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"results_{target_domain}_{timestamp}.txt"
    
    # Ensure results directory exists
    results_dir = "results"
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
    
    # Save file in results directory with more detailed information
    filepath = os.path.join(results_dir, filename)
    
    with open(filepath, 'w') as f:
        f.write(f"PYCON Scan Results for {target_domain}\n")
        f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("=== OPEN PORTS ===\n")
        if ports_found:
            for port in sorted(list(ports_found.keys())):
                service = ports_found[port] if isinstance(ports_found[port], str) else ""
                f.write(f"Port {port} {service}\n")
        else:
            f.write("None found\n")
        
        f.write("\n=== SUBDOMAINS ===\n")
        if found_subdomains:
            for subdomain in sorted(found_subdomains):
                f.write(f"{subdomain}\n")
        else:
            f.write("None found\n")
        
        f.write("\n=== DIRECTORIES ===\n")
        if all_found_directories:
            if isinstance(all_found_directories, dict):
                # If all_found_directories is a dictionary with status info
                for url, status_info in sorted(all_found_directories.items()):
                    f.write(f"{url} {status_info}\n")
            else:
                # If all_found_directories is a list or set
                for directory in sorted(list(all_found_directories)):
                    f.write(f"{directory}\n")
        else:
            f.write("None found\n")
    
    console.print(f"\n[cyan]Results saved to [bold]{filepath}[/bold][/cyan]")

async def main_async(args):
    try:
        target_domain = args.target.strip()
        wordlist_path_dir_primary = args.wordlist_dir.strip()
        wordlist_path_dir_secondary = "wordlists/directories_med.txt"
        num_threads_dir = args.threads
        output_format = args.format
        
        if not target_domain:
            console.print("[red bold]Target domain is required. Exiting.[/red bold]")
            sys.exit(1)
        
        # Port scanning setup
        console.print(f"\n[yellow bold]Target: {target_domain}[/yellow bold]")
        
        # Default port range and custom ports
        ports_input = "1-1052" 
        custom_ports = ["3389", "3390", "4000", "4444", "5000", "8000", "8080", "8443", "8888"]
        print("[+]  Custom ports: ", custom_ports)
        num_threads_ports = 10
        ports_list = []
        
        # Add custom ports to the list
        for port in custom_ports:
            ports_list.append(int(port))
        
        # Parse the input port range
        if ports_input:
            ports_input = ports_input.strip()
            if ports_input.startswith('[') and ports_input.endswith(']'):
                ports_input = ports_input[1:-1]
        
        for part in ports_input.split(','):
            if '-' in part:
                start, end = part.split('-')
                ports_list.extend(range(int(start), int(end) + 1))
            else:
                ports_list.append(int(part))
        
        ports_list = list(set(ports_list))  # Remove duplicates
        ports_list.sort()  # Sort for consistent output
        
        # Run port scan, subdomain scan, and directory scans concurrently
        tasks = [
            run_port_scan(target_domain, ports_list, num_threads_ports),
            run_subdomain_scan(target_domain),
            run_directory_scan(target_domain, wordlist_path_dir_primary, num_threads_dir),
            run_directory_scan(target_domain, wordlist_path_dir_secondary, num_threads_dir),
        ]
        
        # Wait for all tasks to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        ports_found = results[0] if not isinstance(results[0], Exception) else {}
        found_subdomains = results[1] if not isinstance(results[1], Exception) else []
        
        # Process directory scan results
        dir_results_1 = results[2] if not isinstance(results[2], Exception) else {}
        dir_results_2 = results[3] if not isinstance(results[3], Exception) else {}
        
        # Combine directory results - handle dictionaries properly
        all_found_directories = {}
        all_found_directories.update(dir_results_1)
        all_found_directories.update(dir_results_2)
        
        # Display the results
        display_results(target_domain, ports_found, found_subdomains, all_found_directories)
        
    except KeyboardInterrupt:
        console.print("\n[red bold]User interrupted the process. Exiting gracefully.[/red bold]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red bold]An unexpected error occurred: {e}[/red bold]")
        sys.exit(1)

def main():

    os.system('cls' if os.name == 'nt' else 'clear')

    banner()
    
    parser = argparse.ArgumentParser(description="PyCon - Python Reconnaissance Tool")
    parser.add_argument('--target', type=str, required=True, help="The target domain (e.g., example.com)")
    parser.add_argument('--wordlist-dir', type=str, default="wordlists/directories.txt", help="Path to the primary wordlist file for directory enumeration (default: wordlists/directories.txt)")
    parser.add_argument('--threads', type=int, default=10, help="Number of threads for directory enumeration (default: 10)")
    parser.add_argument('--format', type=str, choices=['text', 'json', 'xml'], default='text', help="Output format (default: text)")
    
    args = parser.parse_args()
    
    # Run the async main function
    if sys.platform.startswith('win'):
        # Windows specific event loop policy
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    asyncio.run(main_async(args))

if __name__ == "__main__":
    main()