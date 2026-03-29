import typer
import asyncio
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from transforms import dns_lookup, shodan_recon, whois

load_dotenv()  # Load environment variables from .env file
app = typer.Typer(no_args_is_help=True)
console = Console()


def display_scan_results(all_entities, title="Scan Results"):
    if all_entities:
        table = Table(title=title)
        table.add_column("No", style="white", no_wrap=True)
        table.add_column("Type", style="cyan")
        table.add_column("Value", style="magenta")
        table.add_column("Source", style="yellow")
        
        for i, entity in enumerate(all_entities, start=1):
            table.add_row(str(i), entity.type, entity.value, entity.source)
        
        console.print(table)
    else:
        console.print("[bold red]No results found.[/bold red]")

@app.command(no_args_is_help=True,
             epilog="[bold]Example:[/bold]\n\n  python recon_cli.py allscan google.com")
def allscan(target: str):
    """Run all recon modules against the target."""
    console.print(f"Running all recon modules on [bold green]{target}[/bold green]...")
    
    # Run DNS Lookup
    dns_entities = asyncio.run(dns_lookup.run(target, None))
    
    # Run Shodan Recon: Skip for now, no paid API key available, but you can uncomment if you have one
    # shodan_entities = shodan_recon.run_shodan_ip(target)

    # Extract IPv4 addresses from DNS results for WHOIS lookup
    ipv4_entities = [e for e in dns_entities if e.type == "IPv4"]

    # Run WHOIS Lookup
    whois_lookup = whois.run(target)

    whois_ip_entities = []
    
    for ipv4_entity in ipv4_entities:
        whois_ip_entities.extend(whois.run(ipv4_entity.value))
    
    all_entities = dns_entities + whois_lookup + whois_ip_entities
    
    display_scan_results(all_entities, title="All Recon Results")


@app.command(
        no_args_is_help=True,
        epilog="[bold]Examples:[/bold]\n\n  python recon_cli.py dnsscan google.com\n  python recon_cli.py dnsscan example.com --art CAA")
def dnsscan(
    target: str = typer.Argument(help="Target domain, e.g., google.com"),
    art: str = typer.Option(None, help="Additional DNS record type not in default list['A', 'AAAA', 'MX', 'CNAME', 'MX', 'TXT'], e.g., CAA, PTR, SOA, SRV, etc."),
):
    """Run DNS Lookup against the target."""
    console.print(f"Running recon on [bold green]{target}[/bold green]...")

    entities = asyncio.run(dns_lookup.run(target, art))
    
    display_scan_results(entities, title="DNS Lookup Results")

@app.command(no_args_is_help=True)
def shodan(target: str = typer.Argument(help="Target IP address for Shodan recon e.g., 192.168.1.32")):
    """Run Shodan recon against the target."""
    console.print(f"Running Shodan recon on [bold green]{target}[/bold green]...")
    
    entities = shodan_recon.run_shodan_ip(target)
    
    display_scan_results(entities, title="Shodan Recon Results")

@app.command(
        no_args_is_help=True,
        epilog="[bold]Example:[/bold]\n\n  python recon_cli.py whois-lookup google.com")
def whois_lookup(target: str = typer.Argument(help="Target domain, e.g., google.com")):
    """Run WHOIS lookup against the target."""
    console.print(f"Running WHOIS lookup on [bold green]{target}[/bold green]...")

    entities = whois.run(target)

    display_scan_results(entities, title="WHOIS Lookup Results")


if __name__ == "__main__":
    app()