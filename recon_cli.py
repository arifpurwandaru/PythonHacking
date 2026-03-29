import typer
import asyncio
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from transforms import dns_lookup, shodan_recon

load_dotenv()  # Load environment variables from .env file
app = typer.Typer(no_args_is_help=True)
console = Console()

@app.command(
        no_args_is_help=True,
        epilog="[bold]Examples:[/bold]\n\n  python recon_cli.py dnsscan google.com\n  python recon_cli.py dnsscan example.com --art CAA",
        rich_help_panel=True)
def dnsscan(
    target: str = typer.Argument(help="Target domain, e.g., google.com"),
    art: str = typer.Option(None, help="Additional DNS record type not in default list['A', 'AAAA', 'MX', 'CNAME', 'MX', 'TXT'], e.g., CAA, PTR, SOA, SRV, etc."),
):
    """Run DNS Lookup against the target."""
    console.print(f"Running recon on [bold green]{target}[/bold green]...")

    entities = asyncio.run(dns_lookup.run(target, art))
    
    if entities:
        table = Table(title="Recon Results")
        table.add_column("Type", style="cyan")
        table.add_column("Value", style="magenta")
        table.add_column("Source", style="yellow")
        
        for entity in entities:
            table.add_row(entity.type, entity.value, entity.source)
        
        console.print(table)
    else:
        console.print("[bold red]No results found.[/bold red]")

@app.command(no_args_is_help=True)
def shodan(target: str = typer.Argument(help="Target IP address for Shodan recon e.g., 192.168.1.32")):
    """Run Shodan recon against the target."""
    console.print(f"Running Shodan recon on [bold green]{target}[/bold green]...")
    
    entities = shodan_recon.run_shodan_ip(target)
    
    if entities:
        table = Table(title="Shodan Recon Results")
        table.add_column("Type", style="cyan")
        table.add_column("Value", style="magenta")
        table.add_column("Source", style="yellow")
        
        for entity in entities:
            table.add_row(entity.type, entity.value, entity.source)
        
        console.print(table)
    else:
        console.print("[bold red]No results found.[/bold red]")


if __name__ == "__main__":
    app()