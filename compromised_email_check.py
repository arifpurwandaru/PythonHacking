#!/usr/bin/env python3
"""
Email Breach Checker using Have I Been Pwned API
Checks if email addresses have been compromised in data breaches.
"""

import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

import requests
import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# Load environment variables
load_dotenv()

app = typer.Typer(help="Check if email addresses have been compromised in data breaches")
console = Console()

# Have I Been Pwned API endpoints
HIBP_BREACH_API = "https://haveibeenpwned.com/api/v3/breachedaccount/"
HIBP_PASTE_API = "https://haveibeenpwned.com/api/v3/pasteaccount/"
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")

# User agent as recommended by HIBP
USER_AGENT = "PythonHacking-EmailChecker"


def get_headers() -> Dict[str, str]:
    """Get headers for HIBP API requests."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json"
    }
    
    if HIBP_API_KEY:
        headers["hibp-api-key"] = HIBP_API_KEY
    
    return headers


def check_email_breaches(email: str) -> List[Dict[str, Any]]:
    """
    Check if email has been in any breaches.
    
    Args:
        email: Email address to check
        
    Returns:
        List of breach dictionaries with details
    """
    url = f"{HIBP_BREACH_API}{email}"
    
    try:
        response = requests.get(
            url,
            headers=get_headers(),
            timeout=10,
            params={"truncateResponse": "false"}
        )
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return []  # No breaches found
        elif response.status_code == 401:
            console.print("[red]Error: Invalid or missing API key[/red]")
            console.print("[yellow]Get your free API key at: https://haveibeenpwned.com/API/Key[/yellow]")
            raise typer.Exit(1)
        elif response.status_code == 429:
            console.print("[red]Error: Rate limit exceeded. Please wait before trying again.[/red]")
            raise typer.Exit(1)
        else:
            console.print(f"[red]Error: API returned status code {response.status_code}[/red]")
            raise typer.Exit(1)
            
    except requests.RequestException as e:
        console.print(f"[red]Error connecting to API: {e}[/red]")
        raise typer.Exit(1)


def check_email_pastes(email: str) -> List[Dict[str, Any]]:
    """
    Check if email has been found in pastes.
    
    Args:
        email: Email address to check
        
    Returns:
        List of paste dictionaries with details
    """
    url = f"{HIBP_PASTE_API}{email}"
    
    try:
        response = requests.get(
            url,
            headers=get_headers(),
            timeout=10
        )
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return []  # No pastes found
        else:
            return []  # Don't fail on paste errors
            
    except requests.RequestException:
        return []  # Don't fail on paste errors


def format_date(date_str: Optional[str]) -> str:
    """Format ISO date string to readable format."""
    if not date_str:
        return "Unknown"
    
    try:
        date_obj = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        return date_obj.strftime("%B %d, %Y")
    except:
        return date_str


def display_breach_details(breach: Dict[str, Any], index: int):
    """Display detailed information about a breach."""
    
    # Create breach title
    title = f"🔴 Breach #{index}: {breach.get('Name', 'Unknown')}"
    
    # Build breach details
    details = []
    
    # Domain/Source
    domain = breach.get('Domain', 'N/A')
    details.append(f"[bold cyan]Source:[/bold cyan] {domain}")
    
    # Breach date
    breach_date = format_date(breach.get('BreachDate'))
    details.append(f"[bold yellow]Date:[/bold yellow] {breach_date}")
    
    # Number of accounts
    pwn_count = breach.get('PwnCount', 0)
    details.append(f"[bold red]Accounts Affected:[/bold red] {pwn_count:,}")
    
    # Description
    description = breach.get('Description', 'No description available')
    # Remove HTML tags for cleaner display
    import re
    description = re.sub('<[^<]+?>', '', description)
    details.append(f"\n[bold]Description:[/bold]\n{description}")
    
    # Data classes (types of data compromised)
    data_classes = breach.get('DataClasses', [])
    if data_classes:
        data_str = ", ".join(data_classes)
        details.append(f"\n[bold magenta]Compromised Data:[/bold magenta]\n{data_str}")
    
    # Verification status
    is_verified = breach.get('IsVerified', False)
    verification = "✓ Verified" if is_verified else "⚠ Unverified"
    details.append(f"\n[bold]Status:[/bold] {verification}")
    
    # Create panel with all details
    panel = Panel(
        "\n".join(details),
        title=title,
        title_align="left",
        border_style="red" if is_verified else "yellow",
        padding=(1, 2)
    )
    
    console.print(panel)


@app.command()
def check(
    email: Optional[str] = typer.Option(
        None,
        "--email", "-e",
        help="Email address to check"
    ),
    show_pastes: bool = typer.Option(
        False,
        "--pastes",
        help="Also check for email in pastes"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Show detailed information"
    )
):
    """Check if a single email address has been compromised."""
    
    # Check for API key
    if not HIBP_API_KEY:
        console.print("\n[bold red]⚠️  HIBP API KEY REQUIRED[/bold red]\n")
        console.print("[yellow]The email breach API requires a free API key.[/yellow]")
        console.print("[green]Get your free API key (takes 2 minutes):[/green]")
        console.print("[cyan]https://haveibeenpwned.com/API/Key[/cyan]\n")
        
        console.print("[bold]Quick Setup:[/bold]")
        console.print(f"  Run: [cyan]python {Path(__file__).name} setup[/cyan]\n")
        
        console.print("[bold]Alternatives:[/bold]")
        console.print(f"  • Manual check: [cyan]python {Path(__file__).name} webcheck your@email.com[/cyan]")
        console.print(f"  • Password check (no key needed): [cyan]python compromised_check.py check[/cyan]\n")
        
        raise typer.Exit(1)
    
    if email is None:
        email = typer.prompt("Enter email address to check")
    
    if not email or "@" not in email:
        console.print("[red]Invalid email address[/red]")
        raise typer.Exit(1)
    
    console.print(f"\n[bold]Checking email:[/bold] {email}\n")
    
    # Check breaches
    with console.status("[bold blue]Searching breach databases..."):
        breaches = check_email_breaches(email)
    
    if breaches:
        console.print(f"[bold red]⚠️  EMAIL COMPROMISED![/bold red]")
        console.print(f"[yellow]Found in {len(breaches)} data breach(es)[/yellow]\n")
        
        # Display each breach
        for idx, breach in enumerate(breaches, 1):
            display_breach_details(breach, idx)
            if idx < len(breaches):
                console.print()  # Add spacing between breaches
        
        # Summary table
        console.print("\n[bold]Summary of Breaches:[/bold]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("#", justify="right", style="cyan", width=4)
        table.add_column("Source", style="white")
        table.add_column("Date", style="yellow")
        table.add_column("Accounts", justify="right", style="red")
        
        for idx, breach in enumerate(breaches, 1):
            table.add_row(
                str(idx),
                breach.get('Domain', breach.get('Name', 'Unknown')),
                format_date(breach.get('BreachDate')),
                f"{breach.get('PwnCount', 0):,}"
            )
        
        console.print(table)
        
    else:
        console.print(f"[bold green]✓ Email appears safe[/bold green]")
        console.print("[green]Not found in known data breaches[/green]\n")
    
    # Check pastes if requested
    if show_pastes:
        console.print("\n[bold]Checking pastes...[/bold]")
        with console.status("[bold blue]Searching paste sites..."):
            pastes = check_email_pastes(email)
        
        if pastes:
            console.print(f"[yellow]⚠️  Found in {len(pastes)} paste(s)[/yellow]\n")
            
            for idx, paste in enumerate(pastes, 1):
                source = paste.get('Source', 'Unknown')
                title = paste.get('Title', 'Untitled')
                date = format_date(paste.get('Date'))
                console.print(f"{idx}. [{source}] {title or 'No title'} - {date}")
        else:
            console.print("[green]✓ Not found in any pastes[/green]")


@app.command()
def check_file(
    filepath: Path = typer.Argument(
        ...,
        help="File containing email addresses (one per line)",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True
    ),
    show_sources: bool = typer.Option(
        True,
        "--show-sources/--no-sources",
        help="Show breach sources for each email"
    )
):
    """Check multiple email addresses from a file."""
    
    if not HIBP_API_KEY:
        console.print("[red]Error: HIBP_API_KEY required for batch checking[/red]")
        console.print("[yellow]Get your API key at: https://haveibeenpwned.com/API/Key[/yellow]")
        console.print("[yellow]Then set it in a .env file: HIBP_API_KEY=your_key_here[/yellow]")
        raise typer.Exit(1)
    
    try:
        emails = filepath.read_text().splitlines()
        emails = [e.strip() for e in emails if e.strip() and "@" in e]
    except Exception as e:
        console.print(f"[red]Error reading file: {e}[/red]")
        raise typer.Exit(1)
    
    if not emails:
        console.print("[yellow]No valid email addresses found in file[/yellow]")
        raise typer.Exit(0)
    
    console.print(f"\n[bold]Checking {len(emails)} email address(es)...[/bold]\n")
    
    results = []
    
    for idx, email in enumerate(emails, 1):
        console.print(f"[cyan]Checking {idx}/{len(emails)}:[/cyan] {email}")
        
        breaches = check_email_breaches(email)
        results.append({
            "email": email,
            "breaches": breaches
        })
        
        # Rate limiting - be nice to the API
        if idx < len(emails):
            import time
            time.sleep(1.6)  # HIBP allows ~1 request per 1.5 seconds
    
    # Display results
    console.print("\n[bold]Results:[/bold]\n")
    
    compromised_count = 0
    
    for result in results:
        email = result["email"]
        breaches = result["breaches"]
        
        if breaches:
            compromised_count += 1
            console.print(f"[red]⚠️  {email}[/red] - {len(breaches)} breach(es)")
            
            if show_sources:
                sources = [b.get('Domain', b.get('Name', '?')) for b in breaches]
                console.print(f"    Sources: {', '.join(sources)}")
        else:
            console.print(f"[green]✓ {email}[/green] - Clean")
        
        console.print()
    
    # Summary
    console.print(f"[bold]Summary:[/bold]")
    console.print(f"  Total checked: {len(emails)}")
    console.print(f"  [red]Compromised: {compromised_count}[/red]")
    console.print(f"  [green]Clean: {len(emails) - compromised_count}[/green]\n")


@app.command()
def info():
    """Show information about the email checking service."""
    
    console.print("\n[bold cyan]Email Breach Checker[/bold cyan]")
    console.print("\nThis tool uses the Have I Been Pwned API to check if email")
    console.print("addresses have been compromised in known data breaches.\n")
    
    console.print("[bold]Features:[/bold]")
    console.print("  • Check single or multiple email addresses")
    console.print("  • View detailed breach information")
    console.print("  • See breach sources, dates, and compromised data types")
    console.print("  • Check for email in pastes")
    
    console.print("\n[bold cyan]⚠️  API KEY REQUIREMENT:[/bold cyan]")
    console.print("  [yellow]The email breach API requires an API key.[/yellow]")
    console.print("  [green]The API key is FREE for personal use![/green]")
    
    console.print("\n[bold]API Key Setup:[/bold]")
    console.print("  1. Get a free API key at: https://haveibeenpwned.com/API/Key")
    console.print("  2. Create a .env file in your project directory")
    console.print("  3. Add your key: HIBP_API_KEY=your_key_here")
    console.print("  4. Or run: python compromised_email_check.py setup")
    
    console.print("\n[bold]Alternatives Without API Key:[/bold]")
    console.print("  • Manual check: https://haveibeenpwned.com")
    console.print("  • Password checker: python compromised_check.py (no key needed!)")
    
    console.print("\n[bold]API Information:[/bold]")
    console.print(f"  Service: Have I Been Pwned")
    console.print(f"  Website: https://haveibeenpwned.com")
    console.print(f"  API: https://haveibeenpwned.com/API/v3")
    
    if HIBP_API_KEY:
        console.print(f"\n[green]✓ API Key configured[/green]")
    else:
        console.print(f"\n[yellow]⚠️  No API Key found - get your free key above[/yellow]")
    
    console.print()


@app.command()
def webcheck(
    email: Optional[str] = typer.Argument(
        None,
        help="Email address to check"
    )
):
    """Open Have I Been Pwned website to manually check an email (no API key needed)."""
    
    if email:
        import urllib.parse
        encoded_email = urllib.parse.quote(email)
        url = f"https://haveibeenpwned.com/account/{encoded_email}"
    else:
        url = "https://haveibeenpwned.com"
    
    console.print(f"\n[cyan]Opening in browser:[/cyan] {url}\n")
    console.print("[yellow]Note: This is a manual check via the website.[/yellow]")
    console.print("[yellow]For automated checking, get a free API key with 'setup' command.[/yellow]\n")
    
    # Try to open in browser
    import webbrowser
    try:
        webbrowser.open(url)
        console.print("[green]✓ Browser opened[/green]\n")
    except:
        console.print(f"[yellow]Please manually visit: {url}[/yellow]\n")


@app.command()
def setup():
    """Guide user through API key setup."""
    
    console.print("\n[bold cyan]API Key Setup Guide[/bold cyan]\n")
    
    console.print("[bold]Step 1:[/bold] Get your API key")
    console.print("  Visit: https://haveibeenpwned.com/API/Key")
    console.print("  The API key is free for reasonable use\n")
    
    console.print("[bold]Step 2:[/bold] Create or edit your .env file")
    env_path = Path.cwd() / ".env"
    console.print(f"  File location: {env_path}\n")
    
    console.print("[bold]Step 3:[/bold] Add your API key to .env")
    console.print("  Add this line: HIBP_API_KEY=your_actual_key_here\n")
    
    if typer.confirm("Would you like to add the API key now?"):
        api_key = typer.prompt("Enter your HIBP API key", hide_input=True)
        
        try:
            # Check if .env exists
            if env_path.exists():
                content = env_path.read_text()
                if "HIBP_API_KEY" in content:
                    if not typer.confirm(".env already contains HIBP_API_KEY. Overwrite?"):
                        console.print("[yellow]Setup cancelled[/yellow]")
                        return
                    # Replace existing key
                    import re
                    content = re.sub(r'HIBP_API_KEY=.*', f'HIBP_API_KEY={api_key}', content)
                else:
                    content += f"\nHIBP_API_KEY={api_key}\n"
            else:
                content = f"HIBP_API_KEY={api_key}\n"
            
            env_path.write_text(content)
            console.print(f"\n[green]✓ API key saved to {env_path}[/green]")
            console.print("[yellow]Note: Restart the tool for changes to take effect[/yellow]\n")
            
        except Exception as e:
            console.print(f"[red]Error writing .env file: {e}[/red]")
            raise typer.Exit(1)
    else:
        console.print("\n[yellow]Setup skipped. Remember to add your API key manually![/yellow]\n")


def main():
    """Entry point for the application."""
    app()


if __name__ == "__main__":
    main()
