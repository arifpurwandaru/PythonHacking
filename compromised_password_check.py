#!/usr/bin/env python3
"""
Password Compromise Checker using Have I Been Pwned API
Uses k-anonymity to safely check if passwords have been compromised in data breaches.
"""

import hashlib
import sys
from pathlib import Path
from typing import Optional

import requests
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Check if passwords have been compromised in data breaches", no_args_is_help=True)
console = Console()

# Have I Been Pwned API endpoint
HIBP_API_URL = "https://api.pwnedpasswords.com/range/"


def hash_password(password: str) -> str:
    """Hash password using SHA-1 and return uppercase hex."""
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    return sha1_hash


def check_pwned_api(password: str) -> int:
    """
    Check password against Have I Been Pwned API using k-anonymity.
    
    Returns:
        Number of times the password was found in breaches (0 if safe)
    """
    sha1_hash = hash_password(password)
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    
    try:
        response = requests.get(f"{HIBP_API_URL}{prefix}", timeout=5)
        response.raise_for_status()
        
        # Parse response - format is "SUFFIX:COUNT\r\n"
        hashes = (line.split(':') for line in response.text.splitlines())
        
        for hash_suffix, count in hashes:
            if hash_suffix == suffix:
                return int(count)
        
        return 0  # Password not found in breaches
        
    except requests.RequestException as e:
        console.print(f"[red]Error connecting to API: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def check(
    password: Optional[str] = typer.Option(
        None,
        "--password", "-p",
        help="Password to check (insecure - will be visible in shell history)"
    ),
    show_password: bool = typer.Option(
        False,
        "--show",
        help="Show password when typing interactively"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Show detailed information"
    )
):
    """Check if a single password has been compromised."""
    
    if password is None:
        # Prompt for password interactively
        password = typer.prompt(
            "Enter password to check",
            hide_input=not show_password
        )
    
    if not password:
        console.print("[red]Password cannot be empty[/red]")
        raise typer.Exit(1)
    
    with console.status("[bold blue]Checking password..."):
        count = check_pwned_api(password)
    
    if count > 0:
        console.print(f"\n[bold red]⚠️  PASSWORD COMPROMISED![/bold red]")
        console.print(f"[yellow]Found in {count:,} data breaches[/yellow]")
        console.print("[yellow]This password should NOT be used![/yellow]\n")
    else:
        console.print(f"\n[bold green]✓ Password appears safe[/bold green]")
        console.print("[green]Not found in known data breaches[/green]\n")
    
    if verbose:
        sha1 = hash_password(password)
        console.print(f"[dim]SHA-1 Hash: {sha1}[/dim]")


@app.command()
def check_file(
    filepath: Path = typer.Argument(
        ...,
        help="File containing passwords (one per line)",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True
    ),
    show_passwords: bool = typer.Option(
        False,
        "--show-passwords",
        help="Display passwords in output (insecure)"
    )
):
    """Check multiple passwords from a file."""
    
    try:
        passwords = filepath.read_text().splitlines()
        passwords = [p.strip() for p in passwords if p.strip()]
    except Exception as e:
        console.print(f"[red]Error reading file: {e}[/red]")
        raise typer.Exit(1)
    
    if not passwords:
        console.print("[yellow]No passwords found in file[/yellow]")
        raise typer.Exit(0)
    
    console.print(f"\n[bold]Checking {len(passwords)} password(s)...[/bold]\n")
    
    # Create results table
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("#", justify="right", style="cyan")
    if show_passwords:
        table.add_column("Password", style="white")
    table.add_column("Status", justify="center")
    table.add_column("Times Seen", justify="right")
    
    compromised_count = 0
    
    for idx, password in enumerate(passwords, 1):
        with console.status(f"[bold blue]Checking password {idx}/{len(passwords)}..."):
            count = check_pwned_api(password)
        
        if count > 0:
            compromised_count += 1
            status = "[red]⚠️  COMPROMISED[/red]"
            times = f"[yellow]{count:,}[/yellow]"
        else:
            status = "[green]✓ Safe[/green]"
            times = "[green]0[/green]"
        
        row = [str(idx)]
        if show_passwords:
            row.append(password[:20] + "..." if len(password) > 20 else password)
        row.extend([status, times])
        table.add_row(*row)
    
    console.print(table)
    
    # Summary
    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"  Total checked: {len(passwords)}")
    console.print(f"  [red]Compromised: {compromised_count}[/red]")
    console.print(f"  [green]Safe: {len(passwords) - compromised_count}[/green]\n")
    
    if compromised_count > 0:
        console.print("[yellow]⚠️  Some passwords are compromised and should be changed![/yellow]\n")


@app.command()
def info():
    """Show information about the password checking service."""
    
    console.print("\n[bold cyan]Password Compromise Checker[/bold cyan]")
    console.print("\nThis tool uses the Have I Been Pwned API to check if passwords")
    console.print("have been compromised in known data breaches.\n")
    
    console.print("[bold]How it works:[/bold]")
    console.print("  1. Your password is hashed using SHA-1")
    console.print("  2. Only the first 5 characters of the hash are sent to the API")
    console.print("  3. The API returns all matching hash suffixes")
    console.print("  4. Your system checks if your full hash is in the results")
    console.print("\n[green]Your actual password never leaves your computer![/green]")
    console.print("\n[bold]API Information:[/bold]")
    console.print(f"  Service: Have I Been Pwned")
    console.print(f"  Website: https://haveibeenpwned.com")
    console.print(f"  API: https://api.pwnedpasswords.com\n")


def main():
    """Entry point for the application."""
    app()


if __name__ == "__main__":
    main()
