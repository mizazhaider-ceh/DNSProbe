#!/usr/bin/env python3
import sys
import argparse
import dns.resolver
import dns.reversename
from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

# Initialize Rich Console
console = Console()

class DNSAuditor:
    """
    A class to perform comprehensive DNS auditing for a domain.
    """
    def __init__(self, domain: str):
        self.domain = domain
        self.results: Dict[str, Any] = {}
        self.resolver = dns.resolver.Resolver()
        # Set a reasonable timeout
        self.resolver.lifetime = 5.0

    def print_banner(self):
        """Print the tool banner and credits."""
        banner_text = Text(justify="center")
        banner_text.append("\n📡  DNS PROBE  📡\n", style="bold cyan")
        banner_text.append("════════════════════════════════════\n", style="bold cyan")
        banner_text.append("Built by MIHx0 (Muhammad Izaz Haider)\n", style="bold yellow")
        banner_text.append("Powered by The PenTrix\n", style="italic magenta")
        
        panel = Panel(
            banner_text,
            title="[bold green]Network Analysis Tool[/bold green]",
            border_style="cyan",
            expand=False
        )
        console.print(panel)
        console.print()

    def check_record(self, record_type: str) -> List[str]:
        """Check specific DNS record type for the domain."""
        try:
            answers = self.resolver.resolve(self.domain, record_type)
            return [str(answer) for answer in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
                dns.resolver.Timeout, dns.resolver.NoNameservers):
            return []
        except Exception:
            return []

    def perform_audit(self):
        """Gather all DNS records."""
        self.results = {
            'domain': self.domain,
            'a': self.check_record('A'),
            'aaaa': self.check_record('AAAA'),
            'mx': self.check_record('MX'),
            'txt': self.check_record('TXT'),
            'ns': self.check_record('NS'),
            'cname': self.check_record('CNAME'),
            'soa': self.check_record('SOA'),
            'status': 'alive'
        }
        
        # Determine status
        if not any([self.results['a'], self.results['aaaa'], self.results['mx']]):
            self.results['status'] = 'dead or misconfigured'

    def display_results(self):
        """Display the collected DNS information."""
        # Status Panel
        status_color = "green" if self.results['status'] == 'alive' else "red"
        status_text = f"Domain: [bold blue]{self.results['domain']}[/bold blue]\nStatus: [{status_color}]{self.results['status'].upper()}[/{status_color}]"
        
        console.print(Panel(status_text, border_style=status_color))
        console.print()

        if self.results['status'] == 'dead or misconfigured':
             console.print("[bold red]❌ No critical DNS records found (A, AAAA, or MX).[/bold red]")
             return

        # Results Table
        table = Table(title="DNS Records found", show_header=True, header_style="bold magenta")
        table.add_column("Type", style="cyan", width=10)
        table.add_column("Records", style="white")

        record_types = ['a', 'aaaa', 'mx', 'txt', 'ns', 'cname', 'soa']
        
        has_records = False
        for r_type in record_types:
            records = self.results.get(r_type, [])
            if records:
                has_records = True
                # Format records for display (one per line if multiple)
                content = "\n".join(records)
                table.add_row(r_type.upper(), content)
                table.add_section()

        if has_records:
            console.print(table)
        else:
            console.print("[yellow]No standard records found.[/yellow]")

def main():
    parser = argparse.ArgumentParser(description="Comprehensive DNS auditing tool.")
    parser.add_argument("domain", help="The domain name to probe (e.g., example.com)")
    
    args = parser.parse_args()
    
    auditor = DNSAuditor(args.domain)
    auditor.print_banner()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    ) as progress:
        progress.add_task(description="Querying Name Servers...", total=None)
        auditor.perform_audit()
    
    auditor.display_results()

if __name__ == "__main__":
    main()
