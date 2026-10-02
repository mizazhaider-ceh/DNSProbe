#!/usr/bin/env python3
"""
DNSProbe: fast DNS enumeration and auditing for a domain.

Queries the common record types for a target domain, flags dead or
misconfigured zones, and can dump the whole result set as JSON for
piping into other tooling.
"""
import argparse
import json
import sys
from typing import Any, Dict, List

import dns.resolver
import dns.reversename
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

# Initialize Rich Console
console = Console()

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA"]


class DNSAuditor:
    """
    A class to perform comprehensive DNS auditing for a domain.
    """

    def __init__(self, domain: str, timeout: float = 5.0, do_ptr: bool = False):
        self.domain = self._normalize_domain(domain)
        self.do_ptr = do_ptr
        self.results: Dict[str, Any] = {}
        self.resolver = dns.resolver.Resolver()
        # Set a reasonable timeout
        self.resolver.lifetime = timeout

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        """Strip whitespace, trailing dots and casing noise from the input."""
        return domain.strip().rstrip(".").lower()

    def print_banner(self):
        """Print the tool banner and credits."""
        banner_text = Text(justify="center")
        banner_text.append("\nDNS PROBE\n", style="bold cyan")
        banner_text.append("==============================\n", style="bold cyan")
        banner_text.append("Built by mizazhaider-ceh\n", style="bold yellow")
        banner_text.append("Powered by The PenTrix\n", style="italic magenta")

        panel = Panel(
            banner_text,
            title="[bold green]Network Analysis Tool[/bold green]",
            border_style="cyan",
            expand=False,
        )
        console.print(panel)
        console.print()

    def check_record(self, record_type: str) -> List[str]:
        """Check specific DNS record type for the domain."""
        try:
            answers = self.resolver.resolve(self.domain, record_type)
            return [self._format_answer(record_type, answer) for answer in answers]
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.Timeout,
            dns.resolver.NoNameservers,
        ):
            return []
        except Exception:
            return []

    @staticmethod
    def _format_answer(record_type: str, answer: Any) -> str:
        """Render an rdata object in a human friendly way."""
        if record_type == "TXT":
            # Join quoted chunks so long TXT records read as one string
            return "".join(
                chunk.decode("utf-8", errors="replace")
                for chunk in getattr(answer, "strings", ())
            ) or str(answer)
        if record_type == "SOA":
            return (
                f"mname={answer.mname} rname={answer.rname} "
                f"serial={answer.serial} refresh={answer.refresh} "
                f"retry={answer.retry} expire={answer.expire} "
                f"minimum={answer.minimum}"
            )
        if record_type == "MX":
            return f"{answer.preference} {answer.exchange}"
        if record_type == "CAA":
            return f"{answer.flags} {answer.tag.decode() if isinstance(answer.tag, bytes) else answer.tag} \"{answer.value}\""
        return str(answer)

    def _reverse_lookup(self, ip: str) -> str:
        """Reverse-resolve an IP to its PTR hostname (empty string on failure)."""
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(rev_name, "PTR")
            return str(next(iter(answers)).target).rstrip(".")
        except Exception:
            return ""

    def perform_audit(self):
        """Gather all DNS records."""
        self.results = {"domain": self.domain}
        for record_type in RECORD_TYPES:
            self.results[record_type.lower()] = self.check_record(record_type)

        self.results["status"] = "alive"
        # Determine status
        if not any(
            [self.results["a"], self.results["aaaa"], self.results["mx"]]
        ):
            self.results["status"] = "dead or misconfigured"

        if self.do_ptr:
            ptr_map = {}
            for ip in self.results["a"] + self.results["aaaa"]:
                ptr = self._reverse_lookup(ip)
                if ptr:
                    ptr_map[ip] = ptr
            self.results["ptr"] = ptr_map

    def display_results(self):
        """Display the collected DNS information."""
        # Status Panel
        status_color = "green" if self.results["status"] == "alive" else "red"
        status_text = (
            f"Domain: [bold blue]{self.results['domain']}[/bold blue]\n"
            f"Status: [{status_color}]{self.results['status'].upper()}[/{status_color}]"
        )

        console.print(Panel(status_text, border_style=status_color))
        console.print()

        if self.results["status"] == "dead or misconfigured":
            console.print(
                "[bold red]No critical DNS records found (A, AAAA, or MX).[/bold red]"
            )
            return

        # Results Table
        table = Table(
            title="DNS Records found", show_header=True, header_style="bold magenta"
        )
        table.add_column("Type", style="cyan", width=10)
        table.add_column("Records", style="white")

        record_types = [t.lower() for t in RECORD_TYPES]

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

        ptr_map = self.results.get("ptr", {})
        if ptr_map:
            console.print()
            ptr_table = Table(
                title="Reverse DNS (PTR)", show_header=True, header_style="bold magenta"
            )
            ptr_table.add_column("IP", style="cyan")
            ptr_table.add_column("Hostname", style="white")
            for ip, host in ptr_map.items():
                ptr_table.add_row(ip, host)
            console.print(ptr_table)

    def to_json(self) -> str:
        """Serialize the audit results as JSON."""
        return json.dumps(self.results, indent=2)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Comprehensive DNS auditing tool.")
    parser.add_argument("domain", help="The domain name to probe (e.g., example.com)")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print results as JSON instead of the rich table",
    )
    parser.add_argument(
        "--ptr",
        action="store_true",
        help="Reverse-resolve A/AAAA IPs to PTR hostnames",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Per-query timeout in seconds (default: 5.0)",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    auditor = DNSAuditor(args.domain, timeout=args.timeout, do_ptr=args.ptr)

    if not args.json:
        auditor.print_banner()

    if args.json:
        auditor.perform_audit()
        print(auditor.to_json())
        return 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(description="Querying Name Servers...", total=None)
        auditor.perform_audit()

    auditor.display_results()
    return 0


if __name__ == "__main__":
    sys.exit(main())
