"""CLI handler for the 'leetha import' command."""
from __future__ import annotations

import asyncio
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from leetha.import_pcap import validate_pcap_file, process_pcap, ImportProgress
from leetha.config import get_config
from leetha.store.database import Database

console = Console()


async def run_import(args) -> None:
    """Import one or more PCAP files through the fingerprinting pipeline."""
    files = [Path(f) for f in args.files]
    max_size = getattr(args, "max_size", 500)

    # Validate all files first
    for f in files:
        err = validate_pcap_file(f, max_size_mb=max_size)
        if err:
            console.print(f"[red]Error:[/red] {err}")
            return

    # Initialize database
    console.print("[dim]Initializing fingerprint engine...[/dim]")
    config = get_config()
    db = Database(Path(config.data_dir) / "leetha.db")
    await db.initialize()

    # Create a packet queue for processing
    packet_queue: asyncio.Queue = asyncio.Queue()

    try:
        for filepath in files:
            console.print(f"\n[bold]Importing:[/bold] {filepath.name}")

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total} packets"),
                TimeElapsedColumn(),
                console=console,
            ) as progress_bar:
                task_id = progress_bar.add_task(filepath.name, total=0)

                def on_progress(p: ImportProgress):
                    progress_bar.update(task_id, total=p.total_packets, completed=p.processed)

                result = await process_pcap(
                    filepath,
                    packet_queue,
                    on_progress=on_progress,
                )

            # Summary
            table = Table(title=f"Import Complete: {filepath.name}")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            table.add_row("Packets processed", str(result.processed))
            table.add_row("Total packets", str(result.total_packets))
            table.add_row("Parse errors", str(result.errors))
            console.print(table)
    finally:
        await db.close()

    console.print("\n[bold green]All imports complete.[/bold green]")
