"""
Sensai CLI Tool

This script provides a command-line interface for the Sensai threat intelligence 
and hunting tool. It allows users to analyze threat intelligence sources, extract 
Indicators of Compromise (IOCs), and benchmark the performance of different 
language models.

Commands:
    analyze: Extract IOCs from a given source (file or URL) using a specified language model.
    benchmark: Evaluate multiple language models for threat intelligence analysis.

Usage:
    Run `python sensai.py --help` for detailed command options.
"""

import typer
from rich import print as rp
from rich.console import Console
from rich.table import Table
from rich.markdown import Markdown
from rich.progress import (
    Progress,
    MofNCompleteColumn,
    TimeElapsedColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
)

from thsensai.knowledge import acquire_intel
from thsensai.test.test_intel import benchmark_models
from thsensai.hunter import extract_iocs

app = typer.Typer(help="Sensai: Threat Hunting and Intelligence Tool")


@app.command()
def analyze(  # noqa: R0913
    source: str = typer.Argument(..., help="Input file or URL for IOC extraction"),
    model: str = typer.Option(
        ...,
        "--model",
        "-m",
        help="LLM model to be used for inference",
    ),
    chunk_size: int = typer.Option(
        2600,
        "--chunk-size",
        "-s",
        help="Intel document split size",
    ),
    chunk_overlap: int = typer.Option(
        300,
        "--chunk-overlap",
        "-o",
        help="Intel document split overlap",
    ),
    num_predict: int = typer.Option(
        -1,
        "--num-predict",
        help="Maximum number of tokens to predict when generating text (-1 = infinite)",
    ),
    num_ctx: int = typer.Option(
        4096,
        "--num-ctx",
        help="Size of the context window used to generate the next token",
    ),
    css_selector: str = typer.Option(
        "body",
        "--css-selector",
        "-c",
        help="Optional css selector value to limit the html parsing",
    ),
):
    """
    Analyze threat intelligence from a source.

    This command extracts Indicators of Compromise (IOCs) from the specified input
    (file or URL) using the specified language model. It supports optional document
    chunking and advanced parsing via CSS selectors.

    Args:
        source (str): Input file path or URL for processing.
        model (str): Language model to use for inference.
        chunk_size (int): Size of document chunks in characters.
        num_predict (int): Maximum tokens to predict; -1 for unlimited.
        num_ctx (int): Context window size for the language model.
        css_selector (str, optional): CSS selector to filter HTML content.
    """
    intel = acquire_intel(source, css_selector)
    params = {
        "chunk_size": chunk_size,
        "chunk_overlap": chunk_overlap,
        "num_predict": num_predict, 
        "num_ctx": num_ctx}
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        MofNCompleteColumn(),
    ) as progress:
        iocs = extract_iocs(intel, model, params, progress=progress)

    table = Table(title="Extracted IOCs")
    table.add_column("Type", justify="center", style="cyan", no_wrap=True)
    table.add_column("Value", style="magenta")
    table.add_column("Context", style="green")

    for ioc in iocs.iocs:
        context = ioc.context.strip() if ioc.context and ioc.context.strip() else "N/A"
        table.add_row(ioc.type, ioc.value, context)

    rp("")
    rp(table)



@app.command()
def benchmark(
    models: str = typer.Option(
        ...,
        "--models",
        "-m",
        help="Comma-separated list of models in the format name:size"
        " (e.g., qwen2.5:32b,qwen2.5:14b)",
    ),
    chunk_sizes: str = typer.Option(
        "2600",
        "--chunk-size",
        "-s",
        help="Comma-separated list of chunk_size values" " (e.g., 2400,3200)",
    ),
    chunk_overlaps: str = typer.Option(
        "200",
        "--chunk-overlap",
        "-o",
        help="Comma-separated list of chunk_overlap values" " (e.g., 150,300)",
    ),
):
    """
    Run a benchmark on multiple language models.

    This command evaluates multiple models against test cases, measuring their
    performance in extracting relevant threat intelligence.

    Args:
        models (str): Comma-separated list of models in the format `name:size`.
    """
    model_list = models.split(",")
    chunk_size_list = [int(size) for size in chunk_sizes.split(",")]
    chunk_overlap_list = [int(overlap) for overlap in chunk_overlaps.split(",")]
    report = benchmark_models(
        model_list,
        chunk_size_list,
        chunk_overlap_list,
    )
    console = Console()
    console.print(Markdown(report))

    with open("docs/benchmark.md", 'w', encoding="utf-8") as f_dst:
        f_dst.write(report)


if __name__ == "__main__":
    app()
