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
from thsensai.hunter import extract_iocs, write_report

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
    output_dir: str = typer.Option(
        "./",
        "--output-dir",
        "-d",
        help="Location of the report directory",
    ),
    report: bool = typer.Option(
        False,
        "--write-report",
        "-r",
        help="Create a report file",
    ),
):
    """
    Analyze threat intelligence and extract Indicators of Compromise (IOCs).

    This command processes a specified source (file path or URL) to extract IOCs using 
    a Large Language Model (LLM). It supports document chunking to manage large inputs 
    and provides options for advanced HTML parsing via CSS selectors. Extracted IOCs 
    are displayed in a table and optionally saved as a report.

    Args:
        source (str): The input file path or URL for processing.
        model (str): The LLM model to use for IOC extraction.
        chunk_size (int): The size of document chunks in characters. Larger sizes 
            may improve context for analysis but can exceed model limits.
        chunk_overlap (int): The overlap size between consecutive chunks to ensure 
            context continuity across chunks.
        num_predict (int): The maximum number of tokens to predict when generating 
            text. Use -1 for unlimited prediction.
        num_ctx (int): The size of the context window for the LLM. Determines how 
            much of the input can be considered for predictions.
        css_selector (str): An optional CSS selector to filter HTML content before 
            processing. Defaults to "body" for extracting the main content.
        output_dir (str): The directory to save the generated report. Defaults to the 
            current working directory ("./").
        report (bool): Whether to save the extracted IOCs as a report file. If True, 
            a CSV file will be created in the specified `output_dir`.

    Returns:
        None

    Notes:
        - The function uses chunking to handle large documents, ensuring compatibility 
          with the LLM's context size limitations.
        - Extracted IOCs are displayed in a formatted table using the Rich library.
        - If the `--write-report` option is specified, the extracted IOCs are saved 
          as a CSV report file.
        - Progress of the IOC extraction process is tracked and displayed using Rich's 
          progress bar.

    Example:
        To analyze a local file and save the report:
            $ sensai analyze sample_file.txt --model "example-llm-model" \\
                --chunk-size 2600 --chunk-overlap 300 --write-report

        To analyze a URL and print results without saving:
            $ sensai analyze https://example.com/intel_report.html --model "example-llm-model"

    """
    intel = acquire_intel(source, css_selector)
    params = {
        "chunk_size": chunk_size,
        "chunk_overlap": chunk_overlap,
        "num_predict": num_predict,
        "num_ctx": num_ctx,
    }
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

    if report:
        write_report(iocs, source, params, output_dir)


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
    Run benchmarks on multiple language models to evaluate performance.

    This command tests a list of specified language models using different chunk 
    size and overlap configurations. It evaluates their effectiveness in extracting 
    relevant threat intelligence and generates a detailed report.

    Args:
        models (str): A comma-separated list of language models in the format 
            `name:size` (e.g., `qwen2.5:32b`).
        chunk_sizes (str): A comma-separated list of chunk sizes in characters 
            (e.g., `2400,3200`). Each chunk size represents the size of the 
            input data split for processing.
        chunk_overlaps (str): A comma-separated list of chunk overlap sizes in 
            characters (e.g., `150,300`). Overlap sizes determine the continuity 
            between consecutive chunks.

    Returns:
        None

    Notes:
        - Benchmarks are performed by varying model configurations, chunk sizes, 
          and chunk overlaps. This helps evaluate model performance under 
          different conditions.
        - Results are displayed in the console as a Markdown report and saved 
          to `docs/benchmark.md` for future reference.

    Example:
        To benchmark multiple models with various configurations:
            $ sensai benchmark \\
                --models "qwen2.5:32b,qwen2.5:14b" \\
                --chunk-size "2400,3200" \\
                --chunk-overlap "150,300"

    Output:
        The command generates a Markdown report detailing:
        - Model performance for each chunk size and overlap configuration.
        - Summary of results to identify optimal model and configuration.

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

    with open("docs/benchmark.md", "w", encoding="utf-8") as f_dst:
        f_dst.write(report)


if __name__ == "__main__":
    app()
