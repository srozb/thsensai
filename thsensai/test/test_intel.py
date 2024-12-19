"""
Test cases for measuring performance of the IOC extractor.
"""

import time
from typing import List, Tuple, Dict
from io import StringIO
from rich.table import Table
from rich import box
from rich.console import Console
from rich.progress import (
    Progress,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
    MofNCompleteColumn,
)

from thsensai.knowledge import acquire_intel
from thsensai.hunter import extract_iocs
from thsensai.test.test_cases import test_cases
from thsensai.ioc import IOCs


def rich_table_to_text(table: Table) -> str:
    """
    Convert a Rich Table to a Markdown-formatted table using Rich's box.MARKDOWN style.

    Args:
        table (Table): The Rich Table instance.

    Returns:
        str: A markdown-formatted table as a string.
    """
    table.box = box.MARKDOWN

    # Use a StringIO buffer for capturing the output
    buffer = StringIO()
    console = Console(file=buffer, record=True)
    console.print(table)
    return buffer.getvalue().strip()


def rate_extraction(iocs: IOCs, keywords: set) -> str:
    """
    Rate the extraction against expected keywords.

    Args:
        iocs (IOCs): Extracted IOCs.
        keywords (set): Expected keywords.

    Returns:
        str: Score as a string (e.g., "10/12 83.33%").
    """
    # Convert extracted values and keywords to lowercase for case-insensitive comparison
    extracted_values = {ioc.value.lower() for ioc in iocs.iocs}
    keywords_lower = {keyword.lower() for keyword in keywords}

    # Match if any keyword is a substring of an extracted value (case-insensitive)
    matched = {
        keyword
        for keyword in keywords_lower
        if any(keyword in value for value in extracted_values)
    }

    total = len(keywords)
    score = len(matched)
    percentage = (score / total * 100) if total else 0
    return f"{score}/{total} {percentage:.2f}%"


def benchmark_models(
    models: List[str], chunk_sizes: List[int], chunk_overlaps: List[int]
) -> str:
    """
    Run benchmarks on multiple models, test cases, and configurations,
    and generate a markdown report.

    Args:
        models (List[str]): A list of model names in the format 'name:size'.
        chunk_sizes (List[int]): List of chunk sizes to benchmark.
        chunk_overlaps (List[int]): List of chunk overlaps to benchmark.

    Returns:
        str: The generated markdown report as a string.
    """
    report_parts = ["# IOC Extracting Benchmark\n"]
    for model in models:
        report_parts.append(f"## {model}\n")
        report_parts.append(process_model_benchmark(model, chunk_sizes, chunk_overlaps))
    return "\n".join(report_parts)


def process_model_benchmark(
    model: str, chunk_sizes: List[int], chunk_overlaps: List[int]
) -> str:
    """
    Process the benchmark for a single model and generate a report section.

    Args:
        model (str): Name of the model.
        chunk_sizes (List[int]): List of chunk sizes.
        chunk_overlaps (List[int]): List of chunk overlaps.

    Returns:
        str: The markdown section for this model's benchmark.
    """
    table = create_benchmark_table(model)
    for chunk_size in chunk_sizes:
        for chunk_overlap in chunk_overlaps:
            table = run_benchmarks_for_configuration(
                table, model, chunk_size, chunk_overlap
            )
    return rich_table_to_text(table)


def create_benchmark_table(model: str) -> Table:
    """
    Create a Rich table for benchmark results.

    Args:
        model (str): Name of the model.

    Returns:
        Table: A Rich Table instance.
    """
    table = Table(title=f"Benchmark Results for {model}", box=None)
    table.add_column("Source", justify="left")
    table.add_column("Scraped Size", justify="right")
    table.add_column("Chunk Size", justify="right")
    table.add_column("Chunk Overlap", justify="right")
    table.add_column("Total Inference Time", justify="right")
    table.add_column("Score", justify="right")
    return table


def run_benchmarks_for_configuration(
    table: Table, model: str, chunk_size: int, chunk_overlap: int
) -> Table:
    """
    Run benchmarks for a given configuration and update the table.

    Args:
        table (Table): The Rich table to update.
        model (str): Name of the model.
        chunk_size (int): Size of each chunk.
        chunk_overlap (int): Overlap between chunks.

    Returns:
        Table: The updated table with benchmark results.
    """
    for test_case in test_cases:
        source = test_case.get("source")
        selector = test_case.get("selector", None)
        target = (source, selector) if selector else (source,)
        keywords = set(test_case.get("keywords", []))

        intel = acquire_intel(*target)
        scraped_size = calculate_scraped_size(intel)

        params = {
            "chunk_size": chunk_size,
            "chunk_overlap": chunk_overlap,
            "num_predict": -1,
            "num_ctx": 4096,
        }
        total_inference_time, iocs = run_extraction_with_timer(intel, model, params)
        score = rate_extraction(iocs, keywords)

        table.add_row(
            source,
            str(scraped_size),
            str(chunk_size),
            str(chunk_overlap),
            f"{total_inference_time:.2f} s.",
            score,
        )
    return table


def calculate_scraped_size(intel: List) -> int:
    """
    Calculate the total scraped size from acquired intelligence.

    Args:
        intel (List): Acquired intelligence documents.

    Returns:
        int: Total scraped size.
    """
    return sum(len(doc.page_content) for doc in intel)


def run_extraction_with_timer(
    intel: List, model: str, params: Dict
) -> Tuple[float, IOCs]:
    """
    Run the extraction and measure the total inference time.

    Args:
        intel (List): Acquired intelligence documents.
        model (str): Name of the model.
        params (Dict): Parameters for the extraction.

    Returns:
        Tuple[float, IOCs]: Total inference time and extracted IOCs.
    """
    start_time = time.time()
    with Progress(
        TextColumn(f"Model: {model}"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        MofNCompleteColumn(),
    ) as progress:
        iocs = extract_iocs(intel=intel, model=model, params=params, progress=progress)
    total_inference_time = time.time() - start_time
    return total_inference_time, iocs
