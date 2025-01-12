"""
This module contains shared utility functions for use in other modules.
"""

import os
from typing import Dict, Optional


def ensure_dir_exist(path):
    """
    Ensures that the directory at the specified path exists. If the directory
    does not exist, it is created.

    Args:
        path (str): The path to the directory to check or create.
    """
    if not os.path.exists(path):
        os.makedirs(path)


def build_prompt(context: str, query: str) -> str:
    """
    Construct a prompt by combining a given context and query.

    Args:
        context (str): The contextual information to include in the prompt.
        query (str): The query or question to append to the context.

    Returns:
        str: A formatted string containing the context and query.
    """
    return f"Use the following context:\n\n```\n{context}\n```\n\n{query}"


def generate_report_name(
    source: str,
    params: Dict[str, str],
    report_type: Optional[str] = None,
    extension: Optional[str] = None,
) -> str:
    """
    Generate a unique report name based on the source and extraction parameters.

    Args:
        source (str): A string representing the source of the intelligence data
                      (e.g., a URL or file path).
        params (Dict[str, str]): A dictionary of parameters used for report generation, including:
            - chunk_size (str): Size of document chunks.
            - chunk_overlap (str): Overlap size between chunks.
            - num_ctx (str): Context window size.
            - num_predict (str): Maximum tokens to predict.
        report_type (Optional[str]): The type of report (e.g., "ioc", "hyp"). Defaults to None.
        extension (Optional[str]): The file extension to append to the report name.
            Defaults to None.

    Returns:
        str: The generated report name, formatted with the source and parameters.

    Example:
        >>> source = "https://example.com/threat-report"
        >>> params = {
        ...     "chunk_size": "500",
        ...     "chunk_overlap": "100",
        ...     "num_ctx": "1024",
        ...     "num_predict": "256"
        ... }
        >>> generate_report_name(source, params)
        'example_com_threat-report_cs-500_co-100_nc-1024_np-256.csv'

    Notes:
        The `source` is sanitized by replacing certain characters (e.g., "https://", "/", ".")
        to make it a valid filename. The parameters are appended to the report name
        for better identification.
    """
    report_name = report_type + "_" if report_type else ""
    report_name += source.replace("https://", "").replace("/", "_").replace(".", "_")
    report_name += f"_cs-{params['chunk_size']}_co-{params['chunk_overlap']}"
    report_name += f"_nc-{params['num_ctx']}_np-{params['num_predict']}"
    report_name += f".{extension}"
    return report_name
