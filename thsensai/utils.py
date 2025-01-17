"""
This module contains shared utility functions for use in other modules.
"""

import os
from typing import Dict, Optional
from thsensai.infer import LLMInference


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
    llm: LLMInference,
    params: Dict[str, str],
    report_type: Optional[str] = None,
    extension: Optional[str] = None,
) -> str:
    """
    Generates a report name based on the specified parameters.
    """
    report_name = report_type + "_" if report_type else ""
    report_name += source.replace("https://", "").replace("/", "_").replace(".", "_")
    report_name += f"_cs-{params['chunk_size']}_co-{params['chunk_overlap']}"
    report_name += f"_nc-{llm.num_ctx}_np-{llm.num_predict}"
    report_name += f".{extension}"
    return report_name
