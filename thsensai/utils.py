"""
This module contains shared utility functions for use in other modules.
"""

import re
from typing import Optional
from thsensai.infer import LLMInference
from thsensai.intel import Intel

def slugify(value: str) -> str:
    """
    Convert a string to a slug by replacing non-alphanumeric characters with hyphens.

    Args:
        value (str): The string to slugify.

    Returns:
        str: The slugified string.
    """
    value = re.sub(r"[^\w\s-]", "", value).strip().lower()
    return re.sub(r"[-\s]+", "-", value)


def generate_report_name(
    intel_obj: Intel,
    llm: LLMInference,
    report_type: Optional[str] = None,
    extension: Optional[str] = None,
) -> str:
    """
    Generates a report name based on the specified parameters.
    """
    report_name = report_type + "_" if report_type else ""
    report_name += slugify(intel_obj.source.replace("https://", ""))
    report_name += f"_cs-{intel_obj.chunk_size}_co-{intel_obj.chunk_overlap}"
    report_name += f"_nc-{llm.num_ctx}_np-{llm.num_predict}"
    report_name += f".{extension}"
    return report_name
