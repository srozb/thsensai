"""
This module contains shared utility functions for use in other modules.
"""

from typing import Optional
from slugify import slugify
from thsensai.infer import LLMInference
from thsensai.intel import Intel


def generate_report_name(
    intel_obj: Intel,
    llm: LLMInference,
    report_type: Optional[str] = "",
    extension: Optional[str] = "",
) -> str:
    """
    Generates a report name based on the specified parameters.
    """
    report_name = report_type + "_" if report_type else ""
    report_name += slugify(intel_obj.source.replace("https://", ""))
    report_name += f"_cs-{intel_obj.chunk_size}_co-{intel_obj.chunk_overlap}"
    report_name += f"_nc-{llm.num_ctx}_np-{llm.num_predict}"
    if extension:
        report_name += f".{extension}"
    return report_name
