"""
ioc.py

This module contains models and utilities for handling Indicators of Compromise (IOCs). 
It provides the IOC and IOCs Pydantic models for structured representation of threat 
intelligence, along with helper functions for serializing IOCs to CSV format.

Classes:
    - IOC: Represents a single Indicator of Compromise.
    - IOCs: Represents a collection of IOCs.

Functions:
    - iocs_to_csv: Converts a list of IOC objects to a CSV-formatted string.

Usage:
    >>> from thsensai.ioc import IOC, IOCs, iocs_to_csv
    >>> ioc = IOC(type="ip", value="192.168.1.1", context="Suspicious traffic")
    >>> print(ioc)
    >>> iocs = IOCs(iocs=[ioc])
    >>> print(iocs_to_csv(iocs.iocs))

"""

import csv
from collections import defaultdict
from io import StringIO
from typing import List
from pydantic import BaseModel, field_validator


class IOC(BaseModel):
    """
    Represents a single Indicator of Compromise (IOC).

    Attributes:
        type (str): The type of IOC (e.g., "ip", "url", "hash").
        value (str): The actual value of the IOC.
        context (str): Additional context or metadata associated with the IOC.
    """

    type: str
    value: str
    context: str = ""

    @field_validator("type", mode="before")
    @classmethod
    def normalize_type(cls, v):
        """
        Normalize the 'type' field to be lowercase and stripped of whitespace.
        """
        return v.replace("_", " ").strip().lower()

    @field_validator("value", mode="before")
    @classmethod
    def normalize_value(cls, v):
        """
        Normalize the 'value' field by:
        - Replacing '[.]' with '.'
        - Replacing 'hxxp/s' with 'http/s'
        """
        if isinstance(v, str):
            v = v.replace("[.]", ".")
            v = v.replace("[:]", ":")
            v = v.replace("hxxp://", "http://")
            v = v.replace("hxxps://", "https://")
            v = v.replace("hXXp://", "http://")
            v = v.replace("hXXps://", "https://")
        return v

    @field_validator("context", mode="before")
    @classmethod
    def normalize_context(cls, v):
        """
        Ensure the 'context' field is stripped of leading and trailing whitespace.
        """
        return v.strip() if isinstance(v, str) else v


class IOCs(BaseModel):
    """
    Represents a collection of IOCs.

    Attributes:
        iocs (List[IOC]): A list of IOC objects.
    """

    iocs: List[IOC]

    def deduplicate_and_combine_context(self):
        """
        Deduplicates IOCs by the 'value' attribute and combines their 'context' values.

        This method iterates over all IOCs and combines the 'context' for any IOCs
        that have the same 'value'. The 'context' is combined by appending the context
        of the duplicate IOCs.
        """
        value_to_iocs = defaultdict(list)

        # Group IOCs by their value
        for ioc in self.iocs:
            value_to_iocs[ioc.value].append(ioc)

        # Create a new list to hold the deduplicated IOCs
        deduplicated_iocs = []

        # Iterate through the grouped IOCs
        for iocs_group in value_to_iocs.values():
            if len(iocs_group) > 1:
                # If there are duplicates, combine their contexts
                combined_context = " | ".join(
                    ioc.context.strip() for ioc in iocs_group if ioc.context.strip()
                )
                # Create a new IOC with the combined context
                combined_ioc = iocs_group[0].copy(update={"context": combined_context})
                deduplicated_iocs.append(combined_ioc)
            else:
                # If no duplicates, add the IOC as is
                deduplicated_iocs.append(iocs_group[0])

        # Update the iocs list with deduplicated IOCs
        self.iocs = sorted(deduplicated_iocs, key=lambda ioc: ioc.type)


def iocs_to_csv(iocs_obj: IOCs) -> str:
    """
    Converts a collection of IOCs into a CSV string with a header.

    Args:
        iocs_obj (IOCs): The IOCs object containing a list of IOC instances.

    Returns:
        str: The CSV string representation of the IOCs.
    """

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Type", "Value", "Context"])  # Header row

    for ioc in iocs_obj.iocs:
        writer.writerow([ioc.type, ioc.value, ioc.context])

    return output.getvalue()
