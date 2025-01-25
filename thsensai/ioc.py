"""
This module provides classes for representing and handling Indicators of Compromise (IOCs).

Classes:
    IOC(BaseModel): A class representing a single Indicator of Compromise (IOC).
    IOCs(BaseModel): A class representing a collection of Indicators of Compromise (IOCs).
"""

from __future__ import annotations
import csv
import os
from collections import defaultdict
from io import StringIO
from typing import List, Optional
from rich.table import Table
from rich.progress import Progress
from rich import print as rp
from pydantic import BaseModel, field_validator
from pydantic import ValidationError
from thsensai.infer import LLMInference
from thsensai.intel import Intel
from thsensai.utils import generate_report_name


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
    Represents a collection of Indicators of Compromise (IOCs).

    This class provides methods to extend, deduplicate, and display IOCs.

    Attributes:
        iocs (List[IOC]): A list of IOC objects.

    Methods:
        deduplicate_and_combine_context():

        as_csv() -> str:

        display():
            Displays extracted Indicators of Compromise (IOCs) in a formatted table.
    """

    iocs: List[IOC]

    def extend(
        self,
        chunk_content: str,
        llm: LLMInference,
    ):
        """
        Extend the current collection of IOCs by processing a chunk of threat intelligence data.

        Args:
            chunk_content (str): The content of the data chunk to process.
            model (str): The LLM model to use for extraction.
            num_predict (int): Maximum number of tokens to predict.
            num_ctx (int): Context window size for the LLM input.
            seed (int): Random seed for consistent results.

        Returns:
            int: The number of IOCs extracted from the chunk.
        """

        query = (
            "As a threat intel expert, extract all Indicators of Compromise (IOCs) "
            "from the provided text. Each IOC must include its type, value, and context. "
            "If no IOCs are present, return an empty response. Do not include comments "
            "or extraneous text. Format the response adhering to the schema provided."
        )

        try:
            structured_output = llm.invoke_model(chunk_content, query, IOCs)
            if structured_output is not None:
                self.iocs.extend(structured_output.iocs)  # Extend the current IOCs list
                self.deduplicate_and_combine_context()
                return len(structured_output.iocs)
        except ValidationError:
            pass
        return 0

    def extend_from_csv(self, iocs_csv: str):
        """
        Extend the current collection of IOCs by processing a CSV file containing IOCs.

        Args:
            iocs_csv (str): The content of the CSV file containing IOCs.

        Returns:
            None: The method updates the IOCs list with the extracted IOCs.
        """
        iocs = []
        try:
            with StringIO(iocs_csv) as f_src:
                reader = csv.DictReader(f_src)
                for row in reader:
                    # Convert keys to lowercase
                    lower_case_row = {key.lower(): value for key, value in row.items()}
                    ioc = IOC(**lower_case_row)
                    iocs.append(ioc)
        except ValidationError as e:
            rp(f"Validation error: {e}")

        self.iocs.extend(iocs)
        self.deduplicate_and_combine_context()

    @classmethod
    def from_csv(cls, filename: str) -> IOCs:
        """
        Create an instance of IOCs from a CSV file.

        Args:
            filename (str): The path to the CSV file containing IOCs.

        Returns:
            IOCs: An instance of the IOCs class.
        """
        with open(filename, "r", encoding="utf-8") as file:
            intel = file.read()
        iocs_obj = cls(iocs=[])
        iocs_obj.extend_from_csv(intel)
        return iocs_obj

    @classmethod
    def from_intel(
        cls,
        intel_obj: Intel,
        llm: LLMInference,
        progress: Optional[Progress] = None,
    ) -> IOCs:
        """
        Extract IOCs from a list of intelligence documents using an LLM model and
        return a new IOCs instance.

        Args:
            intel_obj (Intel): An instance of the Intel class containing intelligence data.
            llm (LLMInference): An instance of the LLMInference class.
            progress (Optional[Progress]): A Rich Progress object to display the
                extraction progress.
            seed (Optional[int]): Random seed for consistent results.

        Returns:
            IOCs: A new instance of the IOCs class with the extracted IOCs.
        """
        iocs_instance = cls(iocs=[])
        iocs_instance.generate(intel_obj, llm, progress)
        return iocs_instance

    def generate(
        self,
        intel_obj: Intel,
        llm: LLMInference,
        progress: Progress,
    ):
        """
        Extract IOCs from a list of intelligence documents using an LLM model.

        Args:
            intel_obj (Intel): An instance of the Intel class containing intelligence data.
            llm (LLMInference): An instance of the LLMInference class.
            progress (Progress): A Rich Progress object to display the extraction progress.

        Returns:
            None: The method updates the IOCs list with the extracted IOCs.
        """
        task_id = None

        if progress:
            task_id = progress.add_task(
                "🔎 [green]Extracting IOCs...", total=len(intel_obj.content_chunks)
            )

        for chunk in intel_obj.content_chunks:
            added = self.extend(chunk.page_content, llm)

            if progress and task_id is not None:
                progress.advance(task_id)
                progress.update(
                    task_id,
                    description=f"🔎 [green]Extracted IOCs: [bold]{added}[/bold][/green]",
                )

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
                combined_ioc = iocs_group[0].model_copy(update={"context": combined_context})
                deduplicated_iocs.append(combined_ioc)
            else:
                # If no duplicates, add the IOC as is
                deduplicated_iocs.append(iocs_group[0])

        # Update the iocs list with deduplicated IOCs
        self.iocs = sorted(deduplicated_iocs, key=lambda ioc: ioc.type)

    def as_csv(self) -> str:
        """
        Converts the collection of IOCs into a CSV string with a header.

        Returns:
            str: The CSV string representation of the IOCs.
        """
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["Type", "Value", "Context"])  # Header row

        for ioc in self.iocs:
            writer.writerow([ioc.type, ioc.value, ioc.context])

        return output.getvalue()

    def display(self):
        """
        Display extracted Indicators of Compromise (IOCs) in a formatted table.

        This method displays the IOCs in a structured and visually appealing table
        format using the Rich library. Each IOC is represented by its type, value,
        and context.

        Returns:
            None: The method outputs the table directly to the console.
        """
        table = Table(title="Extracted IOCs")
        table.add_column("Type", justify="center", style="cyan", no_wrap=True)
        table.add_column("Value", style="magenta")
        table.add_column("Context", style="green")

        for ioc in self.iocs:
            context = (
                ioc.context.strip() if ioc.context and ioc.context.strip() else "N/A"
            )
            table.add_row(ioc.type, ioc.value, context)

        rp(table)

    def write_report(self, intel_obj: Intel, llm: LLMInference, output_dir: str):
        """
        Write the extracted IOCs to a CSV report file.

        Args:
            intel_obj (Intel): An instance of the Intel class containing intelligence data.
            llm: (LLMInference): An instance of the LLMInference class.
            output_dir (str): The directory where the report will be saved.

        Returns:
            None: The method writes the report to a CSV file in the specified directory.
        """
        report_name = generate_report_name(intel_obj, llm, "ioc", "csv")
        os.makedirs(output_dir, exist_ok=True)
        with open(f"{output_dir}/{report_name}", "w", encoding="utf-8") as f_dst:
            f_dst.write(self.as_csv())
