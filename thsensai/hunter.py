"""
Hunter Module

This module is responsible for extracting Indicators of Compromise (IOCs) 
from threat intelligence data using LLM-based analysis. It supports chunked 
processing of intelligence documents and outputs structured IOC data.

Classes:
    IOC: Represents a single Indicator of Compromise (IOC) with its type, value, and context.
    IOCs: A collection of multiple IOCs.

Functions:
    extract_iocs: Extracts IOCs from intelligence data using an LLM model and outputs the results.

Notes:
    - The extraction process involves splitting the intelligence data into chunks, 
      sending prompts to the LLM, and parsing the structured response.
    - Outputs are stored in a CSV file in the `output/` directory.
"""

import os
from typing import List, Dict, Any, Optional
from langchain_ollama import ChatOllama
from langchain_core.documents import Document
from rich.progress import Progress
from pydantic import ValidationError
from thsensai import TEMPERATURE
from thsensai.knowledge import split_docs
from thsensai.ioc import IOC, IOCs, iocs_to_csv


def build_prompt(context) -> str:
    """
    Builds a prompt for the LLM to extract IOCs from the provided context.

    Args:
        context (str): The text context to process.

    Returns:
        str: A formatted prompt string.
    """
    query = (
        "As a threat intel expert, extract all Indicators of Compromise (IOCs) "
        "from the provided text. Each IOC must include its type, value, and context. "
        "If no IOCs are present, return an empty response. Do not include comments "
        "or extraneous text. Format the response adhering to the schema provided."
    )
    return f"Use the following context:\n\n```\n{context}\n```\n\n{query}"


def process_chunk(
    chunk_content: str,
    model: str,
    num_predict: int,
    num_ctx: int,
    seed: int,
) -> List[IOC]:
    """
    Process a single chunk of threat intelligence data to extract IOCs.

    Args:
        chunk_content (str): The content of the data chunk to process.
        model (str): The LLM model to use for extraction.
        num_predict (int): Maximum number of tokens to predict.
        num_ctx (int): Context window size for the LLM input.
        seed (int): Random seed for consistent results.

    Returns:
        List[IOC]: Extracted IOC objects from the chunk.
    """
    prompt = build_prompt(chunk_content)
    model_with_structure = ChatOllama(
        model=model,
        temperature=TEMPERATURE,
        num_predict=num_predict,
        num_ctx=num_ctx,
        seed=seed,
    ).with_structured_output(IOCs)
    try:
        structured_output = model_with_structure.invoke(prompt)
        if structured_output is None:
            return []
        return structured_output.iocs  # Returning IOC objects directly
    except ValidationError:
        return []


def generate_report_name(source: str, params: Dict[str, str]) -> str:
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
    report_name = source.replace("https://", "").replace("/", "_").replace(".", "_")
    report_name += f"_cs-{params['chunk_size']}_co-{params['chunk_overlap']}"
    report_name += f"_nc-{params['num_ctx']}_np-{params['num_predict']}.csv"
    return report_name


def write_report(iocs_obj: IOCs, source: str, params: Dict[str, Any], output_dir: str):
    """
    Write extracted IOCs to a CSV file in the specified output directory.

    Args:
        iocs_obj (IOCs): A Pydantic `IOCs` object containing the extracted Indicators of Compromise.
        source (str): A string representing the source of the intelligence data
                      (e.g., a URL or file path) used to generate the report name.
        params (Dict[str, Any]): A dictionary of parameters used for report generation, including:
            - chunk_size (int): Size of document chunks.
            - num_ctx (int): Context window size.
            - num_predict (int): Maximum tokens to predict.
        output_dir (str): The directory where the report file should be saved.

    Raises:
        OSError: If the output directory cannot be created or the file cannot be written.

    Side Effects:
        - Creates the specified output directory if it does not exist.
        - Writes the CSV file containing IOC data to the specified output directory.

    Example:
        >>> iocs_obj = IOCs(iocs=[...])
        >>> source = "https://example.com/threat-report"
        >>> params = {"chunk_size": 500, "num_ctx": 1024, "num_predict": 256}
        >>> write_report(iocs_obj, source, params, output_dir="output")

    Notes:
        The report file is named based on the `source` and `params` values, ensuring a unique
        and descriptive filename. The IOCs are converted to CSV format before writing.
    """
    report_name = generate_report_name(source, params)
    csv_output = iocs_to_csv(iocs_obj)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    with open(f"{output_dir}/{report_name}", "w", encoding="utf-8") as f_dst:
        f_dst.write(csv_output)


def extract_iocs(
    intel: List[Document],
    model: str,
    params: Dict[str, Any],
    seed: Optional[int] = None,
    progress: Optional[Progress] = None,
    ) -> IOCs:
    """
    Extract Indicators of Compromise (IOCs) from the provided intelligence data.

    Args:
        intel (List[Document]): A list of LangChain `Document` objects representing 
            the raw threat intelligence data to analyze.
        model (str): The LLM model to use for IOC extraction.
        params (Dict[str, Any]): A dictionary containing extraction parameters:
            - chunk_size (int): Maximum size of each data chunk for LLM input.
            - chunk_overlap (int): Overlap size between consecutive chunks.
            - num_ctx (int): Context window size for the LLM input.
            - num_predict (int): Maximum number of tokens to predict.
        seed (Optional[int]): Random seed for consistent results. Defaults to None.
        progress (Optional[Progress]): A Rich `Progress` object to display and 
            track progress externally. Defaults to None.

    Returns:
        IOCs: A Pydantic `IOCs` object containing the extracted Indicators of Compromise, 
        with deduplicated entries and combined context.

    Notes:
        - The input intelligence data is divided into chunks based on the specified 
          `chunk_size` and `chunk_overlap` parameters.
        - Each chunk is processed using the specified LLM model to extract IOC objects.
        - If a `Progress` object is provided, progress is tracked for each chunk processed.

    Example:
        >>> from langchain.schema import Document
        >>> intel = [Document(page_content="Sample intel text.", metadata={})]
        >>> model = "example-llm-model"
        >>> params = {
        ...     "chunk_size": 500,
        ...     "chunk_overlap": 100,
        ...     "num_ctx": 1024,
        ...     "num_predict": 256
        ... }
        >>> extract_iocs(intel, model, params)
    """

    chunks = split_docs(
        intel, chunk_size=params["chunk_size"], chunk_overlap=params["chunk_overlap"]
    )
    task_id = None

    if progress:
        task_id = progress.add_task("🔎 [green]Extracting IOCs...", total=len(chunks))

    iocs_obj = IOCs(iocs=[])

    for chunk in chunks:
        extracted = process_chunk(
            chunk.page_content, model, params["num_predict"], params["num_ctx"], seed
        )
        iocs_obj.iocs.extend(extracted)

        if progress and task_id is not None:
            progress.advance(task_id)
            progress.update(
                task_id,
                description=f"🔎 [green]Extracted IOCs: [bold]{len(iocs_obj.iocs)}[/bold][/green]",
            )

    iocs_obj.deduplicate_and_combine_context()

    return iocs_obj
