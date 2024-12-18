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

from typing import List, Dict
from langchain_ollama import ChatOllama
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


def generate_report_name(chunks: List[dict], params: Dict[str, str]) -> str:
    """
    Generate a report name based on metadata and parameters.

    Args:
        chunks (List[dict]): List of metadata dictionaries for the chunks.
        chunk_size (int): Size of document chunks.
        num_ctx (int): Context window size.
        num_predict (int): Maximum tokens to predict.

    Returns:
        str: The generated report name.
    """
    report_name = (
        chunks[0]
        .metadata["source"]
        .replace("https://", "")
        .replace("/", "_")
        .replace(".", "_")
    )
    report_name += f"_cs-{params['chunk_size']}_nc-{params['num_ctx']}"
    report_name += f"_np-{params['num_predict']}.csv"
    return report_name


def write_iocs_to_file(iocs: List[str], report_name: str):
    """
    Write extracted IOCs to a file.

    Args:
        iocs (List[str]): List of IOCs in CSV format.
        report_name (str): Name of the file to save the IOCs.
    """
    with open(f"output/{report_name}", "w", encoding="utf-8") as f_dst:
        f_dst.write("\n".join(iocs))


def extract_iocs(
    intel, model, params: Dict[str, str], seed=None, progress=None
) -> IOCs:
    """
    Extract Indicators of Compromise (IOCs) from the provided intelligence data.

    Args:
        intel (list[Document]): The raw threat intelligence data to analyze,
            represented as a list of LangChain `Document` objects.
        model (str): The LLM model to use for extraction.
        params (Dict[str, str]): A dictionary containing extraction parameters:
            - chunk_size (int): Maximum size of each data chunk for LLM input.
            - num_predict (int): Maximum number of tokens to predict.
            - num_ctx (int): Size of the context window used for LLM input.
        seed (int, optional): Random seed for consistent results. Defaults to None.
        progress (Progress, optional): A Rich Progress object to track progress externally.

    Returns:
        IOCs: A Pydantic `IOCs` object containing the extracted Indicators of Compromise,
              with deduplicated and combined context.
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

    report_name = generate_report_name(chunks, params)

    iocs_obj.deduplicate_and_combine_context()
    csv_output = iocs_to_csv(iocs_obj)

    with open(f"output/{report_name}", "w", encoding="utf-8") as f_dst:
        f_dst.write(csv_output)

    return iocs_obj
