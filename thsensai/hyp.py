"""
This module defines the Hypothesis and Hypotheses models using Pydantic.

Classes:
    Hypothesis: A model representing a single hypothesis with its details.
    Hypotheses: A model representing a list of Hypothesis objects.

Hypothesis Attributes:
    Hypothesis_ID (str): The unique identifier for the hypothesis.
    Hypothesis (str): The description of the hypothesis.
    Rationale (str): The rationale behind the hypothesis.
    Log_Sources (List[str]): A list of log sources related to the hypothesis.
    Detection_Techniques (List[str]): A list of detection techniques associated with the hypothesis.
    Priority_Level (str): The priority level of the hypothesis.

Hypotheses Attributes:
    Hypotheses (List[Hypothesis]): A list of Hypothesis objects.
"""

from typing import List, Dict, Optional
from pydantic import BaseModel
from pydantic import ValidationError
from rich import print as rp
from thsensai.infer import LLMInference
from thsensai.utils import generate_report_name, ensure_dir_exist


class Hypothesis(BaseModel):
    """
    A class representing a hypothesis with associated details.

    Attributes:
        Hypothesis_ID (str): The unique identifier for the hypothesis.
        Hypothesis (str): The description of the hypothesis.
        Rationale (str): The rationale behind the hypothesis.
        Log_Sources (List[str]): A list of log sources relevant to the hypothesis.
        Detection_Techniques (List[str]): A list of detection techniques applicable
            to the hypothesis.
        Priority_Level (str): The priority level of the hypothesis.
    """

    Hypothesis_ID: str
    Hypothesis: str
    Rationale: str
    Log_Sources: List[str]
    Detection_Techniques: List[str]
    Priority_Level: str


class Hypotheses(BaseModel):
    """
    A class representing a collection of hypotheses.

    Attributes:
        Hypotheses (List[Hypothesis]): A list of Hypothesis objects.
    """

    hypotheses: List[Hypothesis]

    def generate(
        self,
        iocs_csv: str,
        model: str,
        params: Dict,
        seed: Optional[int] = None,
    ):
        """
        Generate actionable threat hunting hypotheses based on a given CSV of IOCs.

        Args:
            iocs_csv (str): The CSV content containing IOC data.
            model (str): The LLM model to use for hypothesis generation.
            num_predict (int): Maximum number of tokens to predict.
            num_ctx (int): Context window size for the LLM input.
            seed (int): Random seed for consistent results.
        """
        query = """
        You are a cybersecurity expert assisting in proactive threat hunting. Your task is to create actionable threat hunting hypotheses based on a CSV containing Indicators of Compromise (IOCs) provided as input.

        ### Inputs:
        The CSV that includes fields like `indicator_type` (e.g., IP, domain, hash), `indicator_value`, `context`.

        ### Tasks:
        1. Develop at least five diverse, actionable threat hunting hypotheses that leverage these IOCs in a modern enterprise network environment.
        2. Include examples of how these hypotheses could map to specific log sources (e.g., endpoint logs, DNS traffic, proxy logs, SIEM data).

        ### Output Schema:
        Return structured output for each hypothesis with the following fields:
        - `Hypothesis_ID`: A unique identifier for the hypothesis.
        - `Hypothesis`: A concise statement of the hypothesis.
        - `Rationale`: Explain the reasoning behind the hypothesis and how it connects to the IOCs.
        - `Log_Sources`: Suggested log sources for validation.
        - `Detection_Techniques`: Suggested methods (e.g., correlation rules, anomaly detection) to test the hypothesis.
        - `Priority_Level`: Rank the hypothesis based on urgency or likelihood of malicious activity.

        ### Example Output:
        ```json
        [
            {
                "Hypothesis_ID": "HYP-001",
                "Hypothesis": "Malicious domain communications observed in DNS logs.",
                "Rationale": "Several domains in the CSV are flagged with high confidence scores and were recently active in phishing campaigns.",
                "Log_Sources": ["DNS query logs", "Proxy logs"],
                "Detection_Techniques": ["Anomaly detection"],
                "Priority_Level": "High"
            },
            ...
        ]
        """

        llm = LLMInference(model, params["num_predict"], params["num_ctx"], seed=seed)
        try:
            structured_output = llm.invoke_model(iocs_csv, query, Hypotheses)
            if structured_output is not None:
                self.hypotheses.extend(structured_output.hypotheses)
                # Perhaps it'd be better to set not extend
        except ValidationError as e:
            rp(f"Validation error: {e}")

    def display(self):
        """
        Displays the details of each hypothesis in the Hypotheses list.
        The details are formatted using rich text formatting.
        """
        for hypothesis in self.hypotheses:
            rp(f"[bold]Hypothesis ID: {hypothesis.Hypothesis_ID}[/bold]")
            rp(f"[bold]Hypothesis:[/bold] {hypothesis.Hypothesis}")
            rp(f"[bold]Rationale:[/bold] {hypothesis.Rationale}")
            rp(f"[bold]Log Sources:[/bold] {hypothesis.Log_Sources}")
            rp(f"[bold]Detection Techniques:[/bold] {hypothesis.Detection_Techniques}")
            rp(f"[bold]Priority Level:[/bold] {hypothesis.Priority_Level}")
            rp("")

    def write_report(
        self,
        source: str,
        params: dict,
        output_dir: str,
    ):
        """
        Generates a report and writes it to a specified output directory.

        Args:
            source (str): The source identifier for the report.
            params (dict): A dictionary of parameters used to generate the report.
            output_dir (str): The directory where the report will be saved.
        """
        report_name = generate_report_name(source, params, "hyp", "json")
        ensure_dir_exist(output_dir)
        with open(f"{output_dir}/{report_name}", "w", encoding="utf-8") as f_dst:
            f_dst.write(self.model_dump_json())
