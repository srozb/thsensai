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
    Detection_Techniques (List[str]): A list of detection techniques associated 
        with the hypothesis.
    Priority_Level (str): The priority level of the hypothesis.

Hypotheses Attributes:
    Hypotheses (List[Hypothesis]): A list of Hypothesis objects.
"""

from __future__ import annotations
from typing import List, Optional
from pydantic import BaseModel
from pydantic import ValidationError
from rich import print as rp
from thsensai.infer import LLMInference
from thsensai.utils import generate_report_name, ensure_dir_exist


class Able(BaseModel):
    """
    A class representing the PEAK's ABLE method to help determine the critical pieces of
    hunting hypothesis.
    """

    actor: str = ""
    behavior: str = ""
    location: str = ""
    evidence: str = ""

    def generate(self, hypothesis: Hypothesis, llm: LLMInference):
        """
        Generate the ABLE method for a given hypothesis.

        Args:
            model (str): The LLM model to use for ABLE method generation.
            num_predict (int): Maximum number of tokens to predict.
            num_ctx (int): Context window size for the LLM input.
            seed (int): Random seed for consistent results.
        """
        query = (
            "You are a cybersecurity expert specializing in proactive threat hunting "
            "and adversary detection. Your task is to analyze a given hypothesis "
            "statement and break it down into its critical components using the "
            "**ABLE method** (Actor, Behavior, Location, Evidence).\n\n"
            "### Inputs:\n"
            "- A hypothesis statement related to potential adversary activity or "
            "malicious behavior.\n\n"
            "### Tasks:\n"
            "1. Use the ABLE method to identify the following critical pieces:\n"
            "    - Actor: Identify the threat actor or general type of adversary "
            "involved (e.g., APT groups, ransomware operators, insiders). If the "
            "actor is unknown, infer the most likely profile based on the hypothesis.\n"
            "    - Behavior: Define the specific activity or TTPs (Tactics, "
            "Techniques, and Procedures) that the threat actor is performing or "
            "attempting to perform.\n"
            "    - Location: Specify the part(s) of the organization’s infrastructure "
            "or network where this behavior is likely to manifest (e.g., endpoints, "
            "servers, network perimeter).\n"
            "    - Evidence: Detail the required data sources to investigate and "
            "describe what observable indicators or anomalies might confirm the hypothesis.\n"
            "2. Ensure Contextual Relevance:\n"
            "    - Use domain knowledge to make informed assumptions if the hypothesis "
            "lacks explicit details.\n"
            "    - Include contextual reasoning to explain the link between the hypothesis "
            "and the ABLE components.\n\n"
            "### Example Output:\n"
            "```json\n"
            "{\n"
            '    "actor": "Cybercriminal group leveraging stolen credentials",\n'
            '    "behavior": "Unauthorized access and data exfiltration",\n'
            '    "location": "Cloud storage environment (e.g., AWS S3, Azure Blob Storage)",\n'
            '    "evidence": "Unusual login patterns from anomalous IPs, access to '
            'sensitive files outside of business hours, and high-volume data downloads"\n'
            "}\n"
            "```\n"
        )
        try:
            structured_output = llm.invoke_model(
                hypothesis.model_dump_json, query, Able
            )
            if structured_output is not None:
                self.actor = structured_output.actor
                self.behavior = structured_output.behavior
                self.location = structured_output.location
                self.evidence = structured_output.evidence
        except ValidationError as e:
            rp(f"Validation error: {e}")
        return self


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
    able: Optional[Able] = None
    Priority_Level: str


class Hypotheses(BaseModel):
    """
    A class representing a collection of hypotheses.

    Attributes:
        Hypotheses (List[Hypothesis]): A list of Hypothesis objects.
    """

    hypotheses: List[Hypothesis]

    def generate_able(self, llm: LLMInference):
        """
        Enrich the hypotheses with ABLE method details.

        Args:
            model (str): The LLM model to use for ABLE method generation.
            num_predict (int): Maximum number of tokens to predict.
            num_ctx (int): Context window size for the LLM input.
            seed (int): Random seed for consistent results.
        """
        if self.hypotheses is None:
            raise ValueError("No hypotheses to enrich with ABLE method.")
        for hypothesis in self.hypotheses:
            able = Able()
            able.generate(hypothesis, llm)
            hypothesis.able = able

    def generate(
        self,
        iocs_csv: str,
        llm: LLMInference,
        num_hypotheses: int = 5,
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
        query = (
            "You are a cybersecurity expert assisting in proactive threat hunting. "
            "Your task is to create actionable threat hunting hypotheses based "
            "on a CSV containing Indicators of Compromise (IOCs) provided as input.\n\n"
            "### Inputs:\n"
            "The IoCs/TTPs list that includes fields like `indicator_type` "
            "(e.g., IP, domain, hash), `indicator_value`, `context`.\n\n"
            "### Tasks:\n"
            f"1. Develop {num_hypotheses} actionable threat hunting hypotheses that "
            "leverage these IOCs in a modern enterprise network environment.\n"
            "2. Include examples of how these hypotheses could map to specific log "
            "sources (e.g., endpoint logs, DNS traffic, proxy logs, SIEM data).\n\n"
            "### Output Schema:\n"
            "Return structured output for each hypothesis with the following fields:\n"
            "- `Hypothesis_ID`: A unique identifier for the hypothesis.\n"
            "- `Hypothesis`: A concise statement of the hypothesis.\n"
            "- `Rationale`: Explain the reasoning behind the hypothesis and how it "
            "connects to the IOCs.\n"
            "- `Log_Sources`: Suggested log sources for validation.\n"
            "- `Detection_Techniques`: Suggested methods (e.g., correlation rules, "
            "anomaly detection) to test the hypothesis.\n"
            "- `Priority_Level`: Rank the hypothesis based on urgency or likelihood of "
            "malicious activity.\n\n"
            "### Example Output:\n"
            "```json\n"
            "[\n"
            "    {\n"
            '        "Hypothesis_ID": "HYP-001",\n'
            '        "Hypothesis": "Malicious domain communications observed in '
            'DNS logs.",\n'
            '        "Rationale": "Several domains are flagged with high confidence '
            'scores and were recently active in phishing campaigns.",\n'
            '        "Log_Sources": ["DNS query logs", "Proxy logs"],\n'
            '        "Detection_Techniques": ["Anomaly detection"],\n'
            '        "Priority_Level": "High"\n'
            "    },\n"
            "    ...\n"
            "]\n"
            "```"
        )

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
            if hypothesis.able:
                rp("[bold]ABLE Method:[/bold]")
                rp(f"  [bold]- Actor:[/bold] {hypothesis.able.actor}")
                rp(f"  [bold]- Behavior:[/bold] {hypothesis.able.behavior}")
                rp(f"  [bold]- Location:[/bold] {hypothesis.able.location}")
                rp(f"  [bold]- Evidence:[/bold] {hypothesis.able.evidence}")
            rp("")

    def write_report(
        self,
        source: str,
        llm: LLMInference,
        params: dict,
        output_dir: str = ".",
    ):
        """
        Generates a report and writes it to a specified output directory.

        Args:
            source (str): The source identifier for the report.
            params (dict): A dictionary of parameters used to generate the report.
            output_dir (str): The directory where the report will be saved.
        """
        report_name = generate_report_name(source, llm, params, "hyp", "json")
        ensure_dir_exist(output_dir)
        with open(f"{output_dir}/{report_name}", "w", encoding="utf-8") as f_dst:
            f_dst.write(self.model_dump_json())
