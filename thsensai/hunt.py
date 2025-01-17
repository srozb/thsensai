"""
This module defines the classes and methods for managing and generating threat hunting exercises.
It includes the following classes:
- Scope: Defines the scope of the hunt, including targets, timeframe, datasources, and playbooks.
- HuntMeta: Contains metadata for the hunt, such as name, purpose, scope, and expected outcome.
- Hunt: Represents the entire hunt, including metadata, hypotheses, and IOCs.

The module also provides methods to generate and display hunt metadata, hypotheses, and playbooks.
"""

from __future__ import annotations
from typing import List, Optional
from pydantic import BaseModel
from pydantic import ValidationError
from rich import print as rp
from thsensai.infer import LLMInference
from thsensai.hyp import Hypotheses
from thsensai.ioc import IOCs


class Scope(BaseModel):
    """
    Defines the scope of the hunt, including targets, timeframe, datasources, and playbooks.
    """

    targets: Optional[List[str]] = None
    timeframe_days: Optional[int] = None
    datasources: Optional[List[str]] = None
    playbooks: Optional[List[str]] = None

    def generate_targets(
        self,
        scopes_filename: str,
        hunt: Hunt,
        llm: LLMInference
    ):
        """
        Generate targets based on the provided scoping information.

        Args:
            scopes_filename (str): The filename containing scope information.
            hunt (Hunt): The hunt object containing hypotheses.
            model (str): The model to use for inference.
            params (dict): Parameters for the model.
            seed (Optional[int]): Seed for reproducibility.
        """
        query = (
            "You are a cybersecurity expert specializing in threat hunting. "
            "Your task is to refine and select the most relevant targets for a threat hunting"
            "exercise based on the provided exercise details and available scopes."
            "The context includes:\n\n"
            "1. A list of potential scopes in the format `scope_id;description`, "
            "representing available areas or systems where the hunt could be conducted.\n"
            "2. A hunt plan containing the exercise's name, description, and selected hypotheses.\n"
            "Analyze this information and identify the most appropriate targets "
            "that align with the hunt's objectives, ensuring they reflect the actual environment "
            "where the exercise will take place. Return the selected targets as a list of "
            "strings adhering to the schema.\n\n"
            "Example Output: "
            '["Endpoints with high-value user accounts", "AD servers", '
            '"External-facing RDP systems"]'
        )

        class Targets(BaseModel):
            "Temporary class to hold the targets"
            targets: List[str]

        with open(scopes_filename, "r", encoding="utf-8") as f:
            user_scopes = f.read()
        context = f"Available targets:\n```\n{user_scopes}\n```\n\n"
        context += (
            f"Hunt Hypotheses:\n```json\n{hunt.hypotheses.model_dump_json()}\n```"
        )
        try:
            structured_output = llm.invoke_model(context, query, Targets)
            if structured_output is not None:
                self.targets = structured_output.targets
        except ValidationError as e:
            rp(f"Validation error: {e}")

    def generate_playbooks(
        self,
        playbooks_filename: str,
        hunt: Hunt,
        llm: LLMInference
    ):
        """
        Generate playbooks based on the provided playbook information.

        Args:
            playbooks_filename (str): The filename containing playbook information.
            hunt (Hunt): The hunt object containing hypotheses.
            model (str): The model to use for inference.
            params (dict): Parameters for the model.
            seed (Optional[int]): Seed for reproducibility.
        """
        query = (
            "You are a cybersecurity expert specializing in threat hunting. "
            "Your task is to select the most relevant hunting playbooks for a threat hunting "
            "exercise based on the exercise's name, description, and selected hypotheses. "
            "The context includes:\n"
            "1. A list of available playbooks in the format `playbook_name;description`, "
            "detailing predefined procedures and their purposes.\n"
            "2. A hunt plan containing the exercise's name, description, and selected hypotheses. "
            "Analyze this information to identify and select the playbooks most suitable for "
            "guiding the hunting exercise, ensuring they align with the hunt's hypotheses.\n"
            "Return the selected playbooks as a list of strings adhering "
            "to the schema. Example Output:\n"
            '["inspect_web_server_logs", "hunt_malware_process_injection", '
            '"search_unusual_account_creation"]'
        )

        class Playbooks(BaseModel):
            "Temporary class to hold the playbooks"
            playbooks: List[str]

        with open(playbooks_filename, "r", encoding="utf-8") as f:
            user_playbooks = f.read()
        context = f"Available playbooks:\n```\n{user_playbooks}\n```\n\n"
        context += f"Hunt Hypotheses:\n{hunt.hypotheses.model_dump_json()}"
        try:
            structured_output = llm.invoke_model(context, query, Playbooks)
            if structured_output is not None:
                self.playbooks = structured_output.playbooks
        except ValidationError as e:
            rp(f"Validation error: {e}")


class HuntMeta(BaseModel):
    """
    Contains metadata for the hunt, such as name, purpose, scope, and expected outcome.
    """

    name: Optional[str] = None
    purpose: Optional[str] = None
    objective: Optional[str] = None
    scope: Scope = Scope()
    expected_outcome: Optional[str] = None

    def generate(
        self, iocs_csv: str, llm: LLMInference
    ):
        """
        Generate hunt metadata based on provided IOCs.

        Args:
            iocs_csv (str): The CSV file containing IOCs.
            model (str): The model to use for inference.
            params (dict): Parameters for the model.
            seed (Optional[int]): Seed for reproducibility.
        """
        query = (
            "You are a cybersecurity expert specializing in threat hunting. "
            "Your task is to design a comprehensive and actionable "
            "threat hunting exercise plan based on a provided list of Indicators of "
            "Compromise (IOCs) in a CSV format. The CSV includes the following fields: "
            "- `type`: The type of IOC (e.g., IP, domain, hash). "
            "- `value`: The IOC itself (e.g., 192.168.1.1, malicious.com, or a file hash). "
            "- `context`: Relevant details, such as associated campaigns, suspected "
            "threat actor activity, or attack vectors. "
            "Tasks: "
            "1. Analyze the provided IOCs to extract meaningful insights and patterns. "
            "Use the context field to identify potential threat scenarios and attack surfaces.\n"
            "2. Develop a preliminary threat hunting exercise plan by creating a descriptive "
            "name, clear purpose, and expected outcome for the hunt.\n"
            "3. Define the anticipated scope, including targets, timeframe, relevant "
            "data sources, and any playbooks to guide the investigation.\n"
            "4. Adhere to the following schema for the output:\n"
            "{"
            '"name": "Descriptive name of the hunt", '
            '"purpose": "Short description of the hunt\'s focus (about 2 sentences long)", '
            '"scope": {'
            '"targets": ["List of systems or assets to investigate"], '
            '"timeframe_days": "Duration of the hunt in days", '
            '"datasources": ["Relevant data sources for analysis"], '
            '"playbooks": ["List of playbooks to guide the hunt"]'
            "}, "
            '"expected_outcome": "Clear and concise outcome statements (about 2 sentences long)"'
            "}\n"
            "Example Output:\n"
            "{"
            '"name": "Hunt for APT29 leveraging the PEAKLIGHT downloader to deliver infostealers", '
            '"purpose": "This hunt focuses on detecting and mitigating adversary TTPs associated '
            'with PEAKLIGHT, a memory-only downloader, to prevent infostealer deployment and '
            'associated compromises. By focusing on these specific TTPs, we can proactively '
            'identify potential compromise before attackers can spread infection, '
            'exfiltrate sensitive data or disrupt critical systems.", '
            '"scope": {'
            '"targets": ["Endpoints with high-value user accounts", "AD servers", '
            '"External-facing RDP systems"], '
            '"timeframe_days": 30, '
            '"datasources": ["Endpoint Detection and Response (EDR) telemetry", '
            '"Firewall logs", "DNS logs"], '
            '"playbooks": ["Investigating Unauthorized Remote Access", '
            '"Detecting Memory-Only Malware"]'
            "}, "
            '"expected_outcome": "Identify unauthorized lateral movement and unusual process '
            'activity, detect anomalous usage patterns of legitimate tools and RDP services, '
            'and mitigate data exfiltration risks. Ultimately this exercise aims to prevent data '
            'breaches and ensure the uninterupted operation of critical systems."'
            "}"
        )
        try:
            structured_output = llm.invoke_model(iocs_csv, query, HuntMeta)
            if structured_output is not None:
                self.name = structured_output.name
                self.purpose = structured_output.purpose
                self.scope = structured_output.scope
                self.expected_outcome = structured_output.expected_outcome
        except ValidationError as e:
            rp(f"Validation error: {e}")

    def display(self):
        """
        Display the hunt metadata using rich print.
        """
        rp(f"[bold]Name:[/bold] {self.name}")
        rp(f"[bold]Purpose:[/bold] {self.purpose}")
        rp("[bold]Scope:[/bold]")
        rp(f"[bold]  - Targets:[/bold] {', '.join(self.scope.targets)}")
        rp(f"[bold]  - Timeframe:[/bold] {self.scope.timeframe_days} days")
        rp(f"[bold]  - Data Sources:[/bold] {', '.join(self.scope.datasources)}")
        if self.scope.playbooks is not None:
            rp(f"[bold]  - Playbooks:[/bold] {', '.join(self.scope.playbooks)}")
        rp(f"[bold]Expected Outcome:[/bold] {self.expected_outcome}")


class Hunt(BaseModel):
    """
    Represents the entire hunt, including metadata, hypotheses, and IOCs.
    """

    meta: HuntMeta = HuntMeta()
    hypotheses: Optional[Hypotheses] = Hypotheses(hypotheses=[])
    iocs: Optional[IOCs] = IOCs(iocs=[])

    @classmethod
    def from_iocs(cls, iocs: IOCs) -> Hunt:
        """
        Create an instance of Hunt with the provided IOCs object.

        Args:
            iocs (IOCs): The IOCs object to initialize the Hunt instance with.

        Returns:
            Hunt: An instance of the Hunt class.
        """
        return cls(iocs=iocs)

    def display(self):
        """
        Display the hunt summary, including metadata, hypotheses, and IOCs.
        """
        rp("[green]Hunt Summary:[/green]")
        self.meta.display()
        rp("")
        if len(self.hypotheses.hypotheses) > 0:
            rp("[green]Hypotheses:[/green]")
            self.hypotheses.display()
            rp("")
        if self.iocs is not None:
            self.iocs.display()
            rp("")

    def generate_meta(self, llm: LLMInference):
        """
        Generate hunt metadata.

        Args:
            model (str): The model to use for inference.
            params (dict): Parameters for the model.
            seed (Optional[int]): Seed for reproducibility.
        """
        if self.iocs is None:
            raise ValueError("IOCs must be provided to generate metadata.")
        self.meta.generate(self.iocs.as_csv(), llm)

    def generate_hypotheses(
        self,
        llm: LLMInference,
        num_hypotheses: int = 5,
    ):
        """
        Generate hypotheses for the hunt.

        Args:
            model (str): The model to use for inference.
            params (dict): Parameters for the model.
            seed (Optional[int]): Seed for reproducibility.
            num_hypotheses (int): Number of hypotheses to generate.
        """
        if self.iocs is None:
            raise ValueError("IOCs must be provided to generate hypotheses.")
        self.hypotheses.generate(
            self.iocs.as_csv(), llm, num_hypotheses
        )

    def generate(self, llm: LLMInference):
        """
        Generate both metadata and hypotheses for the hunt.

        Args:
            model (str): The model to use for inference.
            params (dict): Parameters for the model.
            seed (Optional[int]): Seed for reproducibility.
        """
        self.generate_meta(llm)
        self.generate_hypotheses(llm)

    def dump_to_file(self, filename: str):
        """
        Dump the hunt object to a file in JSON format.

        Args:
            filename (str): The filename to dump the JSON data.
        """
        with open(filename, "w", encoding="utf-8") as f:
            f.write(self.model_dump_json(indent=2))
