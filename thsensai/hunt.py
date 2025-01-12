from typing import List, Optional
from pydantic import BaseModel
from pydantic import ValidationError
from rich import print as rp
from thsensai.infer import LLMInference
from thsensai.hyp import Hypotheses
from thsensai.ioc import IOCs


class Scope(BaseModel):
    targets: Optional[List[str]] = None
    timeframe_days: Optional[int] = None
    datasources: Optional[List[str]] = None

class HuntMeta(BaseModel):
    name: Optional[str] = None
    purpose: Optional[str] = None
    objective: Optional[str] = None
    scope: Scope = Scope()
    expected_outcome: Optional[str] = None

    def generate(self, iocs_csv: str, model: str, params: dict, seed: Optional[int] = None):
        query = (
            "You are a cybersecurity expert specializing in threat hunting and incident response."
            "Your task is to design a detailed threat hunting exercise plan based on a provided "
            "list of Indicators of Compromise (IOCs) in a CSV format. The CSV includes fields such "
            "as `type` (e.g., IP, domain, hash), `value` (the IOC itself), and "
            "`context` (e.g., associated campaigns, threat actor activity, or attack vector).\n\n"
            "### Tasks:\n"
            "1. Analyze the provided IOCs and develop a comprehensive threat hunting "
            "exercise plan using the provided schema.\n"
            "2. Incorporate realistic, scenario-driven details such as likely adversary behaviors, "
            "relevant systems, and suitable data sources.\n"
            "3. Exclude the `hypotheses` field, as it will be provided separately.\n"
            "### Schema:\n"
            "The output must adhere to the following schema:\n"
            "HuntMeta(\n"
            'name="Hunt for Adversaries Exploiting CVE-2025-2152 for Initial Access",\n'
            'purpose="To identify and mitigate attempts by adversaries to exploit CVE-2025-2152 in external-facing systems.",\n'
            'objective="Validate IOC activity related to CVE-2025-2152 and uncover potential exploitation attempts.",\n'
            "scope=Scope(\n"
            'targets=["External-facing web servers", "Active Directory servers", "VPN gateways"],\n'
            "timeframe_days=30,\n"
            'datasources=["Web server logs", "IDS/IPS logs", "Firewall logs", "Endpoint EDR telemetry"]\n'
            "),\n"
            'methodology="Perform IOC correlation with threat intelligence feeds, analyze anomalous '
            'activity on external-facing servers, and validate network connections for potential exploitation patterns.",\n'
            'expected_outcome="The hunt will confirm or deny exploitation attempts, provide insight into adversary '
            'activity, and improve the organization’s detection capabilities."\n'
            ")\n"
        )
        llm = LLMInference(model, params["num_predict"], params["num_ctx"], seed=seed)
        try:
            structured_output = llm.invoke_model(iocs_csv, query, HuntMeta)
            if structured_output is not None:
                self.name = structured_output.name
                self.purpose = structured_output.purpose
                self.objective = structured_output.objective
                self.scope = structured_output.scope
                self.expected_outcome = structured_output.expected_outcome
        except ValidationError as e:
            rp(f"Validation error: {e}")
    
    def display(self):
        rp(f"[bold]Name:[/bold] {self.name}")
        rp(f"[bold]Purpose:[/bold] {self.purpose}")
        rp(f"[bold]Objective:[/bold] {self.objective}")
        rp("[bold]Scope:[/bold]")
        rp(f"[bold]  - Targets:[/bold] {', '.join(self.scope.targets)}")
        rp(f"[bold]  - Timeframe:[/bold] {self.scope.timeframe_days} days")
        rp(f"[bold]  - Data Sources:[/bold] {', '.join(self.scope.datasources)}")
        rp(f"[bold]Expected Outcome:[/bold] {self.expected_outcome}")


class Hunt(BaseModel):
    meta: HuntMeta = HuntMeta()
    hypotheses: Optional[Hypotheses] = Hypotheses(hypotheses=[])
    iocs: Optional[IOCs] = IOCs(iocs=[])

    def display(self):
        rp("[green]Hunt Summary:[/green]")
        self.meta.display()
        rp("")
        if self.hypotheses is not None:
            rp("[green]Hypotheses:[/green]")
            self.hypotheses.display()
            rp("")
        if self.iocs is not None:
            rp("[green]IOCs:[/green]")
            self.iocs.display()
            rp("")

    def generate(self, model, params):
        if self.iocs is None:
            raise ValueError("IOCs must be provided to generate hypotheses.")
        self.meta.generate(self.iocs.as_csv(), model, params)
        self.hypotheses.generate(self.iocs.as_csv(), model, params)