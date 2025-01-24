# pylint: disable=missing-module-docstring, missing-function-docstring, redefined-outer-name

import pytest
from thsensai.hunt import Scope, HuntMeta, Hunt
from thsensai.ioc import IOCs, IOC
from thsensai.hyp import Hypotheses
from thsensai.infer import LLMInference


@pytest.fixture
def mock_llm(mocker):
    return mocker.Mock(spec=LLMInference)


@pytest.fixture
def sample_iocs():
    return IOCs(
        iocs=[
            IOC(type="ip", value="192.168.1.1", context="Sample context"),
            IOC(type="domain", value="example.com", context="Another context"),
        ]
    )



sample_hypotheses=[
    {
        "Hypothesis_ID": "HYP-001",
        "Hypothesis": "Test Hypothesis 1",
        "Rationale": "Test Rationale",
        "Log_Sources": ["log1", "log2"],
        "Detection_Techniques": ["technique1", "technique2"],
        "Priority_Level": "High",
    },
    {
        "Hypothesis_ID": "HYP-002",
        "Hypothesis": "Test Hypothesis 2",
        "Rationale": "Test Rationale",
        "Log_Sources": ["log1", "log2"],
        "Detection_Techniques": ["technique1", "technique2"],
        "Priority_Level": "High",
    },
]


def test_scope_generate_targets(mock_llm, mocker):
    mock_llm.invoke_model.return_value = Scope(targets=["Target 1", "Target 2"])
    scope = Scope()
    hunt = Hunt(hypotheses=Hypotheses(hypotheses=[]))
    mocker.patch(
        "builtins.open",
        mocker.mock_open(read_data="scope_id;description\n1;Scope 1\n2;Scope 2"),
    )
    scope.generate_targets("scopes.csv", hunt, mock_llm)
    assert scope.targets == ["Target 1", "Target 2"]


def test_scope_generate_playbooks(mock_llm, mocker):
    mock_llm.invoke_model.return_value = Scope(playbooks=["Playbook 1", "Playbook 2"])
    scope = Scope()
    hunt = Hunt(hypotheses=Hypotheses(hypotheses=[]))
    mocker.patch(
        "builtins.open",
        mocker.mock_open(
            read_data="playbook_name;description\n1;Playbook 1\n2;Playbook 2"
        ),
    )
    scope.generate_playbooks("playbooks.csv", hunt, mock_llm)
    assert scope.playbooks == ["Playbook 1", "Playbook 2"]


def test_huntmeta_generate(mock_llm, sample_iocs):
    mock_llm.invoke_model.return_value = HuntMeta(
        name="Test Hunt",
        purpose="Test Purpose",
        scope=Scope(
            targets=["Target 1"],
            timeframe_days=30,
            datasources=["DataSource 1"],
            playbooks=["Playbook 1"],
        ),
        expected_outcome="Test Outcome",
    )
    hunt_meta = HuntMeta()
    hunt_meta.generate(sample_iocs.as_csv(), mock_llm)
    assert hunt_meta.name == "Test Hunt"
    assert hunt_meta.purpose == "Test Purpose"
    assert hunt_meta.scope.targets == ["Target 1"]
    assert hunt_meta.scope.timeframe_days == 30
    assert hunt_meta.scope.datasources == ["DataSource 1"]
    assert hunt_meta.scope.playbooks == ["Playbook 1"]
    assert hunt_meta.expected_outcome == "Test Outcome"


def test_hunt_generate_meta(mock_llm, sample_iocs):
    hunt = Hunt(iocs=sample_iocs)
    mock_llm.invoke_model.return_value = HuntMeta(
        name="Test Hunt",
        purpose="Test Purpose",
        scope=Scope(
            targets=["Target 1"],
            timeframe_days=30,
            datasources=["DataSource 1"],
            playbooks=["Playbook 1"],
        ),
        expected_outcome="Test Outcome",
    )
    hunt.generate_meta(mock_llm)
    assert hunt.meta.name == "Test Hunt"
    assert hunt.meta.purpose == "Test Purpose"
    assert hunt.meta.scope.targets == ["Target 1"]
    assert hunt.meta.scope.timeframe_days == 30
    assert hunt.meta.scope.datasources == ["DataSource 1"]
    assert hunt.meta.scope.playbooks == ["Playbook 1"]
    assert hunt.meta.expected_outcome == "Test Outcome"


def test_hunt_generate_hypotheses(mock_llm, sample_iocs):
    hunt = Hunt(iocs=sample_iocs)
    mock_llm.invoke_model.return_value = Hypotheses(
        hypotheses=sample_hypotheses
    )
    hunt.generate_hypotheses(mock_llm)
    assert len(hunt.hypotheses.hypotheses) == 2
    assert hunt.hypotheses.hypotheses[0].Hypothesis_ID == "HYP-001"
    assert hunt.hypotheses.hypotheses[0].Hypothesis == "Test Hypothesis 1"
    assert hunt.hypotheses.hypotheses[1].Hypothesis_ID == "HYP-002"
    assert hunt.hypotheses.hypotheses[1].Hypothesis == "Test Hypothesis 2"


def test_hunt_generate(mock_llm, sample_iocs):
    hunt = Hunt(iocs=sample_iocs)
    mock_llm.invoke_model.side_effect = [
        HuntMeta(
            name="Test Hunt",
            purpose="Test Purpose",
            scope=Scope(
                targets=["Target 1"],
                timeframe_days=30,
                datasources=["DataSource 1"],
                playbooks=["Playbook 1"],
            ),
            expected_outcome="Test Outcome",
        ),
        Hypotheses(
            hypotheses=sample_hypotheses
        ),
    ]
    hunt.generate(mock_llm)
    assert hunt.meta.name == "Test Hunt"
    assert hunt.meta.purpose == "Test Purpose"
    assert hunt.meta.scope.targets == ["Target 1"]
    assert hunt.meta.scope.timeframe_days == 30
    assert hunt.meta.scope.datasources == ["DataSource 1"]
    assert hunt.meta.scope.playbooks == ["Playbook 1"]
    assert hunt.meta.expected_outcome == "Test Outcome"
    assert len(hunt.hypotheses.hypotheses) == 2
    assert hunt.hypotheses.hypotheses[0].Hypothesis_ID == "HYP-001"
    assert hunt.hypotheses.hypotheses[0].Hypothesis == "Test Hypothesis 1"
    assert hunt.hypotheses.hypotheses[1].Hypothesis_ID == "HYP-002"
    assert hunt.hypotheses.hypotheses[1].Hypothesis == "Test Hypothesis 2"
