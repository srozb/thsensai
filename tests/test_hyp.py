# pylint: disable=missing-module-docstring, missing-function-docstring, redefined-outer-name

import pytest
from thsensai.hyp import Hypothesis, Hypotheses, Able
from thsensai.infer import LLMInference

@pytest.fixture
def hypothesis_instance():
    return Hypothesis(
        Hypothesis_ID="HYP-001",
        Hypothesis="Test Hypothesis",
        Rationale="Test Rationale",
        Log_Sources=["log1", "log2"],
        Detection_Techniques=["technique1", "technique2"],
        Priority_Level="High"
    )

def test_generate_able(hypothesis_instance, mocker):
    mock_llm = mocker.Mock(spec=LLMInference)
    mock_llm.invoke_model.return_value = Able(
        actor="Test Actor",
        behavior="Test Behavior",
        location="Test Location",
        evidence="Test Evidence"
    )
    able = Able()
    able.generate(hypothesis_instance, mock_llm)
    assert able.actor == "Test Actor"
    assert able.behavior == "Test Behavior"
    assert able.location == "Test Location"
    assert able.evidence == "Test Evidence"

def test_hypotheses_generate_able(hypothesis_instance, mocker):
    mock_llm = mocker.Mock(spec=LLMInference)
    mock_llm.invoke_model.return_value = Able(
        actor="Test Actor",
        behavior="Test Behavior",
        location="Test Location",
        evidence="Test Evidence"
    )
    hypotheses = Hypotheses(hypotheses=[hypothesis_instance])
    hypotheses.generate_able(mock_llm)
    for hypothesis in hypotheses.hypotheses:
        assert hypothesis.able is not None
        assert hypothesis.able.actor == "Test Actor"
        assert hypothesis.able.behavior == "Test Behavior"
        assert hypothesis.able.location == "Test Location"
        assert hypothesis.able.evidence == "Test Evidence"
