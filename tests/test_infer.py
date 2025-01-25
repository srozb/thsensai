# pylint: disable=missing-module-docstring, missing-function-docstring, redefined-outer-name

from unittest.mock import patch, MagicMock
import pytest
from pydantic import ValidationError
from thsensai.infer import LLMInference


@pytest.fixture
def llm_inference():
    return LLMInference(
        model="sample-model", num_predict=50, num_ctx=4096, temperature=0.8, seed=42
    )


def test_build_prompt(llm_inference):
    context = "This is the context."
    query = "What is the answer?"
    prompt = llm_inference.build_prompt(context, query)
    expected_prompt = "Use the following context:\n\n```"
    expected_prompt += "\nThis is the context.\n```\n\nWhat is the answer?"
    assert prompt == expected_prompt


def test_invoke_model_success(llm_inference):
    mock_output_schema = MagicMock()
    mock_model_with_structure = MagicMock()
    mock_model_with_structure.invoke.return_value = {"result": "success"}

    with patch(
        "thsensai.infer.ChatOllama.with_structured_output",
        return_value=mock_model_with_structure,
    ):
        result = llm_inference.invoke_model("context", "query", mock_output_schema)
        assert result == {"result": "success"}


def test_invoke_model_validation_error(llm_inference):
    mock_output_schema = MagicMock()
    mock_model_with_structure = MagicMock()
    mock_model_with_structure.invoke.side_effect = ValidationError(
        "Validation error", []
    )

    with patch(
        "thsensai.infer.ChatOllama.with_structured_output",
        return_value=mock_model_with_structure,
    ):
        result = llm_inference.invoke_model("context", "query", mock_output_schema)
        assert result is None
