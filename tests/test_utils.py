# pylint: disable=missing-module-docstring, missing-function-docstring, redefined-outer-name

import pytest
from thsensai.utils import generate_report_name
from thsensai.intel import Intel
from thsensai.infer import LLMInference


@pytest.fixture
def intel_obj():
    return Intel(
        source="https://example.com",
        chunk_size=3000,
        chunk_overlap=100,
        content_chunks=[],
    )


@pytest.fixture
def llm():
    return LLMInference(model="sample-model", num_predict=-1, num_ctx=4096)


def test_generate_report_name(intel_obj, llm):
    report_name = generate_report_name(
        intel_obj, llm, report_type="ioc", extension="csv"
    )
    expected_name = "ioc_example-com_cs-3000_co-100_nc-4096_np--1.csv"
    assert report_name == expected_name

    report_name_no_type = generate_report_name(intel_obj, llm, extension="csv")
    expected_name_no_type = "example-com_cs-3000_co-100_nc-4096_np--1.csv"
    assert report_name_no_type == expected_name_no_type

    report_name_no_extension = generate_report_name(intel_obj, llm, report_type="ioc")
    expected_name_no_extension = "ioc_example-com_cs-3000_co-100_nc-4096_np--1"
    assert report_name_no_extension == expected_name_no_extension
