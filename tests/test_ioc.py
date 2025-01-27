# pylint: disable=missing-module-docstring, missing-function-docstring, redefined-outer-name

import pytest
from rich.progress import Progress
from thsensai.ioc import IOC, IOCs
from thsensai.infer import LLMInference
from thsensai.intel import Intel


@pytest.fixture
def intel_data():
    return "Sample intelligence data"


@pytest.fixture
def model():
    return "sample-model"


@pytest.fixture
def params():
    return {
        "chunk_size": 3000,
        "chunk_overlap": 100,
        "num_predict": -1,
        "num_ctx": 4096,
    }


@pytest.fixture
def csv_content():
    return (
        "type,value,context\n"
        "IP,192.168.1.1,Sample context\n"
        "Domain,example.com,Another context\n"
    )


@pytest.fixture
def sample_iocs():
    return IOCs(
        iocs=[
            IOC(type="ip", value="192.168.1.1", context="Sample context"),
            IOC(type="domain", value="example.com", context="Another context"),
        ]
    )


def test_iocs_extend_from_csv(csv_content):
    iocs_instance = IOCs(iocs=[])
    iocs_instance.extend_from_csv(csv_content)

    assert len(iocs_instance.iocs) == 2

    assert iocs_instance.iocs[0].type == "domain"
    assert iocs_instance.iocs[0].value == "example.com"
    assert iocs_instance.iocs[0].context == "Another context"

    assert iocs_instance.iocs[1].type == "ip"
    assert iocs_instance.iocs[1].value == "192.168.1.1"
    assert iocs_instance.iocs[1].context == "Sample context"


def test_iocs_deduplicate_and_combine_context():
    iocs_instance = IOCs(
        iocs=[
            IOC(type="ip", value="192.168.1.1", context="Context 1"),
            IOC(type="ip", value="192.168.1.1", context="Context 2"),
            IOC(type="domain", value="example.com", context="Context 3"),
        ]
    )
    iocs_instance.deduplicate_and_combine_context()

    assert len(iocs_instance.iocs) == 2

    assert iocs_instance.iocs[0].type == "domain"
    assert iocs_instance.iocs[0].value == "example.com"
    assert iocs_instance.iocs[0].context == "Context 3"

    assert iocs_instance.iocs[1].type == "ip"
    assert iocs_instance.iocs[1].value == "192.168.1.1"
    assert iocs_instance.iocs[1].context == "Context 1 | Context 2"


def test_iocs_as_csv():
    iocs_instance = IOCs(
        iocs=[
            IOC(type="ip", value="192.168.1.1", context="Sample context"),
            IOC(type="domain", value="example.com", context="Another context"),
        ]
    )
    csv_output = iocs_instance.as_csv()

    expected_csv = (
        "Type,Value,Context\r\n"
        "ip,192.168.1.1,Sample context\r\n"
        "domain,example.com,Another context\r\n"
    )

    assert csv_output == expected_csv


def test_iocs_extend(mocker, sample_iocs):
    mock_llm = mocker.Mock(spec=LLMInference)
    mock_llm.invoke_model.return_value = IOCs(
        iocs=[IOC(type="ip", value="192.168.1.2", context="New context")]
    )
    sample_iocs.extend("Sample chunk content", mock_llm)

    assert len(sample_iocs.iocs) == 3
    assert sample_iocs.iocs[-1].type == "ip"
    assert sample_iocs.iocs[-1].value == "192.168.1.2"
    assert sample_iocs.iocs[-1].context == "New context"


def test_iocs_from_csv(tmp_path):
    csv_content = (
        "type,value,context\n"
        "IP,192.168.1.1,Sample context\n"
        "Domain,example.com,Another context\n"
    )
    csv_file = tmp_path / "iocs.csv"
    csv_file.write_text(csv_content)

    iocs_instance = IOCs.from_csv(str(csv_file))

    assert len(iocs_instance.iocs) == 2
    assert iocs_instance.iocs[0].type == "domain"
    assert iocs_instance.iocs[0].value == "example.com"
    assert iocs_instance.iocs[0].context == "Another context"
    assert iocs_instance.iocs[1].type == "ip"
    assert iocs_instance.iocs[1].value == "192.168.1.1"
    assert iocs_instance.iocs[1].context == "Sample context"


def test_iocs_from_intel(mocker):
    mock_llm = mocker.Mock(spec=LLMInference)
    mock_intel = mocker.Mock(spec=Intel)
    mock_intel.content_chunks = [mocker.Mock(page_content="Sample chunk content")]
    mock_llm.invoke_model.return_value = IOCs(
        iocs=[IOC(type="ip", value="192.168.1.2", context="New context")]
    )

    iocs_instance = IOCs.from_intel(mock_intel, mock_llm)

    assert len(iocs_instance.iocs) == 1
    assert iocs_instance.iocs[0].type == "ip"
    assert iocs_instance.iocs[0].value == "192.168.1.2"
    assert iocs_instance.iocs[0].context == "New context"


def test_iocs_generate(mocker, sample_iocs):
    mock_llm = mocker.Mock(spec=LLMInference)
    mock_intel = mocker.Mock(spec=Intel)
    mock_intel.content_chunks = [mocker.Mock(page_content="Sample chunk content")]
    mock_llm.invoke_model.return_value = IOCs(
        iocs=[IOC(type="ip", value="192.168.1.2", context="New context")]
    )
    progress = mocker.Mock(spec=Progress)

    sample_iocs.generate(mock_intel, mock_llm, progress)

    assert len(sample_iocs.iocs) == 3
    assert sample_iocs.iocs[-1].type == "ip"
    assert sample_iocs.iocs[-1].value == "192.168.1.2"
    assert sample_iocs.iocs[-1].context == "New context"


def test_iocs_write_report(mocker, sample_iocs, tmp_path):
    mock_intel = mocker.Mock(spec=Intel)
    mock_intel.source = "https://example.com"
    mock_intel.chunk_size = 3000
    mock_intel.chunk_overlap = 100
    mock_llm = mocker.Mock(spec=LLMInference)
    mock_llm.num_ctx = 4096
    mock_llm.num_predict = -1
    output_dir = tmp_path / "reports"

    sample_iocs.write_report(mock_intel, mock_llm, str(output_dir))

    report_file = output_dir / "ioc_example-com_cs-3000_co-100_nc-4096_np--1.csv"
    assert report_file.exists()
    assert report_file.read_text() == (
        "Type,Value,Context\n"
        "ip,192.168.1.1,Sample context\n"
        "domain,example.com,Another context\n"
    )
