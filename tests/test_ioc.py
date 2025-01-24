# pylint: disable=missing-module-docstring, missing-function-docstring, redefined-outer-name

import pytest
from thsensai.ioc import IOC, IOCs


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
