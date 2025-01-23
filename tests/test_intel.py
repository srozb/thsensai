# pylint: disable=missing-module-docstring, missing-function-docstring, redefined-outer-name

import pytest
from langchain_core.documents import Document
from thsensai.intel import Intel


@pytest.fixture
def intel_instance():
    return Intel(
        source="https://github.com/srozb/thsensai/blob/master/README.md",
        css_selector="repository-content ",
    )


def test_acquire_intel(intel_instance):
    intel_instance.acquire_intel()
    assert intel_instance.content is not None
    assert len(intel_instance.content) > 0
    assert (
        "sensai - AI-Aided Threat Intelligence & Hunting"
        in intel_instance.content[0].page_content
    )


def test_split_content(intel_instance):
    intel_instance.content = [Document(page_content="test content " * 100)]
    intel_instance.split_content(chunk_size=50, chunk_overlap=10)
    assert intel_instance.content_chunks is not None
    assert len(intel_instance.content_chunks) > 0


def test_save_to_disk(intel_instance, tmp_path):
    intel_instance.content = [Document(page_content="test content")]
    output_dir = tmp_path / "output"
    intel_instance.save_to_disk(output_dir)
    assert (output_dir / "intel.txt").exists()
    with open(output_dir / "intel.txt", "r", encoding="utf-8") as f:
        content = f.read()
        assert "test content" in content
