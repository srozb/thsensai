# pylint: disable=missing-module-docstring, missing-function-docstring, redefined-outer-name

from unittest.mock import patch, MagicMock
import pytest
from thsensai.web_scraper import scrape_web


@pytest.fixture
def mock_loader():
    with patch("thsensai.web_scraper.WebBaseLoader") as mock_loader:
        yield mock_loader


def test_scrape_web_success(mock_loader):
    mock_doc = MagicMock()
    mock_doc.page_content = "Sample content"
    mock_loader.return_value.load.return_value = [mock_doc]

    urls = ("https://example.com",)
    css_selectors = ("content",)
    docs = scrape_web(urls, css_selectors)

    assert len(docs) == 1
    assert docs[0].page_content == "Sample content"


def test_scrape_web_empty_content(mock_loader):
    mock_doc = MagicMock()
    mock_doc.page_content = ""
    mock_doc.metadata = {"source": "https://example.com"}
    mock_loader.return_value.load.return_value = [mock_doc]

    urls = ("https://example.com",)
    css_selectors = ("content",)

    with pytest.raises(
        ValueError,
        match="No content extracted from the following sources: https://example.com",
    ):
        scrape_web(urls, css_selectors)


def test_scrape_web_error(mock_loader):
    mock_loader.return_value.load.side_effect = Exception("Scraping error")

    urls = ("https://example.com",)
    css_selectors = ("content",)

    with pytest.raises(
        ValueError, match="An error occurred during web scraping: Scraping error"
    ):
        scrape_web(urls, css_selectors)
