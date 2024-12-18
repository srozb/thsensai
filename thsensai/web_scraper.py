"""
This module provides functionality to scrape web pages using CSS selectors
and return the extracted content as LangChain documents.

Environment Variables:
    USER_AGENT (str): Sets a custom user agent for HTTP requests.

Functions:
    scrape_web(urls: tuple, css_selectors: tuple) -> list:
        Scrapes specified web pages using the provided CSS selectors.
"""

import os
import bs4

os.environ["USER_AGENT"] = "sensAI/1.0"

from langchain_community.document_loaders import WebBaseLoader  # noqa: C0413


def scrape_web(urls: tuple, css_selectors: tuple):
    """
    Scrape the specified web pages using CSS selectors and return the extracted
    content as LangChain documents.

    Args:
        urls (tuple): A tuple of URLs of the web pages to scrape.
        css_selectors (tuple, optional): A tuple of CSS selectors used for extracting
            relevant content from the web pages. If None, scrape the entire page.


    Returns:
        list: A list of LangChain documents containing the extracted content.
    Raises:
        ValueError: If no content is extracted or a problem occurs during scraping.
    """
    loader = WebBaseLoader(
        web_paths=urls,
        bs_kwargs={
            "parse_only": bs4.SoupStrainer(class_=css_selectors),
        }
    )
    try:
        docs = loader.load()
        # Check if all pages have empty content
        empty_docs = [doc for doc in docs if not doc.page_content.strip()]
        if empty_docs:
            empty_sources = [
                doc.metadata.get("source", "Unknown source") for doc in empty_docs
            ]
            raise ValueError(
                f"No content extracted from the following sources: {', '.join(empty_sources)}. "
                "Possible reasons: incorrect CSS selector, "
                "page behind Cloudflare or other protections. "
                "Try different scrapping strategy."
            )
        return docs
    except Exception as e:
        raise ValueError(f"An error occurred during web scraping: {e}") from e
