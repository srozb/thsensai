"""
Intel class for acquiring and processing threat intelligence data.
"""

from __future__ import annotations
import os
from typing import List, Optional
from pydantic import BaseModel
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from docling.document_converter import DocumentConverter
from thsensai.web_scraper import scrape_web

class Intel(BaseModel):
    """
    A class to represent threat intelligence data.
    Attributes:
        source (str): The source of the threat intelligence data.
        css_selector (Optional[str]): The CSS selector to use for web scraping.
        content (str): The content of the threat intelligence data.
        content_chunks (List[str]): The split content of the threat intelligence data.
        chunk_size (int): The size of each chunk in characters.
        chunk_overlap (int): The overlap between chunks in characters.
    """
    source: str
    css_selector: Optional[str] = None
    content: Optional[List[Document]] = None
    content_chunks: Optional[List[Document]] = None
    chunk_size: int = 2000
    chunk_overlap: int = 200

    def acquire_intel(self):
        """
        Load threat intelligence data from a URL or local source and store it in the vector store.

        If the source is a URL, the function will scrape the web page. If it's a local file,
        the function will convert the document to text.

        Returns:
            List[Document]: List of `Document` objects containing the extracted content.
        """
        if self.source.startswith("http://") or self.source.startswith("https://"):
            self.content = scrape_web((self.source,), (self.css_selector,))
        else:
            converter = DocumentConverter()
            result = converter.convert(self.source)
            intel = result.document.export_to_text()
            self.content = [Document(page_content=intel, metadata={"source": self.source})]

    @classmethod
    def from_source(cls, source: str, css_selector: Optional[str] = None) -> Intel:
        """
        Create a new Intel instance from the given source by running acquire_intel.

        Args:
            source (str): The source from which to acquire intelligence data.
            css_selector (Optional[str]): The CSS selector to use for web scraping.

        Returns:
            Intel: A new instance of the Intel class with the acquired content.
        """
        intel_instance = cls(source=source, css_selector=css_selector)
        intel_instance.acquire_intel()
        return intel_instance

    def split_content(self, chunk_size: Optional[int] = None, chunk_overlap: Optional[int] = None):
        """
        Split the content into smaller chunks for processing.

        Returns:
            List[Document]: List of split document chunks.
        """
        if chunk_size:
            self.chunk_size = chunk_size
        if chunk_overlap:
            self.chunk_overlap = chunk_overlap
        if self.content:
            text_splitter = RecursiveCharacterTextSplitter(
                chunk_size=self.chunk_size,
                chunk_overlap=self.chunk_overlap,
                add_start_index=True,
            )
            self.content_chunks = text_splitter.split_documents(self.content)

    def save_to_disk(self, output_dir: str):
        """
        Save the content to disk.

        Args:
            output_dir (str): Directory where documents will be saved.
        """
        report_name = "intel.txt"
        file_path = os.path.join(output_dir, report_name)
        os.makedirs(output_dir, exist_ok=True)

        with open(file_path, "w", encoding="utf-8") as f:
            for doc in self.content:
                f.write(doc.page_content + "\n\n")
