"""
Module for processing and storing threat intelligence data in a vector store.

This module provides functions for acquiring, splitting, and storing documents
as well as retrieving relevant context based on queries. It utilizes LangChain for
document processing and vector storage, and Ollama for generating embeddings.

Key Functions:
- split_docs: Split documents into smaller chunks for processing.
- store_docs: Add documents to the vector store.
- store_data: Process raw data, split it, and store it in the vector store.
- acquire_intel: Load threat intelligence data from a URL or local source.
- retrieve_context: Retrieve the most relevant documents from the vector store based on a query.
"""

from typing import List
from langchain_core.documents import Document
from langchain_core.vectorstores import InMemoryVectorStore
from langchain_ollama import OllamaEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from docling.document_converter import DocumentConverter
from thsensai.web_scraper import scrape_web

# Initialize embeddings and vector store
embeddings = OllamaEmbeddings(model="nomic-embed-text:latest")
vector_store = InMemoryVectorStore(embeddings)


def split_docs(
    docs: List[Document], chunk_size: int = 1000, chunk_overlap: int = 200
) -> List[Document]:
    """
    Split documents into smaller chunks for processing.

    Args:
        docs (List[Document]): List of documents to split.
        chunk_size (int): Maximum size of each chunk in characters (default is 1000).
        chunk_overlap (int): Overlap between chunks in characters (default is 200).

    Returns:
        List[Document]: List of split document chunks.
    """
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        add_start_index=True,
    )
    return text_splitter.split_documents(docs)


def store_docs(docs: List[Document]) -> None:
    """
    Add documents to the vector store.

    Args:
        docs (List[Document]): List of documents to store.
    """
    vector_store.add_documents(documents=docs)


def store_data(data: str) -> None:
    """
    Process and store data in the vector store.

    This function splits the raw data into smaller chunks and adds them to the vector store.

    Args:
        data (str): Raw data to be split and stored.
    """
    chunks = split_docs(data)
    store_docs(chunks)


def acquire_intel(source: str, css_selector: str = None) -> List[Document]:
    """
    Load threat intelligence data from a URL or local source and store it in the vector store.

    If the source is a URL, the function will scrape the web page. If it's a local file,
    the function will convert the document to text.

    Args:
        source (str): URL or path to the document to scrape/convert.
        css_selector (str, optional): CSS selector to filter content from the webpage.

    Returns:
        List[Document]: List of `Document` objects containing the extracted content.
    """
    if source.startswith("http://") or source.startswith("https://"):
        intel = scrape_web((source,), (css_selector,))
        return intel
    converter = DocumentConverter()
    result = converter.convert(source)
    intel = result.document.export_to_text()
    return [Document(page_content=intel, metadata={"source": source})]


def retrieve_context(query: str, top_k: int = 5) -> str:
    """
    Retrieve the most relevant documents from the vector store based on a query.

    The function performs a similarity search using the provided query and returns the
    concatenated content of the top-k most relevant documents.

    Args:
        query (str): Query to search for.
        top_k (int): Number of top results to retrieve (default is 5).

    Returns:
        str: Concatenated content of the top matching documents.
    """
    docs = vector_store.similarity_search(query, k=top_k)
    return "\n\n".join([doc.page_content for doc in docs])
