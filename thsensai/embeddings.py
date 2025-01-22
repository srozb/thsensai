"""
This module will contain utility functions for processing and storing data in the vector store.
Not implemented yet.
"""

from typing import List
from langchain_ollama import OllamaEmbeddings
from langchain_core.vectorstores import InMemoryVectorStore
from langchain_core.documents import Document


# Initialize embeddings and vector store
embeddings = OllamaEmbeddings(model="nomic-embed-text:latest")
vector_store = InMemoryVectorStore(embeddings)


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