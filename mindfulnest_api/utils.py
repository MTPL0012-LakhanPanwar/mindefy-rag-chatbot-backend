"""
Utility functions for document processing and formatting.
"""
from __future__ import annotations

from typing import Iterable, List, Sequence

from langchain_core.documents import Document


def format_documents_for_context(docs: Sequence[Document] | None) -> str:
    """
    Convert retrieved documents into a clean context string.

    Args:
        docs: Sequence of LangChain `Document` objects.

    Returns:
        Formatted context string.
    """
    if not docs:
        return "No relevant information found."

    pieces: List[str] = []
    for i, doc in enumerate(docs, 1):
        # Clean and format text
        text = doc.page_content.strip().replace("\n", " ")
        pieces.append(f"Document {i}:\n{text}")

    return "\n\n".join(pieces)


def extract_sources(docs: Iterable[Document] | None) -> List[str]:
    """
    Extract unique sources from retrieved documents.

    Args:
        docs: Iterable of LangChain `Document` objects.

    Returns:
        List of unique source strings.
    """
    if not docs:
        return []

    sources: List[str] = []

    for doc in docs:
        # Try multiple metadata fields
        source = (
            doc.metadata.get("source")
            or doc.metadata.get("title")
            or doc.metadata.get("page_label")
            or "unknown"
        )

        # Add only unique sources
        if source not in sources:
            sources.append(source)

    return sources


def clean_response_formatting(text: str | None) -> str:
    """
    Clean LLM response formatting for better UI display.

    Removes markdown artifacts and normalizes spacing.

    Args:
        text: Raw LLM response text.

    Returns:
        Cleaned text suitable for JSON API responses.
    """
    if not text:
        return ""

    import re

    # Remove markdown bold (**text** -> text)
    cleaned = text.replace("**", "")

    # Remove markdown italic (*text* -> text)
    cleaned = re.sub(r"(?<!\*)\*(?!\*)", "", cleaned)  # Remove single asterisks

    # Remove markdown bullet points (- item -> item)
    cleaned = re.sub(r"^\s*[-*]\s+", "", cleaned, flags=re.MULTILINE)

    # Normalize newlines (keep paragraph breaks)
    cleaned = cleaned.replace("\n\n\n", "\n\n")  # Max 2 newlines

    # Remove trailing/leading whitespace
    return cleaned.strip()


def clean_text(text: str | None) -> str:
    """
    Clean text by removing extra whitespace and newlines.

    Args:
        text: Input text string.

    Returns:
        Cleaned text.
    """
    if not text:
        return ""

    # Replace multiple spaces with single space
    return " ".join(text.split()).strip()


def truncate_text(text: str, max_length: int = 200) -> str:
    """
    Truncate text to maximum length with ellipsis.

    Args:
        text: Input text.
        max_length: Maximum character length.

    Returns:
        Truncated text.
    """
    if len(text) <= max_length:
        return text

    return text[:max_length].rsplit(" ", 1)[0] + "..."
