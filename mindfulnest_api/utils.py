"""
Utility functions for document processing and formatting
"""

def format_documents_for_context(docs):
    """
    Convert retrieved documents into clean context string.

    Args:
        docs: List of LangChain document objects

    Returns:
        Formatted context string
    """
    if not docs:
        return "No relevant information found."

    pieces = []
    for i, doc in enumerate(docs, 1):
        # Clean and format text
        text = doc.page_content.strip().replace("\n", " ")
        pieces.append(f"Document {i}:\n{text}")

    return "\n\n".join(pieces)


def extract_sources(docs):
    """
    Extract unique sources from retrieved documents.

    Args:
        docs: List of LangChain document objects

    Returns:
        List of unique source strings
    """
    sources = []

    for doc in docs:
        # Try multiple metadata fields
        source = (
            doc.metadata.get("source") or 
            doc.metadata.get("title") or 
            doc.metadata.get("page_label") or 
            "unknown"
        )

        # Add only unique sources
        if source not in sources:
            sources.append(source)

    return sources


def clean_response_formatting(text):
    """
    Clean LLM response formatting for better UI display.
    Removes markdown artifacts and normalizes spacing.

    Args:
        text: Raw LLM response text

    Returns:
        Cleaned text suitable for JSON API responses
    """
    if not text:
        return ""

    # Remove markdown bold (**text** -> text)
    text = text.replace("**", "")

    # Remove markdown italic (*text* -> text)
    import re
    text = re.sub(r'(?<!\*)\*(?!\*)', '', text)  # Remove single asterisks

    # Remove markdown bullet points (- item -> item)
    text = re.sub(r'^\s*[-*]\s+', '', text, flags=re.MULTILINE)

    # Normalize newlines (keep paragraph breaks)
    text = text.replace("\n\n\n", "\n\n")  # Max 2 newlines

    # Remove trailing/leading whitespace
    text = text.strip()

    return text


def clean_text(text):
    """
    Clean text by removing extra whitespace and newlines.

    Args:
        text: Input text string

    Returns:
        Cleaned text
    """
    if not text:
        return ""

    # Replace multiple spaces with single space
    text = " ".join(text.split())
    return text.strip()


def truncate_text(text, max_length=200):
    """
    Truncate text to maximum length with ellipsis.

    Args:
        text: Input text
        max_length: Maximum character length

    Returns:
        Truncated text
    """
    if len(text) <= max_length:
        return text

    return text[:max_length].rsplit(" ", 1)[0] + "..."
