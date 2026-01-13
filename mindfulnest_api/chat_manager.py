"""
Simple chat history manager for conversations
"""
from langchain_core.messages import HumanMessage, AIMessage

class ChatHistoryManager:
    """
    Manages conversation history with automatic cleanup.
    Keeps only recent messages to prevent context overflow.
    """

    def __init__(self, max_history=5):
        """
        Args:
            max_history: Maximum number of message pairs (user + assistant)
        """
        self.history = []
        self.max_history = max_history

    def add_user_message(self, message):
        """Add user message to history"""
        self.history.append(HumanMessage(content=message))
        self._cleanup()

    def add_assistant_message(self, message):
        """Add assistant response to history"""
        self.history.append(AIMessage(content=message))
        self._cleanup()

    def _cleanup(self):
        """Keep only recent messages"""
        max_messages = self.max_history * 2  # pairs of messages
        if len(self.history) > max_messages:
            self.history = self.history[-max_messages:]

    def get_history(self):
        """Get current history for RAG"""
        return self.history

    def clear(self):
        """Clear all history"""
        self.history = []

    def message_count(self):
        """Get total message count"""
        return len(self.history)

    def conversation_pairs(self):
        """Get number of conversation pairs"""
        return len(self.history) // 2
