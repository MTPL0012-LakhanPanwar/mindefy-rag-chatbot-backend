"""
Main RAG engine for MindfulNest
Handles document retrieval and response generation
Auto-creates vector store if missing
"""
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain_community.vectorstores import FAISS
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

from .config import Config
from .chat_manager import ChatHistoryManager
from .utils import format_documents_for_context, extract_sources, clean_response_formatting
from .logger import setup_logger
from .document_loader import DocumentLoader

logger = setup_logger("rag_engine")


class MindfulNestRAG:
    """
    Production RAG system for mental wellness assistance.
    Automatically creates vector store if it doesn't exist.
    """

    def __init__(self):
        """Initialize the RAG system"""
        logger.info("Initializing MindfulNest RAG system...")

        # Validate configuration
        Config.validate()

        # Initialize components
        self.embeddings = OpenAIEmbeddings(model=Config.EMBEDDING_MODEL)
        self.llm = ChatOpenAI(
            model=Config.LLM_MODEL,
            temperature=Config.LLM_TEMPERATURE,
            max_tokens=Config.LLM_MAX_TOKENS
        )

        # Load or create vector store
        self.vectorstore = self._load_or_create_vectorstore()

        # Create retriever
        self.retriever = self.vectorstore.as_retriever(
            search_type="similarity",
            search_kwargs={"k": Config.RETRIEVAL_K}
        )

        # Setup prompt
        self.prompt = self._create_prompt()

        # Chat manager
        self.chat_manager = ChatHistoryManager(max_history=Config.MAX_CHAT_HISTORY)

        # Stats
        self.query_count = 0
        self.total_tokens = 0

        logger.info("RAG system initialized successfully")

    def _load_or_create_vectorstore(self):
        """Load existing vector store or create new one"""

        # Check if index exists
        if Config.INDEX_FILE.exists():
            logger.info(f"Loading existing FAISS index from {Config.INDEX_PATH}")
            try:
                vectorstore = FAISS.load_local(
                    str(Config.INDEX_PATH),
                    embeddings=self.embeddings,
                    allow_dangerous_deserialization=True
                )
                logger.info("Existing vector store loaded successfully")
                return vectorstore
            except Exception as e:
                logger.warning(f"Failed to load existing index: {e}")
                logger.info("Will create new index...")

        # Index doesn't exist or failed to load - create new one
        logger.info("FAISS index not found - creating new one...")
        logger.info("This will take several minutes (first time only)...")

        try:
            # Build new index
            vectorstore = DocumentLoader.build_and_save_index()
            return vectorstore

        except Exception as e:
            logger.error(f"Failed to create vector store: {e}", exc_info=True)
            raise RuntimeError(
                "Could not load or create vector store. "
                "Check logs and ensure you have internet connection for document loading."
            )

    def _create_prompt(self):
        """Create the system prompt template with improved formatting instructions"""
        system_prompt = """You are MindfulNest — a warm, supportive AI mental well-being companion who helps users 
understand and manage the emotional and psychological effects of excessive screen time.

Your Response Style:
- Be conversational, natural, and emotionally aware
- Before answering, interpret the user's intention: "Why might they be asking this?" and respond with that understanding
- Provide a complete, meaningful response — not too short, not unnecessarily long
- Offer clarity, comfort, and thoughtful explanations when needed
- Maintain a friendly, encouraging tone that feels like a supportive companion

IMPORTANT - Formatting Rules:
- Write in plain, natural paragraphs
- Use simple numbered lists (1. 2. 3.) when giving multiple suggestions
- DO NOT use markdown bold (**text**) or italic (*text*)
- DO NOT use bullet points with asterisks or dashes
- Keep your language warm but clear and readable

Boundaries:
- You are NOT a therapist or medical professional
- Do NOT diagnose conditions or offer medical treatment
- Offer general emotional support, reflective guidance, and healthy coping suggestions
- Encourage seeking a professional when the situation seems beyond general support

Engagement Rules:
- Acknowledge the user's feelings or perspective whenever appropriate
- Give clear, helpful insights without overwhelming them
- You may ask a gentle follow-up question only when it naturally fits the conversation (not forced, not in every message)

RAG Rules (CRITICAL):
1. Use ONLY the information in the <context> below
2. If the answer is not found in the context, say: "I don't have specific information about that in my knowledge base."
3. NEVER invent or guess information
4. If a question is outside mental well-being/screen-time, gently redirect with kindness

<context>
{context}
</context>"""

        return ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            MessagesPlaceholder("chat_history"),
            ("human", "{input}")
        ])

    def query(self, user_message, session_id=None):
        """
        Process user query and return response.

        Args:
            user_message: User's question
            session_id: Optional session identifier for multi-user support

        Returns:
            dict with answer, sources, and metadata
        """
        try:
            self.query_count += 1
            logger.info(f"Processing query #{self.query_count}: {user_message[:50]}...")

            # Retrieve relevant documents
            docs = self.retriever.invoke(user_message)
            logger.debug(f"Retrieved {len(docs)} documents")

            if not docs:
                logger.warning("No documents retrieved")
                return self._empty_response()

            # Format context
            context = format_documents_for_context(docs)

            # Prepare messages
            messages = self.prompt.format_messages(
                input=user_message,
                context=context,
                chat_history=self.chat_manager.get_history()
            )

            # Get LLM response
            response = self.llm.invoke(messages)
            answer = response.content

            # Clean formatting for better UI display
            answer = clean_response_formatting(answer)

            # Track tokens
            tokens = response.response_metadata.get("token_usage", {})
            self.total_tokens += tokens.get("total_tokens", 0)

            # Update chat history
            self.chat_manager.add_user_message(user_message)
            self.chat_manager.add_assistant_message(answer)

            # Extract sources
            sources = extract_sources(docs)

            logger.info(f"Query processed successfully. Tokens: {tokens.get('total_tokens', 0)}")

            return {
                "success": True,
                "answer": answer,
                "sources": sources[:3],  # Top 3 sources
                "tokens_used": tokens.get("total_tokens", 0),
                "conversation_length": self.chat_manager.message_count()
            }

        except Exception as e:
            logger.error(f"Error processing query: {str(e)}", exc_info=True)
            return {
                "success": False,
                "answer": "I'm having trouble processing your question. Please try again.",
                "error": str(e)
            }

    def _empty_response(self):
        """Return response when no documents found"""
        return {
            "success": True,
            "answer": "I couldn't find relevant information for that question in my knowledge base.",
            "sources": [],
            "tokens_used": 0
        }

    def reset_conversation(self):
        """Clear conversation history"""
        self.chat_manager.clear()
        logger.info("Conversation history cleared")

    def get_stats(self):
        """Get system statistics"""
        return {
            "total_queries": self.query_count,
            "total_tokens_used": self.total_tokens,
            "conversation_pairs": self.chat_manager.conversation_pairs(),
            "message_count": self.chat_manager.message_count()
        }
