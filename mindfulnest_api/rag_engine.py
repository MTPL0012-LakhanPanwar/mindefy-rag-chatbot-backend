"""
Agentic LangGraph-based RAG engine for MindfulNest.

Goals:
- KB-only answering (except an emergency-safety response for crisis language)
- Agentic retrieval (multi-pass: retrieve -> refine query -> retrieve)
- Verification pass (remove unsupported claims)
- Single shared chat history (public website)
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, TypedDict

from langchain_community.vectorstores import FAISS
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langgraph.graph import END, StateGraph

from .config import Config
from .document_loader import DocumentLoader
from .logger import setup_logger
from .utils import (
    clean_response_formatting,
    extract_sources,
    format_documents_for_context,
)

logger = setup_logger("rag_engine")


class _GraphState(TypedDict, total=False):
    route: Literal["crisis", "rag", "social"]
    user_input: str
    messages: List[BaseMessage]
    docs: list
    context: str
    draft_answer: str
    final_answer: str
    meta: Dict[str, Any]


class MindfulNestRAG:
    """
    Agentic RAG engine implemented using LangGraph.

    It keeps a single shared history (public chatbot) and enforces KB-only answers
    via:
    - a strict system prompt, plus
    - an answer verification pass against retrieved context.

    NOTE: For crisis / self-harm language, it returns a fixed safety message
    (this is intentionally not sourced from the KB).
    """

    def __init__(self):
        logger.info("Initializing MindfulNest Agentic RAG (LangGraph)...")
        Config.validate()

        self.embeddings = OpenAIEmbeddings(model=Config.EMBEDDING_MODEL)
        self.llm = ChatOpenAI(
            model=Config.LLM_MODEL,
            temperature=Config.LLM_TEMPERATURE,
            max_tokens=Config.LLM_MAX_TOKENS,
        )

        self.vectorstore = self._load_or_create_vectorstore()
        self.retriever = self.vectorstore.as_retriever(
            search_type="similarity",
            search_kwargs={"k": Config.RETRIEVAL_K},
        )

        self._answer_prompt = self._build_answer_prompt()
        self._verify_prompt = self._build_verify_prompt()
        self._clarify_prompt = self._build_clarify_prompt()

        # Shared state for public chatbot
        self._messages: List[BaseMessage] = []

        # Stats
        self.query_count = 0
        self.total_tokens = 0

        # Compile graph once
        self._graph = self._build_graph()

        logger.info("Agentic LangGraph RAG initialized successfully")

    def _load_or_create_vectorstore(self):
        if Config.INDEX_FILE.exists():
            logger.info(f"Loading existing FAISS index from {Config.INDEX_PATH}")
            try:
                return FAISS.load_local(
                    str(Config.INDEX_PATH),
                    embeddings=self.embeddings,
                    allow_dangerous_deserialization=True,
                )
            except Exception as e:
                logger.warning(f"Failed to load existing index: {e}")
                logger.info("Will create new index...")

        logger.info("FAISS index not found - creating new one (first run only)...")
        try:
            return DocumentLoader.build_and_save_index()
        except Exception as e:
            logger.error(f"Failed to create vector store: {e}", exc_info=True)
            raise RuntimeError(
                "Could not load or create vector store. "
                "Check logs and ensure you have internet connection for document loading."
            )

    def _build_answer_prompt(self) -> ChatPromptTemplate:
        system_prompt = """You are MindfulNest — a warm, supportive AI mental well-being companion.
You introduce yourself in a friendly way, for example: "Hi, I'm MindfulNest. I'm here to support you with your screen time and mental well-being."
You help users understand and manage the emotional and psychological effects of excessive screen time and related mental health concerns.

Your Response Style:
- Be conversational, natural, and emotionally aware.
- Before answering, quickly consider: "Why might they be asking this?" and respond with that understanding.
- Provide a complete, meaningful response — not too short, not unnecessarily long.
- Offer clarity, comfort, and thoughtful explanations when needed.
- Maintain a friendly, encouraging tone that feels like a supportive companion.

IMPORTANT - Formatting Rules:
- Write in plain, natural paragraphs.
- Use simple numbered lists (1. 2. 3.) when giving multiple suggestions.
- DO NOT use markdown bold (**text**) or italic (*text*).
- DO NOT use bullet points with asterisks or dashes.
- Keep your language warm but clear and readable.

Boundaries:
- You are NOT a therapist or medical professional.
- Do NOT diagnose conditions or offer medical treatment.

RAG Rules (CRITICAL, KB-ONLY):
1. Use ONLY the information in the <context> below as your knowledge base.
2. If the answer is not found in the context, respond politely and clearly. Say exactly:
   "I'm sorry, but I don't have specific information about that in my knowledge base. I'm mainly designed to help with screen time and mental well-being. If you have questions in that area, I'm happy to explore them with you."
3. NEVER invent, guess, or rely on outside world knowledge beyond the context.

<context>
{context}
</context>"""

        return ChatPromptTemplate.from_messages(
            [
                ("system", system_prompt),
                MessagesPlaceholder("chat_history"),
                ("human", "{input}"),
            ]
        )

    def _build_verify_prompt(self) -> ChatPromptTemplate:
        verify_system = (
            "You are checking an assistant's draft answer against a knowledge base.\n"
            "Rewrite the answer so that every statement is supported by the context.\n"
            "If any part is not supported, remove it or replace it with this exact sentence:\n"
            "\"I'm sorry, but I don't have specific information about that in my knowledge base. I'm mainly designed to help with screen time and mental well-being. If you have questions in that area, I'm happy to explore them with you.\"\n"
            "Do NOT add any new information.\n"
            "Return only the cleaned answer."
        )
        return ChatPromptTemplate.from_messages(
            [
                ("system", verify_system),
                ("human", "CONTEXT:\n{context}\n\nANSWER:\n{answer}\n\nCleaned answer:"),
            ]
        )

    def _build_clarify_prompt(self) -> ChatPromptTemplate:
        return ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "Rewrite the user's question into a clearer, more focused search query.\n"
                    "Do not add any new facts, and do not answer the question.\n"
                    "Return only the rewritten query.",
                ),
                ("human", "{input}"),
            ]
        )

    # -----------------------
    # Graph nodes
    # -----------------------

    @staticmethod
    def _looks_like_crisis(text: str) -> bool:
        t = (text or "").lower()
        keywords = [
            "suicide",
            "kill myself",
            "end my life",
            "self-harm",
            "self harm",
            "hurt myself",
            "want to die",
            "harm myself",
            "kill someone",
            "hurt someone",
        ]
        return any(k in t for k in keywords)

    def _route_node(self, state: _GraphState) -> _GraphState:
        """
        Decide where to send the turn:
        - 'crisis'  -> immediate safety message
        - 'social'  -> warm, conversational support
        - 'rag'     -> KB-backed RAG flow

        Uses a light rule only for obvious crisis language, and otherwise an
        LLM-based intent classifier over recent history + current input.
        """
        user_input = state["user_input"]

        # 1) Hard crisis override for safety
        if self._looks_like_crisis(user_input):
            state["route"] = "crisis"
            return state

        # 2) Model-based intent classification
        intent = self._classify_intent(
            user_input=user_input,
            history=state.get("messages") or [],
        )

        if intent == "social":
            state["route"] = "social"
        elif intent == "rag":
            state["route"] = "rag"
        elif intent == "crisis":
            # In case the classifier detects something subtle
            state["route"] = "crisis"
        else:
            # Fallback: treat as social to stay warm, not robotic
            state["route"] = "social"

        return state

    def _crisis_node(self, state: _GraphState) -> _GraphState:
        # Fixed safety message (intentionally outside the KB)
        state["final_answer"] = (
            "I’m really sorry you’re feeling this way. I can’t provide emergency help, but you deserve support right now.\n\n"
            "If you feel in danger or might act on these thoughts, please contact your local emergency number immediately.\n"
            "If you can, reach out to someone you trust (a friend, family member, or local professional) and let them know what’s going on.\n\n"
            "If you’d like, tell me where you are (country/region), and I can help you find a crisis helpline you can contact."
        )
        state["meta"]["sources"] = []
        state["meta"]["tokens_used"] = 0
        return state

    def _looks_like_small_talk(self, text: str) -> bool:
        """Detect simple greetings / check-ins where a freeform supportive reply is ok."""
        t = (text or "").strip().lower()
        if not t:
            return False

        # Short, non-specific messages are often greetings or check-ins
        if len(t.split()) <= 4:
            greetings = [
                "hi",
                "hello",
                "hey",
                "heyy",
                "heyyy",
                "yo",
                "sup",
                "good morning",
                "good night",
                "good evening",
                "good afternoon",
                "hola",
            ]
            if any(t == g or t.startswith(g) for g in greetings):
                return True

        # Common relational openers
        small_talk_phrases = [
            "how are you",
            "how r u",
            "how's it going",
            "how are u",
            "i am feeling low",
            "i'm feeling low",
            "i feel low",
            "i feel sad",
            "i am sad",
            "i'm sad",
            "i feel anxious",
            "i am anxious",
            "i'm anxious",
            "i feel stressed",
            "i am stressed",
            "i'm stressed",
        ]
        if any(p in t for p in small_talk_phrases):
            return True

        # Short closing / reassurance like "no i am good thanks", "i'm fine now thanks"
        closing_keywords = ["thanks", "thank you", "thx"]
        positive_state = [
            "i am good",
            "i'm good",
            "i am fine",
            "i'm fine",
            "i am ok",
            "i'm ok",
            "i am okay",
            "i'm okay",
            "all good",
            "feeling better",
            "better now",
            "i am better",
            "i'm better",
        ]
        if any(k in t for k in closing_keywords) and any(p in t for p in positive_state):
            return True

        # Generic short, non-question acknowledgements that are not asking for info
        if "?" not in t and len(t.split()) <= 6 and any(
            w in t for w in ["ok", "okay", "fine", "good", "alright"]
        ) and any(k in t for k in closing_keywords + ["no", "nah"]):
            return True

        return False

    def _classify_intent(
        self, user_input: str, history: List[BaseMessage]
    ) -> Literal["crisis", "social", "rag", "unknown"]:
        """
        Use the LLM to classify what the user is doing in this turn.

        Returns one of: 'crisis', 'social', 'rag', 'unknown'.
        - crisis: expressing self-harm / harm-to-others intent or urgent risk
        - social: greetings, emotional sharing, general support, no clear KB question
        - rag: asking for information, explanation, or guidance that should use KB
        """
        system_prompt = (
            "You are an intent classifier for a mental-wellbeing assistant.\n"
            "Look at the recent conversation and the latest user message.\n"
            "Choose exactly ONE label:\n"
            "- crisis  -> user clearly talks about wanting to die, self-harm, or harming others\n"
            "- social  -> greetings, check-ins, sharing feelings, life stress (for example about work, exams, family), or general support\n"
            "- rag     -> clear question asking for information, explanation, or guidance\n"
            "IMPORTANT:\n"
            "- Feeling overwhelmed about work, exams, relationships, money, or losing a job is NOT automatically 'crisis' unless they also talk about wanting to die, self-harm, or harming others.\n"
            "- If you are unsure, choose 'social' (not 'crisis').\n"
            "Respond with ONLY one word: crisis, social, or rag."
        )

        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", system_prompt),
                MessagesPlaceholder("chat_history"),
                ("human", "{input}"),
            ]
        )

        try:
            # Use only the last few messages for classification context
            short_history = history[-6:] if len(history) > 6 else history
            msgs = prompt.format_messages(
                input=user_input,
                chat_history=short_history,
            )
            resp = self.llm.invoke(msgs)
            label = (resp.content or "").strip().lower()
            if label not in {"crisis", "social", "rag"}:
                return "unknown"

            # Extra safety: only allow 'crisis' if the explicit crisis heuristic matches.
            # This prevents non-self-harm worries like "I am going to lose my job"
            # from being escalated to the crisis flow.
            if label == "crisis" and not self._looks_like_crisis(user_input):
                return "social"

            return label  # type: ignore[return-value]
        except Exception:
            return "unknown"

    def _social_node(self, state: _GraphState) -> _GraphState:
        """
        Warm, conversational response that is not strictly KB-bound.

        Used for greetings / emotional check-ins where a general, supportive
        reply is more helpful than a KB lookup.
        """
        user_input = state["user_input"]

        system_prompt = (
            "You are MindfulNest, a warm, supportive mental well-being companion.\n"
            "Gently introduce yourself in a friendly, short way the first time in a conversation, for example:\n"
            "\"Hi, I'm MindfulNest. I'm here to support you with your screen time and mental well-being.\"\n"
            "Have a natural, emotionally aware conversation with the user.\n"
            "Always do ALL of the following, unless the user clearly says they want to stop talking:\n"
            "1) Acknowledge their message and reflect how they might be feeling in simple, human language.\n"
            "2) Offer 2–4 gentle, practical ideas or suggestions that could help them in this moment\n"
            "   (for example: small grounding exercises, screen-time breaks, simple coping ideas, or reframing).\n"
            "3) Ask one soft follow-up question that invites them to share a bit more if they want, without pressure.\n"
            "Only when they clearly sound like they are ending the chat (for example, \"no I am good now, thanks\"):\n"
            "- Appreciate that they reached out, gently close the conversation, and let them know they can come back anytime.\n"
            "Do NOT give medical advice or diagnoses. Keep your language simple, kind, and non-judgmental.\n"
            "Write in plain text (no markdown formatting)."
        )

        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", system_prompt),
                MessagesPlaceholder("chat_history"),
                ("human", "{input}"),
            ]
        )

        history = state.get("messages") or []
        msgs = prompt.format_messages(input=user_input, chat_history=history)

        resp = self.llm.invoke(msgs)
        answer = resp.content

        state["final_answer"] = clean_response_formatting(answer)
        state["meta"]["tokens_used"] = resp.response_metadata.get("token_usage", {}).get(
            "total_tokens", 0
        )
        # No KB sources for pure social replies
        state["meta"]["sources"] = []
        return state

    def _agentic_retrieval_node(self, state: _GraphState) -> _GraphState:
        question = state["user_input"]

        docs_primary = self.retriever.invoke(question)
        if len(docs_primary) >= Config.RETRIEVAL_K or len(docs_primary) >= 3:
            docs = docs_primary
        else:
            # Clarify query (no new facts)
            try:
                msgs = self._clarify_prompt.format_messages(input=question)
                clarified = self.llm.invoke(msgs).content.strip() or question
            except Exception:
                clarified = question

            docs_secondary = self.retriever.invoke(clarified)

            # Merge + dedupe
            seen = set()
            merged = []
            for d in list(docs_primary) + list(docs_secondary):
                key = (d.page_content, tuple(sorted(d.metadata.items())))
                if key not in seen:
                    seen.add(key)
                    merged.append(d)

            max_docs = max(Config.RETRIEVAL_K, 5)
            docs = merged[:max_docs]

        state["docs"] = docs
        state["meta"]["sources"] = extract_sources(docs)
        return state

    def _build_context_node(self, state: _GraphState) -> _GraphState:
        docs = state.get("docs") or []
        state["context"] = format_documents_for_context(docs)
        return state

    def _answer_node(self, state: _GraphState) -> _GraphState:
        user_input = state["user_input"]
        context = state.get("context") or ""
        history = state.get("messages") or []

        msgs = self._answer_prompt.format_messages(
            input=user_input,
            context=context,
            chat_history=history,
        )
        resp = self.llm.invoke(msgs)
        state["draft_answer"] = resp.content

        token_usage = resp.response_metadata.get("token_usage", {}) if hasattr(resp, "response_metadata") else {}
        state["meta"]["tokens_used"] = token_usage.get("total_tokens", 0)
        return state

    def _verify_node(self, state: _GraphState) -> _GraphState:
        context = state.get("context") or ""
        draft = state.get("draft_answer") or ""

        try:
            msgs = self._verify_prompt.format_messages(context=context, answer=draft)
            verified = self.llm.invoke(msgs).content.strip()
            verified = verified or draft
        except Exception:
            verified = draft

        state["final_answer"] = clean_response_formatting(verified)
        return state

    def _update_history_node(self, state: _GraphState) -> _GraphState:
        user_input = state["user_input"]
        final_answer = state.get("final_answer") or ""

        messages = list(state.get("messages") or [])
        messages.append(HumanMessage(content=user_input))
        messages.append(AIMessage(content=final_answer))

        max_msgs = Config.MAX_CHAT_HISTORY * 2
        if len(messages) > max_msgs:
            messages = messages[-max_msgs:]

        state["messages"] = messages
        return state

    def _build_graph(self):
        g = StateGraph(_GraphState)

        g.add_node("route", self._route_node)
        g.add_node("crisis", self._crisis_node)
        g.add_node("social", self._social_node)
        g.add_node("retrieve", self._agentic_retrieval_node)
        g.add_node("context", self._build_context_node)
        g.add_node("answer", self._answer_node)
        g.add_node("verify", self._verify_node)
        g.add_node("history", self._update_history_node)

        g.set_entry_point("route")

        def _router(state: _GraphState) -> str:
            # Default to RAG if something is off
            return state.get("route", "rag")

        g.add_conditional_edges(
            "route",
            _router,
            {
                "crisis": "crisis",
                "social": "social",
                "rag": "retrieve",
            },
        )

        g.add_edge("crisis", END)
        g.add_edge("social", "history")

        # After retrieval, if no docs were found, fall back to social support
        def _retrieval_router(state: _GraphState) -> str:
            docs = state.get("docs") or []
            return "social" if len(docs) == 0 else "context"

        g.add_conditional_edges(
            "retrieve",
            _retrieval_router,
            {
                "social": "social",
                "context": "context",
            },
        )
        g.add_edge("context", "answer")
        g.add_edge("answer", "verify")
        g.add_edge("verify", "history")
        g.add_edge("history", END)

        return g.compile()

    # -----------------------
    # Public API used by Flask
    # -----------------------

    def query(self, user_message: str) -> Dict[str, Any]:
        self.query_count += 1
        logger.info(f"Query #{self.query_count}: {user_message[:80]}")

        # Prepare initial state
        state: _GraphState = {
            "user_input": (user_message or "").strip(),
            "messages": list(self._messages),
            "meta": {},
        }

        # Run graph
        out: _GraphState = self._graph.invoke(state)

        # Update shared history (if it was updated)
        self._messages = list(out.get("messages") or self._messages)

        # Stats
        tokens_used = int(out.get("meta", {}).get("tokens_used", 0) or 0)
        self.total_tokens += tokens_used

        answer = out.get("final_answer") or (
            "I'm sorry, but I don't have specific information about that in my knowledge base. "
            "I'm mainly designed to help with screen time and mental well-being. "
            "If you have questions in that area, I'm happy to explore them with you."
        )
        sources = (out.get("meta", {}).get("sources") or [])[:3]

        return {
            "success": True,
            "answer": answer,
            "sources": sources,
            "tokens_used": tokens_used,
            "conversation_length": len(self._messages),
        }

    def reset_conversation(self):
        self._messages = []
        logger.info("Conversation history cleared")

    def get_stats(self):
        return {
            "total_queries": self.query_count,
            "total_tokens_used": self.total_tokens,
            "message_count": len(self._messages),
            "conversation_pairs": len(self._messages) // 2,
        }
