import re

from handlers import VolatilityQueryHandlers


class QueryRouter:
    def __init__(self, gemini_handler, metadata, results):
        self.gemini_handler = gemini_handler
        self.handlers = VolatilityQueryHandlers(metadata, results)
        # Tiered categories for more precise routing
        self.categories = [
            "supported_function_most_net",
            "supported_function_multi_pid",
            "rag_process_analysis",
            "general_forensics_qna",
            "unsupported_forensics_query",
            "off_topic",
        ]

    def _classify_query(self, query: str) -> str:
        # This prompt is now much more detailed to handle the new distinctions.
        system_prompt = f"""
        You are a precise query classifier for a memory forensics analysis tool. Your task is to categorize the user's query into ONLY ONE of the following categories: {', '.join(self.categories)}

        1.  `supported_function_most_net`: For questions specifically about the process with the MOST or HIGHEST number of network connections.
        2.  `supported_function_multi_pid`: For questions about applications running with multiple process instances.
        3.  `rag_process_analysis`: For any query asking for a summary, report, or details about a SPECIFIC Process ID (PID). The query MUST contain a number.
        4.  `general_forensics_qna`: For conceptual or definitional questions about the FIELD of memory forensics (e.g., "what is volatility?", "explain a VAD tree"). The query is NOT about the specific data loaded.
        5.  `unsupported_forensics_query`: For questions about the loaded data that do NOT match a supported function. Examples: "which process has the LEAST connections?", "find processes created after 10 PM", "list processes with no network connections".
        6.  `off_topic`: For anything else, including greetings, chit-chat, or questions unrelated to computers or forensics.

        Respond with ONLY the category name and nothing else.
        """
        response = self.gemini_handler.query(system_prompt, query).strip()
        return response if response in self.categories else "off_topic"

    def _generate_report_from_context(self, context: str, query: str) -> str:
        """Tier 2: Takes retrieved data and generates a report using Gemini."""
        print("🤖 Generating report from context...")
        # ... (This function remains the same as before)
        system_prompt = (
            "You are a senior cybersecurity analyst. Your task is to generate a complete, "
            "human-readable report based on the provided raw data from the Volatility framework. "
            "Directly answer the user's query and highlight any potentially suspicious indicators you find in the data."
            "The report should contain all of the raw data in form or other, but be well-organized and easy to read."
        )
        full_prompt = f"User Query: {query}\n\n--- Technical Data ---\n{context}"
        return self.gemini_handler.query(system_prompt, full_prompt)

    def _handle_general_forensics_qna(self, query: str) -> str:
        """Tier 3: Answers a general memory forensics question."""
        print("🤖 Answering general forensics question...")
        # This prompt is now more specialized
        system_prompt = "You are an AI assistant and expert in digital and memory forensics. Answer the following conceptual question."
        return self.gemini_handler.query(system_prompt, query)

    def route_query(self, query: str) -> str:
        """Classifies and routes the query to the correct tier."""
        category = self._classify_query(query)
        print(f"🕵️ Intent classified as: {category}")

        # Tier 1: Supported Direct Functions
        if category == "supported_function_most_net":
            return self.handlers.handle_most_network_connections()
        elif category == "supported_function_multi_pid":
            return self.handlers.handle_multiple_pids()

        # Tier 2: RAG for Analysis
        elif category == "rag_process_analysis":
            context = self.handlers.retrieve_process_data(query)
            if context:
                return self._generate_report_from_context(context, query)
            else:
                match = re.search(r"\d+", query)
                pid = match.group(0) if match else "the specified PID"
                return f"❌ Could not retrieve data for {pid}. Please provide a valid Process ID."

        # Tier 3: General Forensics Q&A
        elif category == "general_forensics_qna":
            return self._handle_general_forensics_qna(query)

        # Tier 4: Unsupported Forensics Query
        elif category == "unsupported_forensics_query":
            return "⚠️ This specific query is not yet supported by a specialized tool."

        # Tier 5: Off-Topic
        elif category == "off_topic":
            return "Please ask a memory forensics-related question."

        else:
            return "Error: Could not process the query."
