from gemini import GeminiHandler 
from handlers import VolatilityQueryHandlers
class QueryRouter:
    def __init__(self, gemini_handler, metadata, results):
        self.gemini_handler = gemini_handler
        self.handlers = VolatilityQueryHandlers(metadata, results)
        self.categories = [
            "most_network_connections",
            "process_existence",
            "multiple_pids",
            "unknown" # A fallback category
        ]

    def _classify_query(self, query: str) -> str:
        """Uses the LLM to classify the user's query."""
        system_prompt = f"""
        You are an expert query classifier for a memory analysis tool.
        Your task is to categorize the user's query into one of the following predefined categories:
        {', '.join(self.categories)}

        - If the user asks about which process is 'chatty', 'noisy', or has the most connections, classify it as 'most_network_connections'.
        - If the user asks if a process ID (PID) exists or asks for information about a specific PID, classify it as 'process_existence'.
        - If the user asks about applications running multiple times or with multiple instances, classify it as 'multiple_pids'.
        - If the query does not fit any of these, classify it as 'unknown'.
        
        Respond with ONLY the category name and nothing else.
        """
        
        # Assuming your gemini_handler.query method takes system_prompt and the user query
        response = self.gemini_handler.query(system_prompt, query)
        
        # Clean up the response and ensure it's a valid category
        category = response.strip()
        if category in self.categories:
            return category
        return "unknown" # Default to unknown if the LLM fails

    def route_query(self, query: str) -> str:
        """Classifies and routes the query to the appropriate handler."""
        category = self._classify_query(query)
        
        print(f"🤖 Classified intent as: {category}")

        if category == "most_network_connections":
            return self.handlers.handle_most_network_connections()
        elif category == "process_existence":
            return self.handlers.handle_process_existence(query)
        elif category == "multiple_pids":
            return self.handlers.handle_multiple_pids()
        else:
            # This is where you can fall back to your RAG system for general queries!
            return "I'm not sure how to answer that with my specialized tools. Let me try a general search."