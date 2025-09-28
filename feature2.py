# Verify LangChain version
import langchain_core
from dotenv import load_dotenv
from langchain import hub
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import Tool
from langchain_google_genai import ChatGoogleGenerativeAI
from pydantic import BaseModel, Field

from volatility import VolatilityPluginRunner

print(f"langchain-core version: {langchain_core.__version__}")
if langchain_core.__version__ < "0.1.47":
    raise ImportError(
        "Please upgrade langchain-core to version >= 0.1.47 to use the 'invoke' method."
    )


class VolatilityTools:
    """A class to hold volatility data and provide tools for process/network analysis and general memory forensics questions."""

    def __init__(
        self, metadata: dict, results: dict, llm: ChatGoogleGenerativeAI = None
    ):
        """Initializes the toolset with the necessary data."""
        if not isinstance(metadata, dict) or not isinstance(results, dict):
            raise ValueError("metadata and results must be dictionaries")
        self.metadata = metadata
        self.results = results
        self.llm = llm
        print("VolatilityTools initialized with data.")

    def find_process_with_most_connections(self) -> str:
        """
        Finds process(es) with the highest number of network connections and returns their PID(s) and details.
        Use this to identify the most active or 'chattiest' process(es) with respect to network connections in the memory dump.
        """
        if not self.metadata:
            return "No process data available."
        max_connections = -1
        for meta in self.metadata.values():
            num_connections = meta.get("No of Network Connections", 0)
            if num_connections > max_connections:
                max_connections = num_connections

        top_processes = [
            meta
            for meta in self.metadata.values()
            if meta.get("No of Network Connections", 0) == max_connections
        ]

        if top_processes and max_connections > 0:
            pids = [str(p.get("PID", "N/A")) for p in top_processes]
            return (
                f"Found {len(pids)} process(es) with the maximum of {max_connections} connections. "
                f"PIDs: {', '.join(pids)}."
            )
        return "Could not determine the process(es) with the most connections."

    def find_process_with_least_connections(self) -> str:
        """
        Finds process(es) with the lowest number of (non-zero) network connections and returns their PID(s) and connection count.
        Use this to identify the least active process(es) with respect to network connections in the memory dump.
        """
        if not self.metadata:
            return "No process data available."

        min_connections = float("inf")
        for meta in self.metadata.values():
            conns = meta.get("No of Network Connections", 0)
            if 0 < conns < min_connections:
                min_connections = conns

        if min_connections == float("inf"):
            return "No processes with active network connections were found."

        least_processes = [
            meta
            for meta in self.metadata.values()
            if meta.get("No of Network Connections", 0) == min_connections
        ]

        pids = [str(p.get("PID", "N/A")) for p in least_processes]
        return f"Found {len(pids)} process(es) with the minimum of {min_connections} connections. PIDs: {', '.join(pids)}"

    class GetProcessDataInput(BaseModel):
        pid: int = Field(
            description="The Process ID (PID) to retrieve data for. Must be a positive integer."
        )

    def get_all_process_data_by_pid(self, pid: int) -> str:
        """
        Retrieves all available metadata and raw plugin data for a specific Process ID (PID).
        Use this to get comprehensive details for a single process in the memory dump.
        """
        if not isinstance(pid, int) or pid <= 0:
            return "Please provide a valid PID (a positive integer)."
        if pid in self.metadata:
            process_metadata = self.metadata[pid]
            process_results = self.results.get(pid, {})
            context_lines = [f"Data for PID {pid}:"]
            context_lines.append("\n## Metadata Summary")
            for key, value in process_metadata.items():
                context_lines.append(f"  - {key}: {value}")
            context_lines.append("\n## Detailed Plugin Data")
            for plugin_name, records in process_results.items():
                context_lines.append(f"\n### {plugin_name}")
                for record in records:
                    context_lines.append(f"  - {record}")
            return "\n".join(context_lines)
        return f"Error: PID {pid} not found."

    class GenerateReportInput(BaseModel):
        context: str = Field(
            description="The string of technical data to be summarized in the report."
        )

    def generate_analysis_report(self, context: str) -> str:
        """
        Takes a string of technical data about one or more processes and generates a
        human-readable analysis report. Use this to summarize findings from memory dump data.
        """
        if not self.llm:
            return "Error: LLM not initialized for report generation."
        if not context or not isinstance(context, str):
            return "Please provide valid technical data for the report."
        system_prompt = (
            "You are a senior cybersecurity analyst. Your task is to generate a complete, "
            "human-readable report based on the provided raw data from the Volatility framework. "
            "Directly answer the user's query and highlight any potentially suspicious indicators you find in the data."
            "The report should contain all of the raw data in form or other, but be well-organized and easy to read."
        )
        return self.llm.invoke(f"{system_prompt}\n\nTechnical Data:\n{context}").content

    class MemoryForensicsQuestionInput(BaseModel):
        question: str = Field(
            description="The question about memory forensics to answer."
        )

    def answer_memory_forensics_question(self, question: str) -> str:
        """
        Answers general questions about memory forensics using the LLM.
        Use this for conceptual questions about memory forensics, not for analyzing specific memory dump data.
        """
        if not self.llm:
            return "Error: LLM not initialized for answering questions."
        if not question or not isinstance(question, str):
            return "Please provide a valid question about memory forensics."
        system_prompt = (
            "You are a senior cybersecurity analyst with expertise in memory forensics. "
            "Provide a clear, concise, and accurate answer to the user's question about memory forensics. "
            "Focus on explaining concepts, techniques, or tools (e.g., Volatility) without referencing specific memory dump data unless provided."
            "Only Answer questions related to memory forensics. For other questions, respond with 'Please ask a memory forensics-related question.'"
        )
        return self.llm.invoke(f"{system_prompt}\n\nQuestion: {question}").content


# --- SETUP (runs only once) ---
load_dotenv()

# Initialize the LLM
try:
    llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)
except Exception as e:
    print(f"Error initializing LLM: {e}")
    exit(1)

# Initialize VolatilityPluginRunner and load data
volatility_runner = VolatilityPluginRunner()
try:
    results, metadata = volatility_runner.run_all_plugins(
        r"C:\Users\preet\Downloads\Challenge_NotchItUp\Challenge.raw"
    )
except Exception as e:
    print(f"Error running Volatility plugins: {e}")
    exit(1)

# Instantiate VolatilityTools with the data
vol_tools = VolatilityTools(metadata, results, llm)

# Create Tool objects, using lambdas to handle tool_input
tools = [
    Tool(
        name="find_process_with_most_connections",
        func=lambda tool_input: vol_tools.find_process_with_most_connections(),
        description="Finds the process with the highest number of network connections in the memory dump. Ignores input. Use for queries about the most active process.",
    ),
    Tool(
        name="find_process_with_least_connections",
        func=lambda tool_input: vol_tools.find_process_with_least_connections(),
        description="Finds process(es) with the lowest number of active (non-zero) network connections in the memory dump. Ignores input. Use for queries about the least active process(es).",
    ),
    Tool(
        name="get_all_process_data_by_pid",
        func=lambda tool_input: (
            "Please provide a valid PID (a positive integer)."
            if not tool_input
            or (isinstance(tool_input, dict) and not tool_input.get("pid"))
            or (isinstance(tool_input, str) and not tool_input.isdigit())
            else vol_tools.get_all_process_data_by_pid(
                int(tool_input.get("pid"))
                if isinstance(tool_input, dict)
                else int(tool_input)
            )
        ),
        description="Retrieves all available metadata and raw plugin data for a specific Process ID (PID) in the memory dump. Expects a PID as input (integer or string).",
        args_schema=VolatilityTools.GetProcessDataInput,
    ),
    Tool(
        name="generate_analysis_report",
        func=lambda tool_input: (
            "Please provide valid technical data for the report."
            if not tool_input
            or (isinstance(tool_input, dict) and not tool_input.get("context"))
            else vol_tools.generate_analysis_report(
                tool_input
                if isinstance(tool_input, str)
                else tool_input.get("context", "")
            )
        ),
        description="Generates a human-readable analysis report from technical data about one or more processes in the memory dump. Expects a context string as input, typically from get_all_process_data_by_pid.",
        args_schema=VolatilityTools.GenerateReportInput,
    ),
    Tool(
        name="answer_memory_forensics_question",
        func=lambda tool_input: (
            "Please provide a valid question about memory forensics."
            if not tool_input
            or (isinstance(tool_input, dict) and not tool_input.get("question"))
            else vol_tools.answer_memory_forensics_question(
                tool_input
                if isinstance(tool_input, str)
                else tool_input.get("question", "")
            )
        ),
        description="Answers general questions about memory forensics concepts, techniques, or tools (e.g., Volatility). Use for queries not related to specific memory dump data. Expects a question string as input.",
        args_schema=VolatilityTools.MemoryForensicsQuestionInput,
    ),
]

# Initialize the agent and executor
prompt = hub.pull("hwchase17/react")
agent = create_react_agent(llm, tools, prompt)
agent_executor = AgentExecutor(
    agent=agent, tools=tools, verbose=True, handle_parsing_errors=True
)

# --- INTERACTIVE LOOP (runs continuously) ---
print("Memory Forensics Agent is ready. Type 'exit' to quit.")

while True:
    user_query = input("\nAsk your question: ")
    if user_query.lower() in ["exit", "quit"]:
        print("Exiting agent...")
        break
    try:
        response = agent_executor.invoke({"input": user_query})
        print("\n--- Final Answer ---")
        print(response["output"])
    except Exception as e:
        print(f"Error processing query: {e}")
